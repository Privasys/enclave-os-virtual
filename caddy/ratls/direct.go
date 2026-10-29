package ratls

// Direct domains: an adopter hostname whose TLS ends in this enclave with a
// publicly trusted certificate.
//
// The platform gateway splices a direct name at L4 for every client, so both
// populations reach this module on the same SNI and are split here, on the
// ALPN the client offered:
//
//	privasys-ratls/1  -> the RA-TLS leaf, minted for the adopter name
//	anything else     -> the Let's Encrypt certificate, key born here
//	acme-tls/1        -> answered by certmagic before any getter runs, from
//	                     the challenge the manager left in shared storage
//
// The manager obtains and renews the certificates (certmagic, TLS-ALPN-01,
// the app's account key) into the Caddy storage root, and marks each direct
// name with a file under privasys-direct/. This module only reads.
//
// Every connection that was served the Let's Encrypt certificate is tagged,
// and a request on a direct name is reported to the manager as the direct
// leg unless its connection was positively served the RA-TLS leaf. A resumed
// TLS session skips the certificate getter, so the safe default is the leg
// whose client verified nothing.

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// directMarkerDir holds one <name>.json per direct name, under the
	// storage root.
	directMarkerDir = "privasys-direct"

	// legDirect and legRATLS are the per-connection certificate tags.
	legDirect = "direct"
	legRATLS  = "ratls"

	// hdrEdge is the leg marker the manager reads. The gateway sets
	// "terminate" on the leg it terminated; this module sets "direct" on a
	// direct name, overwriting whatever the client sent.
	hdrEdge = "X-Privasys-Edge"

	directMarkerTTL = 2 * time.Second
)

// directMarker is what the manager writes for a direct name.
type directMarker struct {
	// Canonical is the app's platform hostname, whose extensions the RA-TLS
	// leaf for this name carries.
	Canonical string `json:"canonical"`
}

type directCert struct {
	cert    *tls.Certificate
	modTime time.Time
}

type directState struct {
	mu      sync.Mutex
	markers map[string]directMarkerEntry
	certs   map[string]directCert
}

type directMarkerEntry struct {
	direct  bool
	checked time.Time
}

var direct = directState{
	markers: map[string]directMarkerEntry{},
	certs:   map[string]directCert{},
}

// directEnabled reports whether this getter serves direct names.
func (g *RATLSCertGetter) directEnabled() bool {
	return g != nil && g.DirectStorage != "" && g.DirectIssuerKey != ""
}

// isDirectName reports whether name has a direct marker, cached briefly so a
// busy connection does not stat the disk on every request.
func (g *RATLSCertGetter) isDirectName(name string) bool {
	if !g.directEnabled() || name == "" || strings.ContainsAny(name, `/\`) {
		return false
	}
	name = strings.ToLower(name)
	now := time.Now()
	direct.mu.Lock()
	e, ok := direct.markers[name]
	direct.mu.Unlock()
	if ok && now.Sub(e.checked) < directMarkerTTL {
		return e.direct
	}
	_, err := os.Stat(filepath.Join(g.DirectStorage, directMarkerDir, name+".json"))
	e = directMarkerEntry{direct: err == nil, checked: now}
	direct.mu.Lock()
	direct.markers[name] = e
	direct.mu.Unlock()
	return e.direct
}

// directCertificate loads the publicly trusted certificate of name from the
// certmagic storage layout, reloading when a renewal rewrote it.
func (g *RATLSCertGetter) directCertificate(name string) (*tls.Certificate, error) {
	name = strings.ToLower(name)
	dir := filepath.Join(g.DirectStorage, "certificates", g.DirectIssuerKey, name)
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	st, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: direct name %s has no certificate yet", name)
	}
	direct.mu.Lock()
	c, ok := direct.certs[name]
	direct.mu.Unlock()
	if ok && c.modTime.Equal(st.ModTime()) {
		return c.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: load direct certificate for %s: %w", name, err)
	}
	direct.mu.Lock()
	direct.certs[name] = directCert{cert: &pair, modTime: st.ModTime()}
	direct.mu.Unlock()
	return &pair, nil
}

// directMarkerFor reads the marker of a direct name.
func (g *RATLSCertGetter) directMarkerFor(name string) (directMarker, error) {
	var m directMarker
	data, err := os.ReadFile(filepath.Join(g.DirectStorage, directMarkerDir, strings.ToLower(name)+".json"))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(data, &m)
	return m, err
}

// offersALPN reports whether the ClientHello offered proto.
func offersALPN(hello *tls.ClientHelloInfo, proto string) bool {
	for _, p := range hello.SupportedProtos {
		if p == proto {
			return true
		}
	}
	return false
}

// tagConn records which certificate a connection was served.
func tagConn(hello *tls.ClientHelloInfo, leg string) {
	if hello == nil || hello.Conn == nil {
		return
	}
	if c := connFor(hello.Conn.RemoteAddr().String(), true); c != nil {
		conns.mu.Lock()
		c.leg = leg
		conns.mu.Unlock()
	}
}

// connLeg returns the certificate tag of a connection, "" when unknown.
func connLeg(remote string) string {
	c := connFor(remote, false)
	if c == nil {
		return ""
	}
	conns.mu.Lock()
	defer conns.mu.Unlock()
	return c.leg
}
