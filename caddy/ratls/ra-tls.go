// Package ratls implements the Caddy modules that make an enclave-os-virtual
// VM an RA-TLS v2 server (see ra-tls-clients/docs/ratls-v2.md).
//
// # Certificate
//
// The serving certificate identifies the enclave and carries no attestation
// evidence: an ECDSA P-256 leaf key generated inside the TEE, a chain to the
// Privasys intermediate CA of this environment, and the Privasys OID
// extensions written by the measured manager (per hostname, in ExtensionsDir).
// The leaf key lives for 24 hours and is kept across re-mints that only change
// extension values (a deploy, a configuration change), so a deterministic quote
// minted for the key stays valid across such a re-mint. Leaves are served per
// SNI by the "tls.get_certificate.ra_tls" module (RATLSCertGetter).
//
// # Evidence
//
// A client that wants evidence asks for it after the handshake, on the same
// connection, with POST /__privasys/attest, served by the
// "http.handlers.privasys_attest" module (see attest.go). The quote's
// report_data commits to the leaf key and either a minute timestamp
// (deterministic mode, cached for 24 hours per key) or the client's context and
// this connection's RFC 8446 exporter value (challenge mode, Level 3 binding):
//
//	deterministic: SHA-512( SHA-256(SPKI_DER) || quote_time )
//	challenge:     SHA-512( SHA-256(SPKI_DER) || context || hctx )
//	               hctx = TLS-Exporter("EXPORTER-privasys-ratls-attest-v2", context, 32)
//
// with SHA-256(gpu_evidence) appended to the binding on a GPU host (the
// "tdx-gpu" evidence family).
//
// # Build
//
//	xcaddy build --with github.com/Privasys/enclave-os-virtual/caddy/ratls=.
//
// Stock Go: nothing here needs a TLS extension or a fork.
package ratls

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RATLSCertGetter{})
}

// leafLifetime is the validity of a serving certificate and the lifetime of
// its key.
const leafLifetime = 24 * time.Hour

// RATLSCertGetter serves the RA-TLS v2 leaf of every SNI. It is registered
// under "tls.get_certificate" so Caddy calls GetCertificate on every handshake.
type RATLSCertGetter struct {
	// Backend selects the confidential computing hardware backend ("tdx").
	Backend string `json:"backend"`
	// CACertPath is the PEM intermediary CA certificate that signs leaves.
	CACertPath string `json:"ca_cert_path"`
	// CAKeyPath is the PEM private key of the intermediary CA.
	CAKeyPath string `json:"ca_key_path"`
	// ExtensionsDir holds the per-hostname OID extension files
	// (<hostname>.json) written by the workload manager.
	ExtensionsDir string `json:"extensions_dir,omitempty"`
	// GPUEvidenceDir is where the gpu-attest daemon writes the cached NVIDIA
	// GPU CC evidence (gpu-evidence.bin). Empty means /run.
	GPUEvidenceDir string `json:"gpu_evidence_dir,omitempty"`

	attester Attester
	caCert   *x509.Certificate
	caKey    crypto.Signer
	logger   *zap.Logger

	mu    *sync.RWMutex
	cache map[string]*cachedCert // by SNI, this module instance only
}

// cachedCert is one minted leaf: it is served while its key is current and
// it has not expired.
type cachedCert struct {
	cert     *tls.Certificate
	spkiHash [32]byte
	notAfter time.Time
}

// current is the provisioned getter the attest handler uses to reach the
// attester, the GPU evidence and the CA. Caddy re-provisions modules on every
// config load; the handler always sees the latest instance.
var current atomic.Pointer[RATLSCertGetter]

// CaddyModule returns the Caddy module information.
func (RATLSCertGetter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.get_certificate.ra_tls",
		New: func() caddy.Module { return new(RATLSCertGetter) },
	}
}

// Provision validates configuration, loads the intermediary CA and initialises
// the attestation backend.
func (g *RATLSCertGetter) Provision(ctx caddy.Context) error {
	g.logger = ctx.Logger()
	g.cache = make(map[string]*cachedCert)
	g.mu = new(sync.RWMutex)

	if g.Backend == "" {
		return fmt.Errorf("ra_tls: backend is required")
	}
	if g.CACertPath == "" {
		return fmt.Errorf("ra_tls: ca_cert_path is required")
	}
	if g.CAKeyPath == "" {
		return fmt.Errorf("ra_tls: ca_key_path is required")
	}

	caCertPEM, err := os.ReadFile(g.CACertPath)
	if err != nil {
		return fmt.Errorf("ra_tls: failed to read CA certificate from %q: %w", g.CACertPath, err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return fmt.Errorf("ra_tls: no PEM block found in CA certificate file %q", g.CACertPath)
	}
	g.caCert, err = x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("ra_tls: failed to parse CA certificate: %w", err)
	}
	if !g.caCert.IsCA {
		return fmt.Errorf("ra_tls: certificate in %q is not a CA certificate", g.CACertPath)
	}

	caKeyPEM, err := os.ReadFile(g.CAKeyPath)
	if err != nil {
		return fmt.Errorf("ra_tls: failed to read CA key from %q: %w", g.CAKeyPath, err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return fmt.Errorf("ra_tls: no PEM block found in CA key file %q", g.CAKeyPath)
	}
	caKeyRaw, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		caKeyRaw, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("ra_tls: failed to parse CA private key (tried PKCS#8 and SEC1): %w", err)
		}
	}
	var ok bool
	g.caKey, ok = caKeyRaw.(crypto.Signer)
	if !ok {
		return fmt.Errorf("ra_tls: CA private key type %T does not implement crypto.Signer", caKeyRaw)
	}

	attester, err := newAttester(g.Backend)
	if err != nil {
		return fmt.Errorf("ra_tls: %w", err)
	}
	if err := attester.Provision(g.logger); err != nil {
		return fmt.Errorf("ra_tls[%s]: %w", g.Backend, err)
	}
	g.attester = attester

	current.Store(g)
	g.logger.Info("RA-TLS v2 certificate getter provisioned",
		zap.String("backend", g.Backend),
		zap.String("ca_subject", g.caCert.Subject.String()))
	return nil
}

// GetCertificate implements certmagic.Manager: the v2 leaf for the SNI, from
// this instance's cache when its key is still current, minted otherwise. A
// config reload (new instance) re-mints with the same key, so extension
// changes never rotate the key before its 24 hours are up.
func (g *RATLSCertGetter) GetCertificate(_ context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := hello.ServerName
	lk := leafKeyFor(sni)

	g.mu.RLock()
	c, ok := g.cache[sni]
	g.mu.RUnlock()
	if ok && c.spkiHash == lk.spkiHash && time.Now().Before(c.notAfter) {
		return c.cert, nil
	}

	cert, notAfter, err := g.mint(lk, hello)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.cache[sni] = &cachedCert{cert: cert, spkiHash: lk.spkiHash, notAfter: notAfter}
	g.mu.Unlock()
	return cert, nil
}

// mint signs a leaf for lk carrying the hostname's OID extensions and no
// evidence.
func (g *RATLSCertGetter) mint(lk *leafKey, hello *tls.ClientHelloInfo) (*tls.Certificate, time.Time, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ra_tls: serial number generation failed: %w", err)
	}
	hostExts, err := g.loadHostnameExtensions(hello.ServerName)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Resolve the cert name. Empty ServerName means the client did not send
	// SNI (a Go HTTP client dialling https://IP:port strips IP literals per
	// RFC 6066); Caddy then keys the lookup on the connection's LocalAddr.IP
	// and rejects a cert whose SANs do not contain it.
	certCN := hello.ServerName
	var dnsNames []string
	var ipSANs []net.IP
	if certCN != "" {
		if ip := net.ParseIP(certCN); ip != nil {
			ipSANs = append(ipSANs, ip)
		} else {
			dnsNames = []string{certCN}
		}
	}
	if hello.Conn != nil {
		if local, ok := hello.Conn.LocalAddr().(*net.TCPAddr); ok && local.IP != nil {
			ipSANs = append(ipSANs, local.IP)
			if certCN == "" {
				certCN = local.IP.String()
			}
		}
	}
	if certCN == "" {
		certCN = "enclave-default"
	}

	now := time.Now().UTC().Truncate(time.Minute)
	notAfter := lk.created.Add(leafLifetime)
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: certCN},
		DNSNames:              dnsNames,
		IPAddresses:           ipSANs,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       hostExts,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, g.caCert, &lk.key.PublicKey, g.caKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ra_tls: CA-signed certificate creation failed: %w", err)
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER, g.caCert.Raw},
		PrivateKey:  lk.key,
	}

	g.logger.Info("RA-TLS v2 certificate issued",
		zap.String("server_name", hello.ServerName),
		zap.String("leaf", base64.RawURLEncoding.EncodeToString(lk.spkiHash[:])),
		zap.Int("extensions", len(hostExts)),
		zap.Time("not_after", notAfter))
	return tlsCert, notAfter, nil
}

// UnmarshalCaddyfile parses the "ra_tls" get_certificate directive.
func (g *RATLSCertGetter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "backend":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.Backend = d.Val()
		case "ca_cert":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.CACertPath = d.Val()
		case "ca_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.CAKeyPath = d.Val()
		case "extensions_dir":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.ExtensionsDir = d.Val()
		case "gpu_evidence_dir":
			if !d.NextArg() {
				return d.ArgErr()
			}
			g.GPUEvidenceDir = d.Val()
		default:
			return d.Errf("unrecognised sub-directive: %s", d.Val())
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Per-hostname OID extensions (written by the measured manager)
// ---------------------------------------------------------------------------

// extensionEntry matches the JSON format written by the workload manager.
type extensionEntry struct {
	OID   string `json:"oid"`
	Value string `json:"value"` // base64-encoded DER value
}

// extensionsFile is the object format for per-hostname extension files: the
// manager's static extensions plus an optional upstream URL of the container,
// queried for its self-declared app-defined extensions at issuance.
type extensionsFile struct {
	Extensions []extensionEntry `json:"extensions"`
	Upstream   string           `json:"upstream,omitempty"`
}

// loadHostnameExtensions reads <extensions_dir>/<hostname>.json and returns
// the entries as pkix.Extension values, merged with the container's own
// app-defined extensions when an upstream is configured. Returns nil when the
// directory is not configured or the file does not exist.
func (g *RATLSCertGetter) loadHostnameExtensions(hostname string) ([]pkix.Extension, error) {
	if g.ExtensionsDir == "" {
		return nil, nil
	}
	path := filepath.Join(g.ExtensionsDir, hostname+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ra_tls: read extensions file %q: %w", path, err)
	}
	var file extensionsFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("ra_tls: parse extensions file %q: %w", path, err)
	}
	exts, err := parseExtensionEntries(file.Extensions)
	if err != nil {
		return nil, fmt.Errorf("ra_tls: %s: %w", path, err)
	}

	// Reserved OIDs are stripped from what the container declares: a workload
	// may only publish under the app-defined sub-arc, never an identity or
	// configuration extension the manager stamps.
	if file.Upstream != "" {
		dynamic, err := fetchContainerExtensions(file.Upstream)
		if err != nil {
			g.logger.Warn("failed to fetch container extensions (continuing without them)",
				zap.String("hostname", hostname),
				zap.String("upstream", file.Upstream),
				zap.Error(err))
		}
		for _, ext := range dynamic {
			if reservedExtensionOID(ext.Id) {
				g.logger.Warn("dropping reserved OID self-declared by container",
					zap.String("hostname", hostname),
					zap.String("oid", ext.Id.String()))
				continue
			}
			exts = append(exts, ext)
		}
	}
	return exts, nil
}

// Intel-arc quote OIDs: a v1 certificate extension. A v2 leaf never carries
// them; they are refused from container declarations.
var (
	oidTDXQuote = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 5, 5, 1, 6}
	oidSGXQuote = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 0}
)

// oidPrivasysArc is the Privasys Private Enterprise Number arc every platform
// extension OID lives under.
var oidPrivasysArc = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65230}

// containerDeclarableArc reports whether a sub-arc under the Privasys PEN may
// be self-declared by a container: the app-defined sub-arc 5.4.<n> only (OID
// scheme v2). The root 5.4 itself carries no value.
func containerDeclarableArc(sub asn1.ObjectIdentifier) bool {
	return len(sub) >= 3 && sub[0] == 5 && sub[1] == 4
}

// reservedExtensionOID reports whether a container-declared extension OID must
// be dropped at issuance: the Intel quote OIDs and every Privasys OID outside
// the app-defined sub-arc. Identity is stamped by the measured manager, never
// self-declared.
func reservedExtensionOID(oid asn1.ObjectIdentifier) bool {
	if oid.Equal(oidTDXQuote) || oid.Equal(oidSGXQuote) {
		return true
	}
	if len(oid) <= len(oidPrivasysArc) {
		return false
	}
	for i, v := range oidPrivasysArc {
		if oid[i] != v {
			return false
		}
	}
	return !containerDeclarableArc(oid[len(oidPrivasysArc):])
}

// fetchContainerExtensions calls GET <upstream>/.well-known/attestation-extensions
// and parses the response as a JSON array of extensionEntry objects.
func fetchContainerExtensions(upstream string) ([]pkix.Extension, error) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(upstream + "/.well-known/attestation-extensions")
	if err != nil {
		return nil, fmt.Errorf("GET attestation-extensions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read attestation-extensions body: %w", err)
	}
	var entries []extensionEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse attestation-extensions: %w", err)
	}
	return parseExtensionEntries(entries)
}

// parseExtensionEntries converts extensionEntry values into pkix.Extension values.
func parseExtensionEntries(entries []extensionEntry) ([]pkix.Extension, error) {
	exts := make([]pkix.Extension, 0, len(entries))
	for _, e := range entries {
		oid, err := parseOID(e.OID)
		if err != nil {
			return nil, fmt.Errorf("invalid OID %q: %w", e.OID, err)
		}
		val, err := base64.StdEncoding.DecodeString(e.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 for OID %s: %w", e.OID, err)
		}
		exts = append(exts, pkix.Extension{Id: oid, Value: val})
	}
	return exts, nil
}

// parseOID converts a dot-notation OID string into an asn1.ObjectIdentifier.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, part := range splitDots(s) {
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return nil, fmt.Errorf("non-numeric component %q", part)
			}
			n = n*10 + int(c-'0')
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("too few components")
	}
	return oid, nil
}

func splitDots(s string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i > start {
				parts = append(parts, s[start:i])
			}
			start = i + 1
		}
	}
	return parts
}

// Interface guards.
var (
	_ caddy.Module          = (*RATLSCertGetter)(nil)
	_ caddy.Provisioner     = (*RATLSCertGetter)(nil)
	_ certmagic.Manager     = (*RATLSCertGetter)(nil)
	_ caddyfile.Unmarshaler = (*RATLSCertGetter)(nil)
)
