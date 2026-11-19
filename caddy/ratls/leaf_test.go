package ratls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// leafGetter returns a getter with one published hostname, and empty key tables.
func leafGetter(t *testing.T, published string) *RATLSCertGetter {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, published+".json"), []byte(`{"extensions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	leaves.mu.Lock()
	leaves.bySNI = map[string]*leafKey{}
	leaves.bySPKI = map[[32]byte]*leafKey{}
	leaves.purged = time.Time{}
	leaves.mu.Unlock()
	return &RATLSCertGetter{
		ExtensionsDir: dir,
		caCert:        ca,
		caKey:         key,
		logger:        zap.NewNop(),
		mu:            new(sync.RWMutex),
		cache:         map[string]*cachedCert{},
	}
}

func leafSPKI(t *testing.T, g *RATLSCertGetter, sni string) string {
	t.Helper()
	cert, err := g.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		t.Fatalf("GetCertificate(%q): %v", sni, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(leaf.RawSubjectPublicKeyInfo)
}

// The SNI is client-supplied, so names with no app must not grow any table.
func TestUnknownNamesShareOneKeyAndLeaveNothingBehind(t *testing.T) {
	g := leafGetter(t, "app.example")
	first := leafSPKI(t, g, "unknown-0.example")
	for i := 1; i < 500; i++ {
		if got := leafSPKI(t, g, fmt.Sprintf("unknown-%d.example", i)); got != first {
			t.Fatalf("unknown name %d got its own key", i)
		}
	}
	if got := leafSPKI(t, g, ""); got != first {
		t.Fatal("a handshake with no SNI did not use the shared key")
	}
	if n := len(leaves.bySNI); n != 1 {
		t.Fatalf("%d keys by SNI, want the shared one", n)
	}
	if n := len(leaves.bySPKI); n != 1 {
		t.Fatalf("%d keys by SPKI, want the shared one", n)
	}
	if n := len(g.cache); n != 0 {
		t.Fatalf("%d cached leaves, want none", n)
	}
}

// A leaf still names the SNI it was asked for.
func TestUnknownNameLeafNamesTheSNI(t *testing.T) {
	g := leafGetter(t, "app.example")
	cert, err := g.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: "other.example"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("other.example"); err != nil {
		t.Fatal(err)
	}
}

// A flood of other names must not rotate a published app's key.
func TestPublishedNameKeepsItsOwnKey(t *testing.T) {
	g := leafGetter(t, "app.example")
	key := leafSPKI(t, g, "app.example")
	if shared := leafSPKI(t, g, "unknown.example"); shared == key {
		t.Fatal("a published app shares the key of unknown names")
	}
	for i := 0; i < 500; i++ {
		leafSPKI(t, g, fmt.Sprintf("unknown-%d.example", i))
	}
	if got := leafSPKI(t, g, "app.example"); got != key {
		t.Fatal("the published app's key changed")
	}
	if n := len(g.cache); n != 1 {
		t.Fatalf("%d cached leaves, want the published app's", n)
	}
}

func TestMalformedNamesAreRefused(t *testing.T) {
	g := leafGetter(t, "app.example")
	for _, sni := range []string{
		"../app.example",
		"x/../app.example",
		`a\b.example`,
		"a b.example",
		"a\x00b.example",
		strings.Repeat("a", maxSNILen+1),
	} {
		if _, err := g.GetCertificate(context.Background(), &tls.ClientHelloInfo{ServerName: sni}); err == nil {
			t.Fatalf("%.32q was accepted", sni)
		}
	}
	if n := len(leaves.bySNI); n != 0 {
		t.Fatalf("%d keys after refused names, want 0", n)
	}
}

func TestValidNamesAreAccepted(t *testing.T) {
	for _, sni := range []string{"", "app.apps.privasys.org", "APP.example", "my_app-1.example", "34.155.4.106", "2001:db8::1", strings.Repeat("a", maxSNILen)} {
		if !validSNI(sni) {
			t.Fatalf("%.32q was refused", sni)
		}
	}
}

// A key past its retention leaves both tables.
func TestExpiredKeysAreDropped(t *testing.T) {
	leafGetter(t, "app.example")
	now := time.Now()
	leafKeyFor("old.example", now)
	leafKeyFor("new.example", now.Add(leafLifetime+previousRetention+time.Hour))
	if _, ok := leaves.bySNI["old.example"]; ok {
		t.Fatal("the expired key is still held by SNI")
	}
	if n := len(leaves.bySPKI); n != 1 {
		t.Fatalf("%d keys by SPKI, want 1", n)
	}
}

// A rotated key stays answerable through its retention.
func TestRotatedKeyStaysAnswerable(t *testing.T) {
	leafGetter(t, "app.example")
	now := time.Now()
	old := leafKeyFor("app.example", now)
	rotated := leafKeyFor("app.example", now.Add(leafLifetime+time.Minute))
	if rotated == old {
		t.Fatal("the key did not rotate")
	}
	if leafBySPKI(old.spkiHash) == nil {
		t.Fatal("the rotated key is no longer answerable")
	}
}

func TestDirectMarkerCacheIsBounded(t *testing.T) {
	g := &RATLSCertGetter{DirectStorage: t.TempDir(), DirectIssuerKey: testIssuerKey}
	for i := 0; i < maxDirectMarkers+100; i++ {
		g.isDirectName(fmt.Sprintf("unknown-%d.example", i))
	}
	direct.mu.Lock()
	n := len(direct.markers)
	direct.mu.Unlock()
	if n > maxDirectMarkers {
		t.Fatalf("%d cached markers, want at most %d", n, maxDirectMarkers)
	}
}
