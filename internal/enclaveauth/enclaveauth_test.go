package enclaveauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enclave-os-mini/clients/go/ratls"
)

// testCA writes a self-signed CA pair, standing in for the per-enclave CA the
// control plane delivers at approval.
func testCA(t *testing.T) (dir string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test enclave CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	write := func(name, blockType string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", "CERTIFICATE", der)
	write("ca.key", "EC PRIVATE KEY", keyDER)
	return dir, cert
}

// newTestSigner returns a Signer whose quotes are stubbed: a real quote needs
// TDX hardware, and what matters here is what the signer commits to.
func newTestSigner(t *testing.T, enclaveID string) (*Signer, *x509.Certificate, *[64]byte) {
	t.Helper()
	dir, ca := testCA(t)
	s, err := New(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), enclaveID)
	if err != nil {
		t.Fatal(err)
	}
	var lastReportData [64]byte
	s.quoteFn = func(rd [64]byte) ([]byte, error) {
		lastReportData = rd
		return []byte("stub-quote"), nil
	}
	s.nowFn = func() (time.Time, error) { return time.Now(), nil }
	return s, ca, &lastReportData
}

// The headers must satisfy every check the control plane makes: the leaf was
// issued by this enclave's CA, report_data binds that leaf to the challenge,
// and the signature covers this exact request.
func TestSignedRequestSatisfiesTheControlPlaneChecks(t *testing.T) {
	s, ca, reportData := newTestSigner(t, "11111111-2222-3333-4444-555555555555")
	body := []byte(`{"enclave_id":"11111111-2222-3333-4444-555555555555"}`)
	req, err := http.NewRequest(http.MethodPost, "https://api.example.org/api/v1/enclave/runtime-status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Sign(req, body); err != nil {
		t.Fatal(err)
	}

	if got := req.Header.Get(HeaderEnclaveID); got != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("enclave id header = %q", got)
	}
	certDER, err := base64.StdEncoding.DecodeString(req.Header.Get(HeaderIdentity))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("leaf was not issued by the enclave CA: %v", err)
	}

	challenge, err := base64.StdEncoding.DecodeString(req.Header.Get(HeaderChallenge))
	if err != nil || len(challenge) != ratls.ContextLen {
		t.Fatalf("challenge: %v (%d bytes)", err, len(challenge))
	}
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := ratls.ClientReportData(spki, challenge, ratls.HeaderIdentityHctx[:], nil)
	if string(want) != string(reportData[:]) {
		t.Error("report_data does not bind the leaf key to the challenge")
	}
	bound := int64(binary.BigEndian.Uint64(challenge[:8]))
	if skew := time.Since(time.Unix(bound, 0)); skew > time.Minute || skew < -time.Minute {
		t.Errorf("challenge timestamp is not now (skew %s)", skew)
	}

	sig, err := base64.StdEncoding.DecodeString(req.Header.Get(HeaderSignature))
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf key is %T", leaf.PublicKey)
	}
	canon := CanonicalString(req.Method, req.URL.Path, req.Header.Get(HeaderTimestamp), req.Header.Get(HeaderNonce), body)
	digest := sha256.Sum256([]byte(canon))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature does not verify over the canonical string")
	}
	// The same signature must not stand for another route or another body.
	other := sha256.Sum256([]byte(CanonicalString(req.Method, "/api/v1/enclave/checkin", req.Header.Get(HeaderTimestamp), req.Header.Get(HeaderNonce), body)))
	if ecdsa.VerifyASN1(pub, other[:], sig) {
		t.Error("the signature also verified for a different path")
	}
	otherBody := sha256.Sum256([]byte(CanonicalString(req.Method, req.URL.Path, req.Header.Get(HeaderTimestamp), req.Header.Get(HeaderNonce), []byte("{}"))))
	if ecdsa.VerifyASN1(pub, otherBody[:], sig) {
		t.Error("the signature also verified for a different body")
	}
}

// Each request gets its own nonce, so two identical calls are distinguishable
// and the control plane's replay cache can do its job.
func TestEachRequestGetsItsOwnNonce(t *testing.T) {
	s, _, _ := newTestSigner(t, "11111111-2222-3333-4444-555555555555")
	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://api.example.org/x", nil)
		if err := s.Sign(req, nil); err != nil {
			t.Fatal(err)
		}
		n := req.Header.Get(HeaderNonce)
		if n == "" || seen[n] {
			t.Fatalf("nonce %q repeated or empty", n)
		}
		seen[n] = true
	}
}

// One identity is reused for a few minutes, so a burst of calls does not ask
// the hardware for a quote each time.
func TestIdentityIsReusedThenRefreshed(t *testing.T) {
	s, _, _ := newTestSigner(t, "11111111-2222-3333-4444-555555555555")
	quotes := 0
	s.quoteFn = func([64]byte) ([]byte, error) { quotes++; return []byte("q"), nil }
	now := time.Now()
	s.nowFn = func() (time.Time, error) { return now, nil }

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://api.example.org/x", nil)
		if err := s.Sign(req, nil); err != nil {
			t.Fatal(err)
		}
	}
	if quotes != 1 {
		t.Errorf("quotes taken for a burst = %d, want 1", quotes)
	}
	now = now.Add(identityLifetime + time.Second)
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.org/x", nil)
	if err := s.Sign(req, nil); err != nil {
		t.Fatal(err)
	}
	if quotes != 2 {
		t.Errorf("quotes after the lifetime = %d, want 2", quotes)
	}
}

// Without trusted time the signer refuses rather than dating itself by the
// host's clock.
func TestNoTrustedTimeNoSignature(t *testing.T) {
	s, _, _ := newTestSigner(t, "11111111-2222-3333-4444-555555555555")
	s.nowFn = func() (time.Time, error) { return time.Time{}, os.ErrDeadlineExceeded }
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.org/x", nil)
	err := s.Sign(req, nil)
	if err == nil {
		t.Fatal("signed without trusted time")
	}
	if !strings.Contains(err.Error(), "trusted time") {
		t.Errorf("error does not name the cause: %v", err)
	}
	if req.Header.Get(HeaderSignature) != "" {
		t.Error("headers were attached despite the failure")
	}
}
