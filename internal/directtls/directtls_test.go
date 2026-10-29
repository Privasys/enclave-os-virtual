package directtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func TestAccountKeyIsStablePerBranch(t *testing.T) {
	a1, err := AccountKey([]byte("branch-of-app-one-volume-key-000"))
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := AccountKey([]byte("branch-of-app-one-volume-key-000"))
	b, _ := AccountKey([]byte("branch-of-app-two-volume-key-000"))
	if !a1.Equal(a2) {
		t.Fatal("the same branch must give the same account key (it survives upgrades and CAA pins it)")
	}
	if a1.Equal(b) {
		t.Fatal("two apps must not share an account key")
	}
	if a1.Curve != elliptic.P256() {
		t.Fatal("the account key must be P-256 (accepted by Let's Encrypt)")
	}
	if _, err := AccountKey(nil); err == nil {
		t.Fatal("no branch (no vault-backed volume) must refuse")
	}
}

// writeLeaf stores a certificate where certmagic would.
func writeLeaf(t *testing.T, s *Service, name string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.cfg.StorageRoot, filepath.FromSlash(certmagic.StorageKeys.SiteCert(s.issuerKey, name)))
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	leaf, _ := x509.ParseCertificate(der)
	return leaf
}

func TestApplyMarksNamesAndReportsThem(t *testing.T) {
	// Not t.TempDir: certmagic's background retries may still touch the
	// storage (locks) after the test, which fails TempDir's strict cleanup.
	root, err := os.MkdirTemp("", "directtls")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	// An unreachable CA: issuance keeps failing in the background, which is
	// what a host before the gateway splices the challenge looks like.
	s := New(Config{StorageRoot: root, CA: "https://127.0.0.1:1/directory"}, zap.NewNop())
	key, _ := AccountKey([]byte("branch-of-app-one-volume-key-000"))

	if err := s.Apply("drive", "drive.apps.example.org", []string{"Files.Example.com", "b.example.com"}, key); err != nil {
		t.Fatal(err)
	}
	defer s.Remove("drive")
	for _, d := range []string{"files.example.com", "b.example.com"} {
		data, err := os.ReadFile(filepath.Join(root, MarkerDir, d+".json"))
		if err != nil {
			t.Fatalf("no marker for %s: %v", d, err)
		}
		if !bytes.Contains(data, []byte("drive.apps.example.org")) {
			t.Fatalf("marker for %s does not name the canonical host: %s", d, data)
		}
	}

	st := s.Status("drive")
	if !st.Supported || len(st.Domains) != 2 || st.Domains[0].Issued {
		t.Fatalf("status before issuance = %+v", st)
	}
	if s.KeyBindings("drive") != nil {
		t.Fatal("no key binding before a certificate exists")
	}

	leaf := writeLeaf(t, s, "files.example.com")
	st = s.Status("drive")
	var got DomainStatus
	for _, d := range st.Domains {
		if d.Name == "files.example.com" {
			got = d
		}
	}
	if !got.Issued || got.SPKISHA256 != SPKIHash(leaf) {
		t.Fatalf("status after issuance = %+v", got)
	}
	if kb := string(s.KeyBindings("drive")); kb != "files.example.com sha256:"+SPKIHash(leaf) {
		t.Fatalf("key bindings = %q", kb)
	}

	// Dropping a name removes its marker; the rest stay.
	if err := s.Apply("drive", "drive.apps.example.org", []string{"files.example.com"}, key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, MarkerDir, "b.example.com.json")); !os.IsNotExist(err) {
		t.Fatal("a dropped name kept its marker")
	}
	s.Remove("drive")
	if _, err := os.Stat(filepath.Join(root, MarkerDir, "files.example.com.json")); !os.IsNotExist(err) {
		t.Fatal("Remove kept a marker")
	}
}

func TestIssuerKeyMatchesCaddysLayout(t *testing.T) {
	if got := IssuerKey(LetsEncrypt); !strings.Contains(got, "acme-v02.api.letsencrypt.org") {
		t.Fatalf("issuer key = %q", got)
	}
}
