package directtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

func selfSigned(t *testing.T, name string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The CT watch reports a logged certificate whose key this host did not
// obtain, and stays quiet about its own.
func TestCheckCTFindsForeignCertificates(t *testing.T) {
	root, _ := os.MkdirTemp("", "directtls-ct")
	defer os.RemoveAll(root)

	ours := selfSigned(t, "shop.example.com")
	theirs := selfSigned(t, "shop.example.com")
	certs := map[string][]byte{"101": ours, "202": theirs}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.URL.Query().Get("d"); id != "" {
			w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[id]}))
			return
		}
		if r.URL.Query().Get("exclude") != "expired" {
			t.Errorf("the search must exclude expired certificates: %s", r.URL)
		}
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": 101, "issuer_name": "C=US, O=Let's Encrypt, CN=YE2", "not_before": "2026-10-29T10:45:22", "not_after": "2027-01-27T10:45:21"},
			{"id": 202, "issuer_name": "C=XX, O=Somebody Else", "not_before": "2026-10-30T00:00:00", "not_after": "2027-01-28T00:00:00"},
		})
	}))
	defer srv.Close()

	s := New(Config{StorageRoot: root, CA: "https://127.0.0.1:1/directory", CTSearch: srv.URL}, zap.NewNop())
	leaf, _ := x509.ParseCertificate(ours)
	s.obtained.record("shop.example.com", SPKIHash(leaf))

	st := s.checkCT(context.Background(), []string{"shop.example.com"})
	if st.err != "" {
		t.Fatalf("check error: %s", st.err)
	}
	if len(st.foreign) != 1 || st.foreign[0].CrtshID != 202 || st.foreign[0].Issuer != "C=XX, O=Somebody Else" {
		t.Fatalf("foreign = %+v, want only crt.sh 202", st.foreign)
	}
	if !s.ctSeen(101) {
		t.Fatal("our own certificate should be remembered, not downloaded again")
	}

	// The record of obtained keys survives a restart (it lives on /data).
	s2 := New(Config{StorageRoot: root, CA: "https://127.0.0.1:1/directory"}, zap.NewNop())
	if !s2.obtained.has("shop.example.com", SPKIHash(leaf)) {
		t.Fatal("obtained keys must persist under the storage root")
	}
}

// A CT search that cannot be reached degrades to an error in the status,
// never to "no foreign certificate" silently.
func TestCheckCTUnreachable(t *testing.T) {
	root, _ := os.MkdirTemp("", "directtls-ct")
	defer os.RemoveAll(root)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusBadGateway)
	}))
	defer srv.Close()
	s := New(Config{StorageRoot: root, CA: "https://127.0.0.1:1/directory", CTSearch: srv.URL}, zap.NewNop())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st := s.checkCT(ctx, []string{"shop.example.com"})
	if st.err == "" || st.checkedAt.IsZero() {
		t.Fatalf("state = %+v, want an error and a check time", st)
	}
}

// A name that does not resolve is not ordered yet (it stays waiting).
func TestOrderingGuardWaitsForDNS(t *testing.T) {
	root, _ := os.MkdirTemp("", "directtls-dns")
	defer os.RemoveAll(root)
	asked := make(chan string, 4)
	s := New(Config{StorageRoot: root, CA: "https://127.0.0.1:1/directory",
		LookupHost: func(_ context.Context, name string) ([]string, error) {
			asked <- name
			return nil, fmt.Errorf("NXDOMAIN")
		}}, zap.NewNop())
	key, _ := AccountKey([]byte("branch-of-app-one-volume-key-000"))
	if err := s.Apply("drive", "drive.apps.example.org", []string{"files.example.com"}, key); err != nil {
		t.Fatal(err)
	}
	defer s.Remove("drive")
	select {
	case n := <-asked:
		if n != "files.example.com" {
			t.Fatalf("resolved %q", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the guard never checked DNS")
	}
}
