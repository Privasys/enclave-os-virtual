package ratls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testIssuerKey = "acme-v02.api.letsencrypt.org-directory"

// writeDirectName lays out a direct name the way the manager does: the marker
// and a certificate in the certmagic storage layout.
func writeDirectName(t *testing.T, root, name string) []byte {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, directMarkerDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, directMarkerDir, name+".json"), []byte(`{"canonical":"app.apps.example.org"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := filepath.Join(root, "certificates", testIssuerKey, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, name+".crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	return der
}

type fakeConn struct {
	net.Conn
	remote string
}

func (c fakeConn) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", c.remote)
	return a
}

func TestDirectNameServesThePublicCertificateToBrowsers(t *testing.T) {
	root := t.TempDir()
	der := writeDirectName(t, root, "shop.example.com")
	g := &RATLSCertGetter{DirectStorage: root, DirectIssuerKey: testIssuerKey}

	hello := &tls.ClientHelloInfo{
		ServerName:      "shop.example.com",
		SupportedProtos: []string{"h2", "http/1.1"},
		Conn:            fakeConn{remote: "198.51.100.7:40001"},
	}
	cert, err := g.GetCertificate(context.Background(), hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if string(cert.Certificate[0]) != string(der) {
		t.Fatal("a browser on a direct name did not get the public certificate")
	}
	if got := connLeg("198.51.100.7:40001"); got != legDirect {
		t.Fatalf("connection leg = %q, want %q", got, legDirect)
	}
}

func TestDirectNameWithoutCertificateRefuses(t *testing.T) {
	root := t.TempDir()
	writeDirectName(t, root, "shop.example.com")
	os.RemoveAll(filepath.Join(root, "certificates"))
	g := &RATLSCertGetter{DirectStorage: root, DirectIssuerKey: testIssuerKey}
	_, err := g.GetCertificate(context.Background(), &tls.ClientHelloInfo{
		ServerName: "shop.example.com", SupportedProtos: []string{"h2"},
		Conn: fakeConn{remote: "198.51.100.7:40002"},
	})
	if err == nil {
		t.Fatal("a direct name with no certificate yet must refuse, not fall back to the RA-TLS leaf")
	}
}

func TestNonDirectNameIsUntouched(t *testing.T) {
	g := &RATLSCertGetter{DirectStorage: t.TempDir(), DirectIssuerKey: testIssuerKey}
	if g.isDirectName("app.apps.example.org") {
		t.Fatal("a name without a marker is not direct")
	}
	if g.isDirectName("../etc/passwd") {
		t.Fatal("a path-like name is never direct")
	}
	if (&RATLSCertGetter{}).isDirectName("shop.example.com") {
		t.Fatal("direct names are off without a storage root")
	}
}

// The leg reaches the manager from the connection, never from the request.
func TestAttestHandlerStampsTheDirectLeg(t *testing.T) {
	root := t.TempDir()
	writeDirectName(t, root, "shop.example.com")
	g := &RATLSCertGetter{DirectStorage: root, DirectIssuerKey: testIssuerKey}
	current.Store(g)
	defer current.Store(nil)

	var seen string
	next := handlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		seen = r.Header.Get(hdrEdge)
		return nil
	})
	h := &Attest{}

	// A client on the direct name that claims the RA-TLS leg in a header,
	// on a connection served the public certificate.
	tagConn(&tls.ClientHelloInfo{Conn: fakeConn{remote: "198.51.100.8:1"}}, legDirect)
	r := httptest.NewRequest(http.MethodGet, "https://shop.example.com/", nil)
	r.RemoteAddr = "198.51.100.8:1"
	r.TLS = &tls.ConnectionState{ServerName: "shop.example.com"}
	r.Header.Set(hdrEdge, "")
	h.ServeHTTP(httptest.NewRecorder(), r, next)
	if seen != legDirect {
		t.Fatalf("edge = %q, want %q", seen, legDirect)
	}

	// A resumed session: no certificate was served on this connection.
	r = httptest.NewRequest(http.MethodGet, "https://shop.example.com/", nil)
	r.RemoteAddr = "198.51.100.8:2"
	r.TLS = &tls.ConnectionState{ServerName: "shop.example.com"}
	h.ServeHTTP(httptest.NewRecorder(), r, next)
	if seen != legDirect {
		t.Fatalf("resumed session edge = %q, want %q (fail to the unverified leg)", seen, legDirect)
	}

	// The RA-TLS leaf on the same name: no marker, so the manager treats it
	// as TLS that ended here for a client that asked for attestation.
	tagConn(&tls.ClientHelloInfo{Conn: fakeConn{remote: "198.51.100.8:3"}}, legRATLS)
	r = httptest.NewRequest(http.MethodGet, "https://shop.example.com/", nil)
	r.RemoteAddr = "198.51.100.8:3"
	r.TLS = &tls.ConnectionState{ServerName: "shop.example.com"}
	r.Header.Set(hdrEdge, "direct")
	h.ServeHTTP(httptest.NewRecorder(), r, next)
	if seen != "" {
		t.Fatalf("RA-TLS edge = %q, want none", seen)
	}
}

type handlerFunc func(http.ResponseWriter, *http.Request) error

func (f handlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }
