package directtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

const probeName = "shop.example.com"

// probeService builds a service whose probe reaches addr for every name.
func probeService(t *testing.T, root, ca string, dialTo func() string) *Service {
	t.Helper()
	return New(Config{
		StorageRoot: root,
		CA:          ca,
		LookupHost: func(context.Context, string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		},
		ProbeDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dialTo())
		},
		ProbeFirstWait: 10 * time.Millisecond,
		ProbeMaxWait:   20 * time.Millisecond,
	}, zap.NewNop())
}

// gateway serves TLS on a local port with getCert.
func gateway(t *testing.T, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: getCert,
		NextProtos:     []string{acmeTLS1, "h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// caddyLike answers acme-tls/1 the way Caddy does for a direct name: from the
// distributed challenge in the shared storage, under an issuer of the same CA.
func caddyLike(root, ca string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
		Logger:           zap.NewNop(),
	})
	magic = certmagic.New(cache, certmagic.Config{Storage: &certmagic.FileStorage{Path: root}, Logger: zap.NewNop()})
	magic.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{CA: ca, Logger: zap.NewNop()})}
	return magic.GetCertificate
}

func probeSelfSigned(t *testing.T) *tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: probeName}, DNSNames: []string{probeName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tempRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "directtls-probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	return root
}

// The gateway splices acme-tls/1 to the enclave, whose Caddy serves the
// challenge from the shared storage: the probe passes, and leaves nothing.
func TestProbeSucceedsWhenTheChallengeReachesTheEnclave(t *testing.T) {
	root := tempRoot(t)
	const ca = "https://ca.example.test/directory"
	addr := gateway(t, caddyLike(root, ca))
	s := probeService(t, root, ca, func() string { return addr })

	if err := s.probe(context.Background(), probeName); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if _, err := os.Stat(root + "/" + s.challengeKey(probeName)); !os.IsNotExist(err) {
		t.Fatal("the probe challenge must be removed after the probe")
	}
}

// The name lands somewhere that does not serve this enclave's challenge (the
// gateway still terminating, or another server): the probe fails.
func TestProbeFailsOnSomeoneElsesCertificate(t *testing.T) {
	root := tempRoot(t)
	cert := probeSelfSigned(t)
	addr := gateway(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil })
	s := probeService(t, root, "https://ca.example.test/directory", func() string { return addr })

	err := s.probe(context.Background(), probeName)
	if err == nil || !strings.Contains(err.Error(), "not this enclave's challenge certificate") {
		t.Fatalf("probe = %v, want a wrong-certificate failure", err)
	}
}

func TestProbeFailsWithoutAConnection(t *testing.T) {
	root := tempRoot(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	s := probeService(t, root, "https://ca.example.test/directory", func() string { return addr })

	err := s.probe(context.Background(), probeName)
	if err == nil || !strings.HasPrefix(err.Error(), "connect") {
		t.Fatalf("probe = %v, want a connect failure", err)
	}
}

func TestProbeFailsWithoutDNS(t *testing.T) {
	s := New(Config{
		StorageRoot: tempRoot(t),
		LookupHost:  func(context.Context, string) ([]string, error) { return nil, errors.New("NXDOMAIN") },
	}, zap.NewNop())
	err := s.probe(context.Background(), probeName)
	if err == nil || !strings.HasPrefix(err.Error(), "no DNS") {
		t.Fatalf("probe = %v, want a DNS failure", err)
	}
}

// While the probe fails, the wrapper never lets an order reach the CA, and
// the status shows why.
func TestIssuerPlacesNoOrderWhileTheProbeFails(t *testing.T) {
	var caHits atomic.Int64
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caHits.Add(1)
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer ca.Close()

	root := tempRoot(t)
	cert := probeSelfSigned(t)
	addr := gateway(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil })
	s := probeService(t, root, ca.URL+"/directory", func() string { return addr })

	magic := certmagic.New(certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return nil, nil },
		Logger:           zap.NewNop(),
	}), certmagic.Config{Storage: s.storage, Logger: zap.NewNop()})
	iss := &probingIssuer{s: s, inner: certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{CA: ca.URL + "/directory", Agreed: true, Logger: zap.NewNop()})}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{probeName}}, key)
	csr, _ := x509.ParseCertificateRequest(csrDER)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := iss.Issue(ctx, csr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Issue = %v, want it to keep waiting for the probe", err)
	}
	if n := caHits.Load(); n != 0 {
		t.Fatalf("the CA was contacted %d times while the probe failed", n)
	}
	st := s.probeOf(probeName)
	if st == nil || st.OK || !strings.Contains(st.Error, "challenge certificate") {
		t.Fatalf("probe state = %+v", st)
	}
	if iss.IssuerKey() != IssuerKey(ca.URL+"/directory") {
		t.Fatal("the wrapper must keep the CA's issuer key (storage paths Caddy reads)")
	}
}
