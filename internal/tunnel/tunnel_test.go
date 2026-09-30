// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package tunnel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
)

// fakeSigner stands in for enclaveauth.Signer: it records what it signed.
type fakeSigner struct{ path chan string }

func (f fakeSigner) Sign(req *http.Request, body []byte) error {
	req.Header.Set("X-Enclave-Id", "enc-1")
	req.Header.Set("X-Enclave-Sig", "sig")
	f.path <- req.Method + " " + req.URL.Path + " " + string(body)
	return nil
}

func serverTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{"tunnel.apps.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{ALPN},
	}, pool
}

// fakeGateway accepts one tunnel, checks the upgrade, answers status, and
// hands back the yamux client session (nil when status is not 101).
func fakeGateway(t *testing.T, status int) (addr string, pool *x509.CertPool, sessions chan *yamux.Session, reqs chan *http.Request) {
	t.Helper()
	cfg, pool := serverTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	sessions = make(chan *yamux.Session, 4)
	reqs = make(chan *http.Request, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					c.Close()
					return
				}
				io.ReadAll(req.Body)
				reqs <- req
				if status != http.StatusSwitchingProtocols {
					io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno")
					c.Close()
					return
				}
				io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: privasys-tunnel/1\r\nConnection: Upgrade\r\n\r\n")
				sess, err := yamux.Client(c, nil)
				if err != nil {
					c.Close()
					return
				}
				sessions <- sess
			}(c)
		}
	}()
	return ln.Addr().String(), pool, sessions, reqs
}

// echoTarget upper-cases what it reads until EOF: stands in for Caddy.
func echoTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				defer c.Close()
				b, _ := io.ReadAll(c)
				c.Write([]byte(strings.ToUpper(string(b))))
			}()
		}
	}()
	return ln.Addr().String()
}

func newClient(t *testing.T, gw string, pool *x509.CertPool, target string, signed chan string) *Client {
	t.Helper()
	c, err := New(Config{
		Gateways:   []string{gw},
		ServerName: "tunnel.apps.test",
		Target:     target,
		EnclaveID:  "enc-1",
		Signer:     fakeSigner{path: signed},
		TLSConfig:  &tls.Config{RootCAs: pool},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTunnelServesStreams(t *testing.T) {
	gw, pool, sessions, reqs := fakeGateway(t, http.StatusSwitchingProtocols)
	signed := make(chan string, 4)
	c := newClient(t, gw, pool, echoTarget(t), signed)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	req := <-reqs
	if req.Method != http.MethodPost || req.URL.Path != Path || req.Header.Get("Upgrade") != upgradeProtocol {
		t.Fatalf("upgrade request %s %s upgrade=%q", req.Method, req.URL.Path, req.Header.Get("Upgrade"))
	}
	if req.Header.Get("X-Enclave-Sig") == "" {
		t.Fatal("upgrade request not signed")
	}
	if s := <-signed; !strings.HasPrefix(s, "POST "+Path+" ") || !strings.Contains(s, `"enclave_id":"enc-1"`) {
		t.Fatalf("signed %q", s)
	}

	var sess *yamux.Session
	select {
	case sess = <-sessions:
	case <-time.After(5 * time.Second):
		t.Fatal("no session")
	}
	for i := 0; i < 3; i++ {
		s, err := sess.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		addr := "198.51.100.9:1234"
		pre := []byte{preambleVersion, 0, 0}
		binary.BigEndian.PutUint16(pre[1:], uint16(len(addr)))
		s.Write(append(pre, addr...))
		s.Write([]byte("client hello"))
		s.Close() // half-close
		s.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, err := io.ReadAll(s)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "CLIENT HELLO" {
			t.Fatalf("got %q", got)
		}
	}
	if st := c.Status()[gw]; st != "up" {
		t.Fatalf("status %q", st)
	}
}

func TestTunnelReconnectsAfterRefusal(t *testing.T) {
	gw, pool, _, reqs := fakeGateway(t, http.StatusForbidden)
	c := newClient(t, gw, pool, echoTarget(t), make(chan string, 16))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	for i := 0; i < 2; i++ { // refused, then retried after backoff
		select {
		case <-reqs:
		case <-time.After(5 * time.Second):
			t.Fatalf("attempt %d never arrived", i+1)
		}
	}
	if st := c.Status()[gw]; st == "up" {
		t.Fatal("refused tunnel reported up")
	}
}

func TestNewDisabledWithoutGateways(t *testing.T) {
	c, err := New(Config{Gateways: []string{" ", ""}}, zap.NewNop())
	if c != nil || err != nil {
		t.Fatalf("got %v, %v; want disabled", c, err)
	}
	if _, err := New(Config{Gateways: []string{"gw:443"}, ServerName: "x", EnclaveID: "e"}, zap.NewNop()); err == nil {
		t.Fatal("missing signer accepted")
	}
}
