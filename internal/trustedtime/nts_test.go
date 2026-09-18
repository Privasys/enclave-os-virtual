package trustedtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)

// quorumWith builds a quorum whose servers answer with fixed offsets from now
// (or fail).
func quorumWith(answers map[string]any) *NTSQuorum {
	var servers []string
	for s := range answers {
		servers = append(servers, s)
	}
	return &NTSQuorum{
		servers: servers,
		query: func(_ context.Context, s string, _ time.Time) (reading, error) {
			switch a := answers[s].(type) {
			case time.Duration:
				return reading{server: s, est: t0.Add(a), recv: time.Now()}, nil
			case error:
				return reading{}, a
			}
			return reading{}, fmt.Errorf("no answer for %s", s)
		},
	}
}

func TestQuorumAgreement(t *testing.T) {
	q := quorumWith(map[string]any{"a": time.Duration(0), "b": time.Second, "c": 1500 * time.Millisecond})
	s, err := q.Quorum(context.Background(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if d := s.Time.Sub(t0); d < 0 || d > 2*time.Second {
		t.Fatalf("unexpected quorum time offset %s", d)
	}
	if len(s.Servers) != 2 {
		t.Fatalf("servers %v", s.Servers)
	}
}

func TestQuorumMajority(t *testing.T) {
	// One liar: whichever two are picked first, the third settles it.
	for i := 0; i < 20; i++ {
		q := quorumWith(map[string]any{"a": time.Duration(0), "b": 500 * time.Millisecond, "liar": -time.Hour})
		s, err := q.Quorum(context.Background(), t0)
		if err != nil {
			t.Fatal(err)
		}
		if d := s.Time.Sub(t0); d < 0 || d > time.Second {
			t.Fatalf("majority lost to the liar: offset %s from %v", d, s.Servers)
		}
		for _, srv := range s.Servers {
			if srv == "liar" {
				t.Fatalf("liar in the quorum: %v", s.Servers)
			}
		}
	}
}

func TestQuorumNoMajority(t *testing.T) {
	q := quorumWith(map[string]any{"a": time.Duration(0), "b": time.Hour, "c": 2 * time.Hour})
	if _, err := q.Quorum(context.Background(), t0); err == nil {
		t.Fatal("want an error without a majority")
	}
	q = quorumWith(map[string]any{"a": time.Duration(0), "b": errors.New("down"), "c": errors.New("down")})
	if _, err := q.Quorum(context.Background(), t0); err == nil || !strings.Contains(err.Error(), "too few") {
		t.Fatalf("want too few replies, got %v", err)
	}
}

func TestCompiledServerList(t *testing.T) {
	if len(NTSServers) != 10 {
		t.Fatalf("want ten pinned servers, got %d", len(NTSServers))
	}
	seen := map[string]bool{}
	for _, s := range NTSServers {
		if seen[s] {
			t.Fatalf("duplicate %s", s)
		}
		seen[s] = true
	}
}

// chain mints a root and a leaf for host with the given leaf validity.
func chain(t *testing.T, host string, nb, na time.Time) (*x509.CertPool, []*x509.Certificate) {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: t0.AddDate(-5, 0, 0), NotAfter: t0.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rder, _ := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	root, _ := x509.ParseCertificate(rder)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: nb, NotAfter: na, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	lder, _ := x509.CreateCertificate(rand.Reader, lt, root, &lk.PublicKey, rk)
	leaf, _ := x509.ParseCertificate(lder)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool, []*x509.Certificate{leaf}
}

func TestVerifyAgainstFloor(t *testing.T) {
	floor := t0
	// Valid around the floor.
	pool, certs := chain(t, "nts.example", floor.Add(-24*time.Hour), floor.Add(24*time.Hour))
	if err := verifyAgainstFloor(certs, "nts.example", floor, pool); err != nil {
		t.Fatal(err)
	}
	// Expired before the floor: refused, whatever the host clock says.
	pool, certs = chain(t, "nts.example", floor.Add(-48*time.Hour), floor.Add(-time.Hour))
	if err := verifyAgainstFloor(certs, "nts.example", floor, pool); err == nil {
		t.Fatal("want an expired certificate refused")
	}
	// Issued after the floor (the floor is only a lower bound): accepted.
	pool, certs = chain(t, "nts.example", floor.Add(30*24*time.Hour), floor.Add(120*24*time.Hour))
	if err := verifyAgainstFloor(certs, "nts.example", floor, pool); err != nil {
		t.Fatalf("a certificate newer than the floor must pass: %v", err)
	}
	// Wrong host.
	pool, certs = chain(t, "other.example", floor.Add(-time.Hour), floor.Add(time.Hour))
	if err := verifyAgainstFloor(certs, "nts.example", floor, pool); err == nil {
		t.Fatal("want a hostname mismatch refused")
	}
	// Untrusted root.
	_, certs = chain(t, "nts.example", floor.Add(-time.Hour), floor.Add(time.Hour))
	other, _ := chain(t, "x", floor.Add(-time.Hour), floor.Add(time.Hour))
	if err := verifyAgainstFloor(certs, "nts.example", floor, other); err == nil {
		t.Fatal("want an unknown root refused")
	}
}

// TestLiveNTS queries the real pinned servers. It needs internet access
// (TCP 4460 and UDP 123) and runs only with PRIVASYS_LIVE_NTS=1.
func TestLiveNTS(t *testing.T) {
	if os.Getenv("PRIVASYS_LIVE_NTS") != "1" {
		t.Skip("set PRIVASYS_LIVE_NTS=1 to query the pinned NTS servers")
	}
	for _, s := range NTSServers {
		r, err := queryNTS(context.Background(), s, MinTrustedTime)
		if err != nil {
			t.Logf("%-26s FAIL %v", s, err)
			continue
		}
		t.Logf("%-26s ok   offset from host %s", s, r.now().Sub(time.Now()))
	}
	s, err := NewNTSQuorum().Quorum(context.Background(), MinTrustedTime)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("quorum %v from %v (host offset %s)", s.Time, s.Servers, s.Time.Sub(time.Now()))
}
