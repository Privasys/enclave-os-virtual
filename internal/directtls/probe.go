package directtls

// Ordering guard: no ACME order for a direct name until a TLS-ALPN-01
// validation would reach this enclave.
//
// Let's Encrypt allows few failed validations per account and name per hour.
// An order placed while the name does not resolve, or while the platform
// gateway is not yet splicing the name's acme-tls/1 connections to this
// enclave, fails validation and burns that allowance, which can hold issuance
// back for an hour after everything is in place.
//
// So every issuance (first order, retry, renewal) goes through a wrapper
// issuer that first proves the path end to end: it publishes a throwaway
// TLS-ALPN-01 challenge in the shared storage, exactly where Caddy looks for
// a challenge, connects to the name through public DNS offering only
// acme-tls/1, and checks that the certificate it gets back carries that
// challenge's key authorization. Only then is the real order placed. Until
// then it waits and probes again, without contacting the CA.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

const (
	probeFirstWait = 2 * time.Minute
	probeMaxWait   = 15 * time.Minute
	probeTimeout   = 15 * time.Second
	acmeTLS1       = "acme-tls/1"
)

// oidACMEIdentifier is the acmeIdentifier extension of a TLS-ALPN-01
// challenge certificate (RFC 8737).
var oidACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// ProbeState is the last probe of a direct name, in the direct status.
type ProbeState struct {
	OK        bool   `json:"ok"`
	CheckedAt string `json:"checked_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// probingIssuer gates an ACME issuer on a successful probe of every name in
// the request. It keeps the inner issuer's key, so certificates and challenge
// tokens live where Caddy expects them.
type probingIssuer struct {
	inner *certmagic.ACMEIssuer
	s     *Service
}

func (p *probingIssuer) IssuerKey() string { return p.inner.IssuerKey() }

func (p *probingIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	return p.inner.PreCheck(ctx, names, interactive)
}

func (p *probingIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	return p.inner.Revoke(ctx, cert, reason)
}

func (p *probingIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	for _, name := range csr.DNSNames {
		if err := p.s.waitForProbe(ctx, name); err != nil {
			return nil, err
		}
	}
	return p.inner.Issue(ctx, csr)
}

// waitForProbe returns once a probe of name succeeds, or when ctx ends.
func (s *Service) waitForProbe(ctx context.Context, name string) error {
	wait := s.cfg.ProbeFirstWait
	if wait <= 0 {
		wait = probeFirstWait
	}
	maxWait := s.cfg.ProbeMaxWait
	if maxWait <= 0 {
		maxWait = probeMaxWait
	}
	for {
		err := s.probe(ctx, name)
		s.setProbe(name, err)
		if err == nil {
			s.log.Info("direct name reachable for validation, ordering", zap.String("name", name))
			return nil
		}
		s.log.Warn("direct name not reachable for validation yet; no order placed",
			zap.String("name", name), zap.Error(err), zap.Duration("next_probe", wait))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, maxWait)
	}
}

// probe publishes a throwaway challenge for name and checks that a client
// reaching name through public DNS with acme-tls/1 is served it.
func (s *Service) probe(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	addrs, err := s.lookupHost(ctx, name)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("no DNS: %v", errOr(err, "no address"))
	}

	keyAuth, err := randomToken()
	if err != nil {
		return err
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	chal := acme.Challenge{
		Type:             acme.ChallengeTypeTLSALPN01,
		Token:            token,
		KeyAuthorization: keyAuth,
		Identifier:       acme.Identifier{Type: "dns", Value: name},
	}
	b, err := json.Marshal(chal)
	if err != nil {
		return err
	}
	key := s.challengeKey(name)
	if err := s.storage.Store(ctx, key, b); err != nil {
		return fmt.Errorf("publish probe challenge: %w", err)
	}
	defer func() { _ = s.storage.Delete(context.Background(), key) }()

	port := s.cfg.ProbePort
	if port == "" {
		port = "443"
	}
	dial := s.cfg.ProbeDial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	raw, err := dial(ctx, "tcp", net.JoinHostPort(addrs[0], port))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: name,
		NextProtos: []string{acmeTLS1},
		// The challenge certificate is self-signed by design; what matters is
		// the key authorization it carries, checked below.
		InsecureSkipVerify: true,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("handshake: %w (the gateway is probably not passing the challenge to this enclave yet)", err)
	}
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return errors.New("no certificate served")
	}
	if !carriesKeyAuth(st.PeerCertificates[0], keyAuth) {
		return errors.New("not this enclave's challenge certificate (the gateway is not passing the challenge to this enclave yet)")
	}
	return nil
}

// challengeKey is where certmagic, and so Caddy, finds a distributed
// TLS-ALPN-01 challenge for name under this service's CA.
func (s *Service) challengeKey(name string) string {
	return path.Join("acme", certmagic.StorageKeys.Safe(s.issuerKey), "challenge_tokens", certmagic.StorageKeys.Safe(name)+".json")
}

// carriesKeyAuth reports whether cert is a TLS-ALPN-01 challenge certificate
// for keyAuth.
func carriesKeyAuth(cert *x509.Certificate, keyAuth string) bool {
	want := sha256.Sum256([]byte(keyAuth))
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidACMEIdentifier) {
			continue
		}
		var got []byte
		if _, err := asn1.Unmarshal(ext.Value, &got); err != nil {
			return false
		}
		return bytes.Equal(got, want[:])
	}
	return false
}

func (s *Service) setProbe(name string, err error) {
	st := ProbeState{OK: err == nil, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if err != nil {
		st.Error = err.Error()
	}
	s.mu.Lock()
	s.probes[name] = st
	s.mu.Unlock()
}

func (s *Service) probeOf(name string) *ProbeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.probes[name]
	if !ok {
		return nil
	}
	return &st
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func errOr(err error, fallback string) string {
	if err != nil {
		return err.Error()
	}
	return fallback
}
