// Package directtls obtains and renews the publicly trusted certificates of
// an app's direct domains: adopter hostnames whose TLS ends in this enclave.
//
// The platform gateway splices a direct name at L4, so the only way a browser
// gets a certificate it trusts is for the enclave to obtain one itself. This
// package does that with certmagic over ACME TLS-ALPN-01:
//
//   - The ACME account key is derived from the app's vault-backed volume key
//     (a one-way branch), so only approved measurements can hold it, it
//     survives upgrades, and every enclave serving the app holds the same
//     account. An adopter's CAA record can then pin issuance to that account
//     (RFC 8657 accounturi), and nobody else can obtain a certificate for the
//     name, the platform included.
//   - Each certificate key is generated here and never leaves the enclave
//     (the storage root is on the encrypted /data volume).
//   - Certificates and challenge tokens go into the storage root that Caddy
//     also uses: Caddy answers the acme-tls/1 challenge from it, and the
//     ra_tls certificate getter serves the certificate from it.
//
// Only names in the owner-approved app policy are ever requested.
package directtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

// LetsEncrypt is the production ACME directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// MarkerDir is the directory under the storage root holding one <name>.json
// per direct name. The ra_tls getter reads it; keep in step with
// caddy/ratls/direct.go.
const MarkerDir = "privasys-direct"

// accountKeyInfo is the HKDF label of the account key. Changing it changes
// every app's ACME account, which breaks every CAA record that pins one.
const accountKeyInfo = "privasys-acme-account/v1"

// AccountKey derives the app's ACME account key (ECDSA P-256) from its
// one-way branch of the volume key.
func AccountKey(branch []byte) (*ecdsa.PrivateKey, error) {
	if len(branch) == 0 {
		return nil, fmt.Errorf("directtls: no key branch (the app has no vault-backed volume)")
	}
	for i := 0; i < 16; i++ {
		raw, err := hkdf.Key(sha256.New, branch, nil, fmt.Sprintf("%s|%d", accountKeyInfo, i), 32)
		if err != nil {
			return nil, err
		}
		if key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("directtls: no valid account key derived")
}

// Config addresses the CA and the shared storage.
type Config struct {
	// StorageRoot is the Caddy storage root (file_system), on /data.
	StorageRoot string
	// CA is the ACME directory URL. Empty means LetsEncrypt.
	CA string
	// OnChange is called with the container name after a certificate of
	// one of its names was obtained or renewed, so the launcher can stamp
	// the new key on the app's attestation.
	OnChange func(container string)
	// CTSearch is the Certificate Transparency search base URL (empty:
	// crt.sh), and LookupHost the resolver the ordering guard uses (nil:
	// the system resolver). Both exist for tests.
	CTSearch   string
	LookupHost func(ctx context.Context, name string) ([]string, error)

	// The ordering probe (probe.go): ProbeDial and ProbePort reach a name
	// (nil and "" mean a plain TCP dial to port 443), ProbeFirstWait and
	// ProbeMaxWait pace the retries (zero: 2 and 15 minutes). For tests.
	ProbeDial      func(ctx context.Context, network, addr string) (net.Conn, error)
	ProbePort      string
	ProbeFirstWait time.Duration
	ProbeMaxWait   time.Duration
}

// Status is what the control plane reads to decide whether a domain may go
// direct.
type Status struct {
	Supported  bool           `json:"supported"`
	AccountURI string         `json:"account_uri"`
	Domains    []DomainStatus `json:"domains"`
	// Certificate Transparency watch (watch.go): when it last completed,
	// what it could not check, and any certificate for a direct name whose
	// key this enclave did not obtain.
	CTCheckedAt         string               `json:"ct_checked_at,omitempty"`
	CTError             string               `json:"ct_error,omitempty"`
	ForeignCertificates []ForeignCertificate `json:"foreign_certificates"`
}

// DomainStatus describes one direct name.
type DomainStatus struct {
	Name       string `json:"name"`
	Issued     bool   `json:"issued"`
	NotAfter   string `json:"not_after,omitempty"`
	SPKISHA256 string `json:"spki_sha256,omitempty"`
	// Probe is the last check that a validation would reach this enclave
	// (probe.go); absent until the first issuance attempt.
	Probe *ProbeState `json:"probe,omitempty"`
}

type app struct {
	canonical  string
	domains    []string
	key        *ecdsa.PrivateKey
	accountURI string
	cache      *certmagic.Cache
	cancel     context.CancelFunc
	ct         ctState
}

// Service manages the direct names of every container on this host.
type Service struct {
	cfg       Config
	log       *zap.Logger
	storage   *certmagic.FileStorage
	issuerKey string

	mu   sync.Mutex
	apps map[string]*app // by container name

	obtained *obtainedKeys
	ctClient *http.Client
	ctOurs   map[int64]bool // crt.sh ids already matched to a key of ours
	probes   map[string]ProbeState
}

// New builds the service. It does nothing until Apply names a domain.
func New(cfg Config, log *zap.Logger) *Service {
	if cfg.CA == "" {
		cfg.CA = LetsEncrypt
	}
	s := &Service{
		cfg:     cfg,
		log:     log.Named("directtls"),
		storage: &certmagic.FileStorage{Path: cfg.StorageRoot},
		apps:    map[string]*app{},
		obtained: &obtainedKeys{path: filepath.Join(cfg.StorageRoot, MarkerDir, obtainedFile)},
		ctClient: &http.Client{Timeout: 30 * time.Second},
		ctOurs:   map[int64]bool{},
		probes:   map[string]ProbeState{},
	}
	s.issuerKey = IssuerKey(cfg.CA)
	return s
}

// IssuerKey is certmagic's storage key for a CA, which Caddy's issuer of the
// same CA computes identically (it is how Caddy finds the challenge).
func IssuerKey(ca string) string {
	return certmagic.NewACMEIssuer(&certmagic.Config{}, certmagic.ACMEIssuer{CA: ca}).IssuerKey()
}

// IssuerDir is the directory name of this service's CA under certificates/
// in the storage root, which the ra_tls getter is configured with.
func (s *Service) IssuerDir() string { return certmagic.StorageKeys.Safe(s.issuerKey) }

// CA returns the ACME directory this service uses.
func (s *Service) CA() string { return s.cfg.CA }

// Apply sets the direct names of a container: writes their markers, and
// starts obtaining and renewing their certificates. An empty list removes
// them. Calling it again with the same names is cheap.
func (s *Service) Apply(container, canonical string, domains []string, key *ecdsa.PrivateKey) error {
	domains = normalise(domains)
	s.mu.Lock()
	old := s.apps[container]
	if old != nil && old.canonical == canonical && equal(old.domains, domains) && sameKey(old.key, key) {
		s.mu.Unlock()
		return nil
	}
	if old != nil {
		old.stop()
		delete(s.apps, container)
	}
	s.mu.Unlock()

	for _, d := range removed(old, domains) {
		_ = os.Remove(s.markerPath(d))
	}
	if len(domains) == 0 {
		return nil
	}
	if key == nil {
		return fmt.Errorf("directtls: %s has no account key", container)
	}
	if err := os.MkdirAll(filepath.Join(s.cfg.StorageRoot, MarkerDir), 0o700); err != nil {
		return fmt.Errorf("directtls: marker dir: %w", err)
	}
	for _, d := range domains {
		b, _ := json.Marshal(map[string]string{"canonical": canonical})
		if err := os.WriteFile(s.markerPath(d), b, 0o600); err != nil {
			return fmt.Errorf("directtls: marker for %s: %w", d, err)
		}
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	a := &app{canonical: canonical, domains: domains, key: key}
	var magic *certmagic.Config
	a.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
		Logger:           s.log,
	})
	magic = certmagic.New(a.cache, certmagic.Config{
		Storage: s.storage,
		Logger:  s.log,
		OnEvent: func(_ context.Context, event string, data map[string]any) error {
			if event == "cert_obtained" {
				s.recordCurrent(domains)
				if s.cfg.OnChange != nil {
					go s.cfg.OnChange(container)
				}
			}
			return nil
		},
	})
	// Every issuance (first order, retry, renewal) is gated on a probe that a
	// validation would reach this enclave (probe.go).
	magic.Issuers = []certmagic.Issuer{&probingIssuer{s: s, inner: certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA: s.cfg.CA,
		// After a failure certmagic retries against a "test" CA (Let's
		// Encrypt staging by default) with the SAME account, which staging
		// rejects ("KeyID header contained an invalid account URL"), so a
		// name whose first attempt failed could never be issued. One CA.
		TestCA:               s.cfg.CA,
		Agreed:               true,
		AccountKeyPEM:        keyPEM,
		DisableHTTPChallenge: true,
		Logger:               s.log,
	})}}

	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	s.mu.Lock()
	s.apps[container] = a
	s.mu.Unlock()

	s.recordCurrent(domains)
	go s.resolveAccount(ctx, container, a)
	if err := magic.ManageAsync(ctx, domains); err != nil {
		s.log.Warn("direct names not managed", zap.String("container", container), zap.Strings("domains", domains), zap.Error(err))
	}
	go s.watchCT(ctx, container, a)
	s.log.Info("direct names set",
		zap.String("container", container), zap.String("canonical", canonical), zap.Strings("domains", domains))
	return nil
}

// Remove drops every direct name of a container.
func (s *Service) Remove(container string) {
	_ = s.Apply(container, "", nil, nil)
}

// resolveAccount learns the account URL the CA assigned to the app's key, the
// value an adopter's CAA record pins. Registering an existing key returns the
// same account, so this is idempotent.
func (s *Service) resolveAccount(ctx context.Context, container string, a *app) {
	client := acmez.Client{Client: &acme.Client{Directory: s.cfg.CA}}
	for wait := 5 * time.Second; ; wait = min(wait*2, 10*time.Minute) {
		acct, err := client.NewAccount(ctx, acme.Account{TermsOfServiceAgreed: true, PrivateKey: a.key})
		if err == nil {
			s.mu.Lock()
			a.accountURI = acct.Location
			s.mu.Unlock()
			s.log.Info("ACME account resolved", zap.String("container", container), zap.String("account", acct.Location))
			return
		}
		s.log.Warn("ACME account not resolved yet", zap.String("container", container), zap.Error(err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Status reports a container's direct names.
func (s *Service) Status(container string) Status {
	st := Status{Supported: true, Domains: []DomainStatus{}, ForeignCertificates: []ForeignCertificate{}}
	s.mu.Lock()
	a := s.apps[container]
	var domains []string
	if a != nil {
		st.AccountURI = a.accountURI
		domains = append(domains, a.domains...)
		if !a.ct.checkedAt.IsZero() {
			st.CTCheckedAt = a.ct.checkedAt.Format(time.RFC3339)
		}
		st.CTError = a.ct.err
		st.ForeignCertificates = append(st.ForeignCertificates, a.ct.foreign...)
	}
	s.mu.Unlock()
	for _, d := range domains {
		ds := DomainStatus{Name: d}
		if leaf, err := s.Leaf(d); err == nil {
			ds.Issued = true
			ds.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
			ds.SPKISHA256 = SPKIHash(leaf)
		}
		ds.Probe = s.probeOf(d)
		st.Domains = append(st.Domains, ds)
	}
	return st
}

// Leaf returns the current certificate of a direct name.
func (s *Service) Leaf(name string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(s.cfg.StorageRoot, filepath.FromSlash(certmagic.StorageKeys.SiteCert(s.issuerKey, name))))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("directtls: %s: no PEM certificate", name)
	}
	return x509.ParseCertificate(block.Bytes)
}

// KeyBindings returns "name sha256:<spki hex>" lines for the issued names of
// a container, sorted, for the attestation stamp. Nil when none is issued.
func (s *Service) KeyBindings(container string) []byte {
	s.mu.Lock()
	a := s.apps[container]
	var domains []string
	if a != nil {
		domains = append(domains, a.domains...)
	}
	s.mu.Unlock()
	var lines []string
	for _, d := range domains {
		if leaf, err := s.Leaf(d); err == nil {
			lines = append(lines, d+" sha256:"+SPKIHash(leaf))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n"))
}

// SPKIHash is the hex SHA-256 of a certificate's SubjectPublicKeyInfo.
func SPKIHash(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func (s *Service) markerPath(name string) string {
	return filepath.Join(s.cfg.StorageRoot, MarkerDir, name+".json")
}

func (a *app) stop() {
	if a.cancel != nil {
		a.cancel()
	}
	if a.cache != nil {
		a.cache.Stop()
	}
}

func normalise(domains []string) []string {
	out := make([]string, 0, len(domains))
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameKey(a, b *ecdsa.PrivateKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(b)
}

func removed(old *app, keep []string) []string {
	if old == nil {
		return nil
	}
	k := map[string]bool{}
	for _, d := range keep {
		k[d] = true
	}
	var out []string
	for _, d := range old.domains {
		if !k[d] {
			out = append(out, d)
		}
	}
	return out
}
