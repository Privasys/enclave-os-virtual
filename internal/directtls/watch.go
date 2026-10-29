package directtls

// A background duty per app, started by Apply:
//
//   - (The ordering guard lives in probe.go: no order until a validation
//     would reach this enclave.)
//
//   - Certificate Transparency watch: every publicly trusted certificate is
//     logged in CT. Each direct name is searched there periodically, and any
//     unexpired certificate whose key this enclave did not obtain itself is
//     reported (metric, log, status). With a CAA record pinning issuance to
//     the app's account there should never be one; this is how a broken or
//     relaxed CAA becomes visible.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

const (
	// CTSearch is the default Certificate Transparency search (crt.sh).
	CTSearch = "https://crt.sh"

	ctEvery      = 6 * time.Hour
	ctJitter     = 30 * time.Minute
	ctFirst      = 5 * time.Minute

	obtainedFile = "obtained.json"
)

var foreignCerts = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "enclave_os",
	Name:      "direct_foreign_certificates",
	Help:      "Unexpired publicly trusted certificates for a direct name whose key this enclave did not obtain (from Certificate Transparency).",
}, []string{"name"})

// ForeignCertificate is a certificate for a direct name this enclave did not
// obtain, as Certificate Transparency reports it.
type ForeignCertificate struct {
	Name      string `json:"name"`
	CrtshID   int64  `json:"crtsh_id"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Issuer    string `json:"issuer"`
}

// ctState is the watch's last result for an app.
type ctState struct {
	checkedAt time.Time
	err       string
	foreign   []ForeignCertificate
}

// obtained records every key this host obtained a certificate for, per name,
// so the CT watch can tell ours from anyone else's after a renewal rotated
// the key. Kept under the storage root.
type obtainedKeys struct {
	mu   sync.Mutex
	path string
}

func (o *obtainedKeys) load() map[string][]string {
	m := map[string][]string{}
	if data, err := os.ReadFile(o.path); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

// record adds the key of a name's current certificate.
func (o *obtainedKeys) record(name, spki string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	m := o.load()
	for _, k := range m[name] {
		if k == spki {
			return
		}
	}
	m[name] = append(m[name], spki)
	if data, err := json.Marshal(m); err == nil {
		_ = os.MkdirAll(filepath.Dir(o.path), 0o700)
		_ = os.WriteFile(o.path, data, 0o600)
	}
}

func (o *obtainedKeys) has(name, spki string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, k := range o.load()[name] {
		if k == spki {
			return true
		}
	}
	return false
}

// recordCurrent records the key of each name's current certificate, if any.
func (s *Service) recordCurrent(domains []string) {
	for _, d := range domains {
		if leaf, err := s.Leaf(d); err == nil {
			s.obtained.record(d, SPKIHash(leaf))
		}
	}
}

// watchCT runs the Certificate Transparency watch for an app until ctx ends.
func (s *Service) watchCT(ctx context.Context, container string, a *app) {
	wait := ctFirst + time.Duration(rand.Int64N(int64(ctFirst)))
	for {
		select {
		case <-ctx.Done():
			for _, d := range a.domains {
				foreignCerts.DeleteLabelValues(d)
			}
			return
		case <-time.After(wait):
		}
		st := s.checkCT(ctx, a.domains)
		s.mu.Lock()
		a.ct = st
		s.mu.Unlock()
		if st.err != "" {
			s.log.Info("certificate transparency check incomplete", zap.String("container", container), zap.String("error", st.err))
		}
		wait = ctEvery + time.Duration(rand.Int64N(int64(2*ctJitter))) - ctJitter
	}
}

// crtshEntry is one row of crt.sh's JSON search.
type crtshEntry struct {
	ID         int64  `json:"id"`
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

// checkCT searches CT for each name and reports certificates whose key is
// not one this host obtained.
func (s *Service) checkCT(ctx context.Context, domains []string) ctState {
	st := ctState{checkedAt: time.Now().UTC()}
	for _, d := range domains {
		count := 0
		entries, err := s.ctSearch(ctx, d)
		if err != nil {
			st.err = fmt.Sprintf("%s: %v", d, err)
			continue
		}
		for _, e := range entries {
			if s.ctSeen(e.ID) {
				continue
			}
			spki, err := s.ctKey(ctx, e.ID)
			if err != nil {
				st.err = fmt.Sprintf("%s: crt.sh id %d: %v", d, e.ID, err)
				continue
			}
			if s.obtained.has(d, spki) {
				s.ctMarkSeen(e.ID)
				continue
			}
			count++
			st.foreign = append(st.foreign, ForeignCertificate{
				Name: d, CrtshID: e.ID, NotBefore: e.NotBefore, NotAfter: e.NotAfter, Issuer: e.IssuerName,
			})
			s.log.Warn("a publicly trusted certificate for a direct name was not obtained here",
				zap.String("name", d), zap.Int64("crtsh_id", e.ID), zap.String("issuer", e.IssuerName))
		}
		foreignCerts.WithLabelValues(d).Set(float64(count))
	}
	return st
}

// ctSearch lists the unexpired certificates CT knows for name.
func (s *Service) ctSearch(ctx context.Context, name string) ([]crtshEntry, error) {
	u := fmt.Sprintf("%s/?q=%s&output=json&exclude=expired", s.ctBase(), url.QueryEscape(name))
	body, err := s.ctGet(ctx, u)
	if err != nil {
		return nil, err
	}
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parse search: %w", err)
	}
	return entries, nil
}

// ctKey downloads a logged certificate and returns its SPKI hash.
func (s *Service) ctKey(ctx context.Context, id int64) (string, error) {
	body, err := s.ctGet(ctx, fmt.Sprintf("%s/?d=%d", s.ctBase(), id))
	if err != nil {
		return "", err
	}
	der := body
	if block, _ := pem.Decode(body); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

// ctGet fetches a CT search URL, retrying a flaky answer a few times.
func (s *Service) ctGet(ctx context.Context, u string) ([]byte, error) {
	var last error
	for attempt, wait := 0, 2*time.Second; attempt < 3; attempt, wait = attempt+1, wait*3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := s.ctClient.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return body, nil
	}
	return nil, last
}

func (s *Service) ctBase() string {
	if s.cfg.CTSearch != "" {
		return s.cfg.CTSearch
	}
	return CTSearch
}

func (s *Service) ctSeen(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctOurs[id]
}

func (s *Service) ctMarkSeen(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctOurs[id] = true
}

func (s *Service) lookupHost(ctx context.Context, name string) ([]string, error) {
	if s.cfg.LookupHost != nil {
		return s.cfg.LookupHost(ctx, name)
	}
	return net.DefaultResolver.LookupHost(ctx, name)
}
