package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// jwksIssuer serves discovery and a one-key JWKS, counting fetches, with an
// optional delay on the JWKS response.
type jwksIssuer struct {
	fetches atomic.Int32
	delay   atomic.Int64 // nanoseconds
	url     string
}

func newJWKSIssuer(t *testing.T) *jwksIssuer {
	t.Helper()
	is := &jwksIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"jwks_uri": is.url + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		is.fetches.Add(1)
		time.Sleep(time.Duration(is.delay.Load()))
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "known",
			"x": "AA", "y": "AA",
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	is.url = srv.URL
	return is
}

func newJWKSVerifier(t *testing.T, issuer string) *Verifier {
	t.Helper()
	v, err := NewVerifier(&OIDCConfig{Issuer: issuer, Audience: "a"}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Unknown kids are caller-chosen. However many arrive, they may cause at
// most one refresh per oidcJWKSMinRefresh.
func TestUnknownKidsDoNotEachRefetchTheJWKS(t *testing.T) {
	is := newJWKSIssuer(t)
	v := newJWKSVerifier(t, is.url)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := v.getSigningKey(fmt.Sprintf("random-%d", i), "ES256"); err == nil {
				t.Errorf("unknown kid %d resolved", i)
			}
		}(i)
	}
	wg.Wait()

	if n := is.fetches.Load(); n != 1 {
		t.Fatalf("50 unknown kids caused %d JWKS fetches, want 1", n)
	}
}

// A lookup that hits a fresh cache must not wait for a refresh another
// caller triggered.
func TestAKnownKidIsNotBlockedByARefreshInFlight(t *testing.T) {
	is := newJWKSIssuer(t)
	v := newJWKSVerifier(t, is.url)
	if _, err := v.getSigningKey("known", "ES256"); err != nil {
		t.Fatalf("prime: %v", err)
	}

	// Let the refresh window pass, then make the IdP slow and start a
	// refresh with an unknown kid.
	v.refreshMu.Lock()
	v.lastRefresh = time.Now().Add(-2 * oidcJWKSMinRefresh)
	v.refreshMu.Unlock()
	is.delay.Store(int64(2 * time.Second))
	go v.getSigningKey("unknown", "ES256")
	time.Sleep(100 * time.Millisecond) // the refresh is now in flight

	start := time.Now()
	if _, err := v.getSigningKey("known", "ES256"); err != nil {
		t.Fatalf("known kid: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("known kid waited %v behind a refresh", d)
	}
}
