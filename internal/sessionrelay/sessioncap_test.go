package sessionrelay

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// bootstrapOnce posts one unauthenticated session bootstrap and returns the
// status code.
func bootstrapOnce(t *testing.T, url string) int {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(initRequest{SDKPub: base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())})
	resp, err := http.Post(url+initPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Bootstrap needs no credential, so the live session table must be capped:
// past the cap a bootstrap is refused, and once sessions expire new ones
// are admitted again.
func TestSessionBootstrapIsCapped(t *testing.T) {
	m := NewManager()
	m.maxSessions = 3
	clock := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return clock }

	srv := httptest.NewServer(m.Middleware(http.NotFoundHandler()))
	defer srv.Close()

	for i := 0; i < 3; i++ {
		if code := bootstrapOnce(t, srv.URL); code != http.StatusOK {
			t.Fatalf("bootstrap %d: status %d, want 200", i, code)
		}
	}
	if code := bootstrapOnce(t, srv.URL); code != http.StatusServiceUnavailable {
		t.Fatalf("bootstrap past the cap: status %d, want 503", code)
	}

	clock = clock.Add(defaultTTL + time.Minute)
	if code := bootstrapOnce(t, srv.URL); code != http.StatusOK {
		t.Fatalf("bootstrap after the sessions expired: status %d, want 200", code)
	}
	if n := len(m.sessions); n != 1 {
		t.Fatalf("%d sessions after the sweep, want 1", n)
	}
}

// The expired-session sweep runs at most every gcInterval while the table
// has room, not on every bootstrap.
func TestSessionSweepIsAmortised(t *testing.T) {
	m := NewManager()
	clock := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return clock }

	expired := &Session{ExpiresAt: clock.Add(-time.Second)}
	m.admit("first", &Session{ExpiresAt: clock.Add(time.Hour)}) // sweeps, sets lastGC
	m.sessions["stale"] = expired

	m.admit("second", &Session{ExpiresAt: clock.Add(time.Hour)})
	if _, ok := m.sessions["stale"]; !ok {
		t.Fatal("swept on a bootstrap inside gcInterval")
	}
	clock = clock.Add(gcInterval)
	m.admit("third", &Session{ExpiresAt: clock.Add(time.Hour)})
	if _, ok := m.sessions["stale"]; ok {
		t.Fatal("expired session not swept after gcInterval")
	}
}
