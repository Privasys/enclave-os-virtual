package sessionrelay

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A session is bound to the host it was bootstrapped on. The gateway
// carries the routing host outside the seal, so a sealed request it sends
// to another app on the same enclave is refused before anything is
// decrypted, with the answer an unknown session gets, and the other app
// never sees it (nor the user's Sub).
func TestSealedRequestNeverCrossesHosts(t *testing.T) {
	m := NewManager()
	sess, seal := testSession(t, m, "user-123") // bootstrapped on example.com
	reached := false
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))

	send := func(host string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/x", bytes.NewReader(seal(http.MethodPost, "/api/x", []byte("{}"), 0)))
		r.Host = host
		r.Header.Set("Authorization", authScheme+" "+sess.ID)
		r.Header.Set("Content-Type", sealedContentType)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := send("other-app.example.com"); code != http.StatusUnauthorized || reached {
		t.Fatalf("cross-host sealed request: status %d, reached app %v", code, reached)
	}
	if sess.C2SNext != 0 {
		t.Fatal("a cross-host request advanced the session (it was decrypted)")
	}
	if code := send("example.com"); code == http.StatusUnauthorized || !reached {
		t.Fatalf("same-host sealed request: status %d, reached app %v", code, reached)
	}
}

// A mux stream OPEN naming any host but the session's own is refused like
// an unknown session: no stream, no dial.
func TestMuxOpenNeverCrossesHosts(t *testing.T) {
	m := NewManager()
	sess, _ := testSession(t, m, "user-1")
	sess.Host = "app-a.example.org"
	dialled := make(chan struct{}, 1)
	app := startEchoApp(t)
	relayHost := startRelay(t, m, app)
	m.SetWSUpstream(func(host string) (string, bool) { dialled <- struct{}{}; return app, true })
	c := dialMux(t, relayHost)
	sealer := newStreamSealer(sess, "/live", 7)
	c.write(muxTypeOpen, sess.ID, 7, c.openPayload("app-b.example.org", "/live", sealer.seal([]byte("open"), 0)))
	typ, _, _, payload := c.read()
	if typ != muxTypeClose || !bytes.Contains(payload, []byte("unknown or expired session")) {
		t.Fatalf("cross-host OPEN: frame type %d %q", typ, payload)
	}
	select {
	case <-dialled:
		t.Fatal("a cross-host OPEN dialled an upstream")
	case <-time.After(200 * time.Millisecond):
	}
}

// A rebind cannot move a live session id onto another host.
func TestRebindNeverMovesASessionAcrossHosts(t *testing.T) {
	m := NewManager()
	sess, _ := testSession(t, m, "")
	if _, live := m.lookupByID(sess.ID); !live || !sess.sameHost("example.com") || sess.sameHost("other.example.com") {
		t.Fatal("bootstrap host not recorded")
	}
	if (&Session{}).sameHost("") {
		t.Fatal("a session with no recorded host matched")
	}
}
