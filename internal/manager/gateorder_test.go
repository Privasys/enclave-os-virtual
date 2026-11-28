//go:build testhooks

package manager

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/apifees"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// TestTheAppHostGatesRunInOrder pins the order of the gates an app request
// goes through, through the whole handler: each case fails or passes several
// gates at once and must get the answer of the first. The order is the
// tool-subject assertion, then the billing freeze, the guarded route, the
// configure gate and its freeze, and the fee gate last.
func TestTheAppHostGatesRunInOrder(t *testing.T) {
	ids, iss := newIdentityServer(t)
	log := zap.NewNop()
	l := launcher.New(launcher.Config{}, log)
	s := New(Config{}, log, l, ids.verifier)

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "app sub="+r.Header.Get("X-Privasys-Sub")+" via="+r.Header.Get(SubViaHeader))
	}))
	t.Cleanup(app.Close)
	upstream := strings.TrimPrefix(app.URL, "http://")

	const host, pausedHost = "gate.apps.test", "paused.apps.test"
	st := launcher.FreezeState{
		AppID:     toolAppHex,
		ConfigAPI: &launcher.ConfigAPISpec{Method: http.MethodPost, Path: "/configure"},
		RouteAuth: []apifees.RouteAuth{
			{Tool: "owner", Path: "/v1/owner", Policy: apifees.PolicyOwner},
			{Tool: "me", Path: "/v1/me", Policy: apifees.PolicyAuthenticated},
			// Never applied: the configure gate guards the configure path.
			{Tool: "configure", Path: "/configure", Policy: apifees.PolicyRole, Roles: []string{"nobody"}},
		},
	}
	prices := apifees.Table{"/v1/priced": {Tool: "priced", Rule: apifees.PriceRule{Credits: 1}}}
	launcher.RegisterAppForTest(l, "gate", host, st, prices)
	paused := st
	paused.BillingFrozen, paused.BillingReason = true, "credits exhausted"
	launcher.RegisterAppForTest(l, "paused", pausedHost, paused, prices)
	s.RegisterAppHost(host, upstream)
	s.RegisterAppHost(pausedHost, upstream)
	h := s.handler()

	owner := iss.token(t, "p1", "enclave-os-virtual", map[string]any{"roles": []string{"enclave-os-virtual:app:" + toolAppHex + ":owner"}})
	tool := iss.token(t, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt", "act": map[string]any{"client_id": "privasys-wallet"}})
	call := func(method, h0, path, tok string) (int, string) {
		t.Helper()
		r := httptest.NewRequest(method, "https://"+h0+path, nil)
		r.Host = h0
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}

	for _, c := range []struct {
		name, method, host, path, tok string
		code                          int
		body                          string
	}{
		{"a paused app answers before its route gate", "GET", pausedHost, "/v1/owner", "", 503, "app paused"},
		{"the route gate answers before the configure freeze", "GET", host, "/v1/owner", "", 403, "route /v1/owner requires"},
		{"past the route gate, the configure freeze holds", "GET", host, "/v1/owner", owner, 503, "awaiting initial configuration"},
		{"the configure freeze answers before the fee gate", "GET", host, "/v1/priced", "", 503, "awaiting initial configuration"},
		{"the configure gate guards its path, not the route gate", "POST", host, "/configure", "", 403, "configure requires"},
		{"the owner configures", "POST", host, "/configure", owner, 200, "app sub="},
		{"configured: the fee gate answers last", "GET", host, "/v1/priced", "", 402, "payment required"},
		{"a tool token names the caller before the route gate", "GET", host, "/v1/me", tool, 200, "app sub=p1 via=privasys-wallet"},
		{"an unguarded route reaches the app", "GET", host, "/v1/plain", "", 200, "app sub="},
	} {
		code, body := call(c.method, c.host, c.path, c.tok)
		if code != c.code || !strings.Contains(body, c.body) {
			t.Fatalf("%s: %d %q, want %d with %q", c.name, code, body, c.code, c.body)
		}
	}
}
