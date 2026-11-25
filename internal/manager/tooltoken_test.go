package manager

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	toolAppID  = "11111111-2222-3333-4444-555555555555"
	toolAppHex = "11111111222233334444555555555555"
)

// A tool token (act.client_id, aud app:<this app>) pays as the person, and is
// withheld from the app; the app's own tokens never pay and still reach it.
func TestToolTokenPaysForItsAppOnly(t *testing.T) {
	s, iss := newIdentityServer(t)
	s.appIDOf = func(string) string { return toolAppID }
	act := map[string]any{"client_id": "privasys-wallet"}
	call := func(tok string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://svc.example/v1/capabilities", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}

	tool := iss.token(t, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt", "act": act})
	if got := s.callerIdentity(call(tool)); got != "p1" {
		t.Fatalf("tool token for this app: payer %q", got)
	}
	if sub, via := s.toolCaller(call(tool)); sub != "p1" || via != "privasys-wallet" {
		t.Fatalf("toolCaller = %q via %q", sub, via)
	}
	if !withholdToken(tool, "roles", toolAppID) {
		t.Fatal("a tool token reached the app")
	}
	// In X-App-Auth too.
	r := httptest.NewRequest(http.MethodPost, "http://svc.example/v1/capabilities", nil)
	r.Header.Set("X-App-Auth", tool)
	if got := s.callerIdentity(r); got != "p1" {
		t.Fatalf("tool token in X-App-Auth: payer %q", got)
	}

	for name, tok := range map[string]string{
		"another app's tool token": iss.token(t, "p1", "app:ffffffffffffffffffffffffffffffff", map[string]any{"typ": "at+jwt", "act": act}),
		"app's own client token":   iss.token(t, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt"}),
		"no typ":                   iss.token(t, "p1", "app:"+toolAppHex, map[string]any{"act": act}),
		"roles":                    iss.token(t, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt", "act": act, "roles": []string{"x"}}),
		"two audiences":            iss.token(t, "p1", "", map[string]any{"typ": "at+jwt", "act": act, "aud": []string{"app:" + toolAppHex, "privasys-platform"}}),
		"empty act":                iss.token(t, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt", "act": map[string]any{"client_id": ""}}),
	} {
		if got := s.callerIdentity(call(tok)); got != "" {
			t.Errorf("%s: payer %q, want none", name, got)
		}
	}
	// The app's own token passes through to the app, as before.
	own := iss.token(t, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt"})
	if withholdToken(own, "roles", toolAppID) {
		t.Fatal("the app's own token was withheld")
	}
	// A forged signature never pays.
	if got := s.callerIdentity(call(tool[:len(tool)-4] + "AAAA")); got != "" {
		t.Fatalf("forged tool token paid as %q", got)
	}
}
