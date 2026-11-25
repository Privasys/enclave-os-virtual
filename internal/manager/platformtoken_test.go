package manager

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
)

// jwt builds an unsigned token with the given claims: the strip reads tokens
// unverified, so no signature is needed to exercise it.
func jwt(t *testing.T, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","kid":"k"}`)) + "." + enc(b) + ".c2ln"
}

const (
	firstPartyApp = "02104572-ca2f-41e8-ae2d-24c0294e6f5e" // drive-demo (dev), allowlisted
	thirdPartyApp = "11111111-2222-3333-4444-555555555555"
)

func staffToken(t *testing.T) string {
	return jwt(t, map[string]any{"aud": "privasys-platform", "sub": "s",
		"roles": []any{"privasys-platform:admin", "privasys-platform:app:abc:owner"}})
}

func userToken(t *testing.T) string {
	return jwt(t, map[string]any{"aud": []any{"privasys-platform-test"}, "sub": "u",
		"roles": []any{"privasys-platform-test:app:abc:owner"}})
}

func appToken(t *testing.T) string {
	return jwt(t, map[string]any{"aud": "app:0210457" + "2ca2f41e8ae2d24c0294e6f5e", "sub": "u"})
}

func TestWithholdToken(t *testing.T) {
	for _, tc := range []struct {
		name, tok, app string
		withhold       bool
	}{
		{"staff to third party", staffToken(t), thirdPartyApp, true},
		{"staff to first party", staffToken(t), firstPartyApp, true},
		{"user to third party", userToken(t), thirdPartyApp, true},
		{"user to first party", userToken(t), firstPartyApp, false},
		{"user to unknown app", userToken(t), "", true},
		{"app token", appToken(t), thirdPartyApp, false},
		{"opaque", "not-a-jwt", thirdPartyApp, false},
		// Exact role names only: a look-alike is not a staff role.
		{"look-alike role", jwt(t, map[string]any{"aud": "privasys-platform",
			"roles": []any{"privasys-platform:administrator", "x-privasys-platform:admin"}}), firstPartyApp, false},
		{"role in map claim", jwt(t, map[string]any{"aud": "privasys-platform",
			"roles": []any{}, "realm_access": map[string]any{"roles": []any{"privasys-platform:monitoring"}}}), firstPartyApp, true},
		{"platform among several audiences", jwt(t, map[string]any{"aud": []any{"app:x", "privasys-platform"}}), thirdPartyApp, true},
		{"app id not normalised", userToken(t), strings.ToUpper(strings.ReplaceAll(firstPartyApp, "-", "")), false},
	} {
		if got := withholdToken(tc.tok, "roles", tc.app); got != tc.withhold {
			t.Errorf("%s: withhold = %v, want %v", tc.name, got, tc.withhold)
		}
	}
}

// Every leg reaches a container through the app proxy's Rewrite: what it
// strips never arrives, whatever the leg.
func TestPlatformTokensNeverReachTheContainer(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer upstream.Close()

	apps := map[string]string{"third.example": thirdPartyApp, "first.example": firstPartyApp}
	s := &Server{appIDOf: func(h string) string { return apps[h] }}
	for h := range apps {
		s.appHosts.Store(h, strings.TrimPrefix(upstream.URL, "http://"))
	}
	proxy := &httputil.ReverseProxy{Rewrite: s.rewriteAppRequest}

	legs := map[string]func(*http.Request){
		"sealed":  func(r *http.Request) { r.Header.Set(TransportHeader, TransportSealed) },
		"gateway": func(r *http.Request) { r.Header.Set(TransportHeader, TransportAttested) },
		"direct":  func(r *http.Request) { r.Header.Set(TransportHeader, TransportDirect) },
	}
	send := func(leg, host string, set func(h http.Header)) http.Header {
		got = nil
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/x", nil)
		set(r.Header)
		legs[leg](r)
		proxy.ServeHTTP(httptest.NewRecorder(), r)
		if got == nil {
			t.Fatalf("%s %s: request did not reach the app", leg, host)
		}
		return got
	}
	carry := func(tok string) func(http.Header) {
		return func(h http.Header) {
			h.Set("Authorization", "Bearer "+tok)
			h.Set("X-App-Auth", tok)
			h.Set(wsProtocolHeader, wsProtocol+", "+wsBearerPrefix+tok+", chat")
		}
	}
	reached := func(h http.Header, tok string) (auth, xapp, ws bool) {
		return strings.Contains(h.Get("Authorization"), tok), h.Get("X-App-Auth") == tok,
			strings.Contains(h.Get(wsProtocolHeader), tok)
	}

	for leg := range legs {
		for _, host := range []string{"third.example", "first.example"} {
			h := send(leg, host, carry(staffToken(t)))
			if a, x, w := reached(h, staffToken(t)); a || x || w {
				t.Errorf("%s %s: a staff token reached the app (auth %v, x-app-auth %v, ws %v)", leg, host, a, x, w)
			}
			if !strings.Contains(h.Get(wsProtocolHeader), "chat") {
				t.Errorf("%s %s: the other subprotocols were dropped too: %q", leg, host, h.Get(wsProtocolHeader))
			}

			h = send(leg, host, carry(userToken(t)))
			a, x, w := reached(h, userToken(t))
			want := host == "first.example"
			if a != want || x != want || w != want {
				t.Errorf("%s %s: user token reached (auth %v, x-app-auth %v, ws %v), want %v", leg, host, a, x, w, want)
			}

			h = send(leg, host, carry(appToken(t)))
			if a, x, w := reached(h, appToken(t)); !a || !x || !w {
				t.Errorf("%s %s: the app's own token was withheld (auth %v, x-app-auth %v, ws %v)", leg, host, a, x, w)
			}
		}
	}
}
