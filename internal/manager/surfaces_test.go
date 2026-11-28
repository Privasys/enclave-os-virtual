package manager

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/edge"
	"github.com/Privasys/enclave-os-virtual/internal/surfaces"
)

const surfHost = "web.apps-test.privasys.org"

func surfServer(t *testing.T, manifest string) *Server {
	t.Helper()
	s := &Server{log: zap.NewNop(), publicLimiter: newPublicLimiter()}
	s.RegisterAppHost(surfHost, "127.0.0.1:1")
	surf, err := surfaces.Parse(manifest)
	if err != nil {
		t.Fatal(err)
	}
	s.SetSurfaces(surfHost, surf)
	return s
}

const webManifest = `{"surfaces":{
  "static":["/","/assets/"],
  "public":[
    {"method":"GET","path":"/api/v1/public/"},
    {"method":"POST","path":"/api/v1/webhooks/demo","headers":["X-Demo-Signature"]}
  ],
  "cors":"*"}}`

func clearReq(method, path string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, "https://"+surfHost+path, nil)
	r.Host = surfHost
	r.Header.Set(edge.Header, "terminate")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

// TestClearAllowed pins what the require-sealed predicate lets through in
// the clear: exactly the declared surfaces, a CORS preflight for a public
// path when the app opened CORS, and nothing else.
func TestClearAllowed(t *testing.T) {
	s := surfServer(t, webManifest)
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/", true},
		{"HEAD", "/assets/a.js", true},
		{"POST", "/", false},
		{"GET", "/api/v1/public/feed", true},
		{"POST", "/api/v1/public/feed", false},
		{"POST", "/api/v1/webhooks/demo", true},
		{"GET", "/api/v1/webhooks/demo", false},
		{"GET", "/api/v1/me", false},
		{"OPTIONS", "/api/v1/public/feed", true},
		{"OPTIONS", "/api/v1/me", false},
		{"OPTIONS", "/assets/a.js", false}, // static needs no preflight
	}
	for _, c := range cases {
		if got := s.clearAllowed(clearReq(c.method, c.path, nil)); got != c.want {
			t.Errorf("clearAllowed(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
	// Without CORS opened, a preflight is private like anything else.
	s2 := surfServer(t, strings.Replace(webManifest, `"cors":"*"`, `"cors":"same-origin"`, 1))
	if s2.clearAllowed(clearReq("OPTIONS", "/api/v1/public/feed", nil)) {
		t.Error("preflight must be refused when the app did not open CORS")
	}
	// Unknown host: nothing.
	r := clearReq("GET", "/", nil)
	r.Host = "other.apps-test.privasys.org"
	if s.clearAllowed(r) {
		t.Error("an undeclared host serves nothing in the clear")
	}
}

// TestServePublicAnonymous pins the clear-leg treatment: credentials and
// undeclared headers never reach the app, the declared one does, the client
// address is the last forwarded entry, and the app learns the leg.
func TestServePublicAnonymous(t *testing.T) {
	s := surfServer(t, webManifest)
	r := clearReq("POST", "/api/v1/webhooks/demo", map[string]string{
		"Authorization":    "Bearer leaked",
		"Cookie":           "session=abc",
		"X-Api-Key":        "invented",
		"X-Privasys-Sub":   "spoofed",
		"X-Demo-Signature": "sig",
		"Content-Type":     "application/json",
		"X-Forwarded-For":  "1.1.1.1, 203.0.113.9",
	})
	rec := httptest.NewRecorder()
	w, ok := s.servePublic(rec, r)
	if !ok || w == nil {
		t.Fatalf("declared route refused: %d %s", rec.Code, rec.Body.String())
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Api-Key", "X-Privasys-Sub"} {
		if r.Header.Get(h) != "" {
			t.Errorf("%s reached the app", h)
		}
	}
	if r.Header.Get("X-Demo-Signature") != "sig" || r.Header.Get("Content-Type") != "application/json" {
		t.Error("declared and allow-listed headers must survive")
	}
	if got := r.Header.Get("X-Forwarded-For"); got != "203.0.113.9" {
		t.Errorf("client = %q, want the last forwarded entry", got)
	}
	if r.Header.Get(TransportHeader) != TransportPublic {
		t.Error("the app must learn the request is on the clear leg")
	}
	if n := s.PublicCredentialsSeen()[surfHost]; n != 1 {
		t.Errorf("credentials seen = %d, want 1", n)
	}

	// Response: the app's headers are reduced to the allow-list, no cookie
	// can ever be planted, CORS is open on a public route, and the gateway
	// learns the response is public.
	w.Header().Set("Set-Cookie", "sid=1")
	w.Header().Set("X-User-Id", "u1")
	w.Header().Set("ETag", `"v1"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{}`))
	res := rec.Result()
	if res.StatusCode != http.StatusCreated {
		t.Errorf("status %d", res.StatusCode)
	}
	if res.Header.Get("Set-Cookie") != "" || res.Header.Get("X-User-Id") != "" {
		t.Error("Set-Cookie and app identity headers must be dropped")
	}
	if res.Header.Get("ETag") != `"v1"` || res.Header.Get("Content-Type") != "application/json" {
		t.Error("allow-listed response headers must survive")
	}
	if res.Header.Get("Access-Control-Allow-Origin") != "*" || res.Header.Get(TransportHeader) != TransportPublic {
		t.Errorf("public response markers missing: %v", res.Header)
	}
	if res.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("a public route never allows credentials")
	}
}

func TestServePublicStaticHasNoCORSAndSetsReferrerPolicy(t *testing.T) {
	s := surfServer(t, webManifest)
	rec := httptest.NewRecorder()
	w, ok := s.servePublic(rec, clearReq("GET", "/assets/app.js", nil))
	if !ok {
		t.Fatal("static refused")
	}
	w.WriteHeader(http.StatusOK)
	res := rec.Result()
	if res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("static assets carry no CORS")
	}
	if res.Header.Get("Referrer-Policy") != "same-origin" {
		t.Error("static responses set a same-origin referrer policy")
	}
}

func TestServePublicPreflight(t *testing.T) {
	s := surfServer(t, webManifest)
	rec := httptest.NewRecorder()
	if _, ok := s.servePublic(rec, clearReq("OPTIONS", "/api/v1/webhooks/demo", map[string]string{"Origin": "https://any.example"})); ok {
		t.Fatal("a preflight is answered by the runtime")
	}
	res := rec.Result()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", res.StatusCode)
	}
	if res.Header.Get("Access-Control-Allow-Origin") != "*" ||
		res.Header.Get("Access-Control-Allow-Methods") != "POST" ||
		!strings.Contains(res.Header.Get("Access-Control-Allow-Headers"), "X-Demo-Signature") ||
		res.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("preflight headers: %v", res.Header)
	}
}

func TestServePublicRefusesUpgrade(t *testing.T) {
	s := surfServer(t, webManifest)
	rec := httptest.NewRecorder()
	if _, ok := s.servePublic(rec, clearReq("GET", "/api/v1/public/events", map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"})); ok {
		t.Fatal("an upgrade on a public route must be refused")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status %d", rec.Code)
	}
}

func TestServePublicRateLimit(t *testing.T) {
	s := surfServer(t, strings.Replace(webManifest, `"cors":"*"`, `"cors":"*","limits":{"rps":1,"burst":3}`, 1))
	now := time.Unix(1_700_000_000, 0)
	s.publicLimiter.now = func() time.Time { return now }
	hdr := map[string]string{"X-Forwarded-For": "198.51.100.7"}
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		if _, ok := s.servePublic(rec, clearReq("GET", "/api/v1/public/feed", hdr)); !ok {
			t.Fatalf("request %d refused: %d", i, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	if _, ok := s.servePublic(rec, clearReq("GET", "/api/v1/public/feed", hdr)); ok || rec.Code != http.StatusTooManyRequests {
		t.Fatalf("burst exhausted: ok=%v status=%d", ok, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a 429 says when to retry")
	}
	// Another client has its own bucket.
	rec = httptest.NewRecorder()
	if _, ok := s.servePublic(rec, clearReq("GET", "/api/v1/public/feed", map[string]string{"X-Forwarded-For": "198.51.100.8"})); !ok {
		t.Error("buckets are per client")
	}
	// Tokens refill with time.
	now = now.Add(2 * time.Second)
	rec = httptest.NewRecorder()
	if _, ok := s.servePublic(rec, clearReq("GET", "/api/v1/public/feed", hdr)); !ok {
		t.Error("the bucket refills")
	}
}

// A clear request the predicate let through on its own exemptions (nothing
// declared) still gets the anonymous treatment rather than a refusal.
func TestServePublicWithoutDeclaration(t *testing.T) {
	s := &Server{log: zap.NewNop(), publicLimiter: newPublicLimiter()}
	s.RegisterAppHost(surfHost, "127.0.0.1:1")
	rec := httptest.NewRecorder()
	r := clearReq("GET", "/.well-known/openid-federation", map[string]string{"Authorization": "Bearer x"})
	w, ok := s.servePublic(rec, r)
	if !ok || r.Header.Get("Authorization") != "" || r.Header.Get(TransportHeader) != TransportPublic {
		t.Fatal("the exemption paths are anonymous too")
	}
	w.WriteHeader(http.StatusOK)
	if rec.Result().Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("no CORS without a declaration")
	}
}

func TestSetSurfacesClears(t *testing.T) {
	s := surfServer(t, webManifest)
	s.SetSurfaces(surfHost, nil)
	if s.clearAllowed(clearReq("GET", "/", nil)) {
		t.Error("cleared host serves nothing in the clear")
	}
	if s.SurfacesSummary(surfHost) != "none" {
		t.Error(s.SurfacesSummary(surfHost))
	}
}

// TestDirectLegFollowsTheClearRules pins the direct adopter leg: same surface
// rules as the gateway-terminated leg (a private path is not let through in
// the clear), but the app and the client learn it as "direct", never as
// attested and never as public.
func TestDirectLegFollowsTheClearRules(t *testing.T) {
	s := surfServer(t, webManifest)
	direct := func(method, path string) *http.Request {
		r := clearReq(method, path, nil)
		r.Header.Set(edge.Header, "direct")
		return r
	}
	if !isClearLeg(direct("GET", "/api/v1/me")) {
		t.Fatal("the direct leg must be a clear leg")
	}
	if s.clearAllowed(direct("GET", "/api/v1/me")) {
		t.Fatal("a private path must not be served in the clear on the direct leg")
	}
	if !s.clearAllowed(direct("GET", "/api/v1/public/feed")) {
		t.Fatal("a declared public route serves on the direct leg")
	}
	r := direct("GET", "/api/v1/public/feed")
	rec := httptest.NewRecorder()
	w, ok := s.servePublic(rec, r)
	if !ok {
		t.Fatalf("declared route refused: %d", rec.Code)
	}
	if got := r.Header.Get(TransportHeader); got != TransportDirect {
		t.Fatalf("transport to the app = %q, want %q", got, TransportDirect)
	}
	w.WriteHeader(http.StatusOK)
	if got := rec.Result().Header.Get(TransportHeader); got != TransportDirect {
		t.Fatalf("transport to the client = %q, want %q", got, TransportDirect)
	}
	if isClearLeg(httptest.NewRequest("GET", "https://"+surfHost+"/", nil)) {
		t.Fatal("no marker is the RA-TLS leg")
	}
}

// TestDirectPrivateOptIn pins phase 3: a direct private request is prepared
// by serveDirect (identity headers runtime-asserted, transport "direct"), a
// bearer that cannot be checked is refused, and the fee gate never takes the
// direct leg's subject as a payer.
func TestDirectPrivateOptIn(t *testing.T) {
	s := surfServer(t, strings.Replace(webManifest, `"cors":"*"`, `"cors":"*","direct":"private"`, 1))
	if !s.surfacesOf(surfHost).DirectPrivate() {
		t.Fatal("the manifest opted in")
	}
	if surfServer(t, webManifest).surfacesOf(surfHost).DirectPrivate() {
		t.Fatal("no opt-in by default")
	}

	// Anonymous: spoofed identity is stripped, the leg is stamped.
	r := clearReq("GET", "/api/v1/me", map[string]string{
		"X-Privasys-Sub": "spoofed", AttestationLevelHeader: "verified",
	})
	r.Header.Set(edge.Header, "direct")
	rec := httptest.NewRecorder()
	if _, ok := s.serveDirect(rec, r); !ok {
		t.Fatalf("anonymous direct request refused: %d", rec.Code)
	}
	if r.Header.Get("X-Privasys-Sub") != "" || r.Header.Get(AttestationLevelHeader) != "" {
		t.Fatal("client-asserted identity reached the app")
	}
	if r.Header.Get(TransportHeader) != TransportDirect {
		t.Fatal("the leg must be stamped direct")
	}

	// A bearer this runtime cannot check is refused, never passed through.
	r = clearReq("GET", "/api/v1/me", map[string]string{"Authorization": "Bearer x.y.z"})
	r.Header.Set(edge.Header, "direct")
	rec = httptest.NewRecorder()
	if _, ok := s.serveDirect(rec, r); ok || rec.Code != http.StatusUnauthorized {
		t.Fatalf("unverifiable bearer: ok, code %d; want refused with 401", rec.Code)
	}

	// The fee gate: on the direct leg a subject is never a payer.
	r = clearReq("GET", "/api/v1/me", map[string]string{"X-Privasys-Sub": "pairwise-1"})
	r.Header.Set(TransportHeader, TransportDirect)
	if got := s.callerIdentity(r); got != "" {
		t.Fatalf("payer on the direct leg = %q, want none (no wallet, no account: 402)", got)
	}
}

// Letter case and a trailing dot on the Host never open a second bucket or a
// second credential count, and forget clears what the host accumulated.
func TestServePublicHostSpellingsShareState(t *testing.T) {
	s := surfServer(t, strings.Replace(webManifest, `"cors":"*"`, `"cors":"*","limits":{"rps":1,"burst":2}`, 1))
	now := time.Unix(1_700_000_000, 0)
	s.publicLimiter.now = func() time.Time { return now }
	spellings := []string{surfHost, strings.ToUpper(surfHost), surfHost + "."}
	hdr := map[string]string{"X-Forwarded-For": "198.51.100.7", "Authorization": "Bearer x"}
	for i, h := range spellings {
		r := clearReq("GET", "/api/v1/public/feed", hdr)
		r.Host = h
		rec := httptest.NewRecorder()
		_, ok := s.servePublic(rec, r)
		if want := i < 2; ok != want {
			t.Fatalf("host %q: ok=%v want %v (status %d)", h, ok, want, rec.Code)
		}
	}
	seen := s.PublicCredentialsSeen()
	if len(seen) != 1 || seen[surfHost] != 2 {
		t.Fatalf("credentials seen = %v, want one entry for %q", seen, surfHost)
	}
	s.publicLimiter.forget(strings.ToUpper(surfHost) + ".")
	if len(s.PublicCredentialsSeen()) != 0 || len(s.publicLimiter.buckets) != 0 {
		t.Fatal("forget must clear every spelling of the host")
	}
}

func TestPublicLimiterBoundsAndIPv6Prefix(t *testing.T) {
	l := newPublicLimiter()
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }

	// Two addresses in one IPv6 /64 share a bucket; another /64 does not.
	if !l.allow("h", "2001:db8:1:2::1", 1, 1) {
		t.Fatal("first request refused")
	}
	if l.allow("h", "2001:db8:1:2:ffff::9", 1, 1) {
		t.Fatal("a second address in the same /64 must share the bucket")
	}
	if !l.allow("h", "2001:db8:1:3::1", 1, 1) {
		t.Fatal("another /64 has its own bucket")
	}

	// A full table refuses a new client but keeps serving known ones.
	for i := len(l.buckets); i < maxLimiterBuckets; i++ {
		l.buckets[fmt.Sprintf("fill|%d", i)] = &bucket{tokens: 1, last: now}
	}
	if l.allow("h", "198.51.100.1", 1, 5) {
		t.Fatal("a full table must refuse a new client")
	}
	if len(l.buckets) != maxLimiterBuckets {
		t.Fatalf("table grew past the cap: %d", len(l.buckets))
	}
	now = now.Add(2 * time.Second)
	if !l.allow("h", "2001:db8:1:3::2", 1, 1) {
		t.Fatal("a known client keeps its bucket when the table is full")
	}
	// Once idle buckets are swept, new clients are admitted again.
	now = now.Add(limiterIdle + limiterGCInterval)
	if !l.allow("h", "198.51.100.1", 1, 5) {
		t.Fatal("the sweep must free room")
	}
}

// On the direct private leg the bearer scheme is read in any letter case, and
// no Authorization value or runtime subprotocol reaches the app unverified.
func TestDirectPrivateNeverPassesAnUnverifiedCredential(t *testing.T) {
	s := surfServer(t, strings.Replace(webManifest, `"cors":"*"`, `"cors":"*","direct":"private"`, 1))
	direct := func(hdr map[string]string) (*http.Request, *httptest.ResponseRecorder, bool) {
		r := clearReq("GET", "/api/v1/me", hdr)
		r.Header.Set(edge.Header, "direct")
		rec := httptest.NewRecorder()
		out, ok := s.serveDirect(rec, r)
		return out, rec, ok
	}
	for _, authz := range []string{"bearer x.y.z", "BEARER x.y.z", "Bearer  x.y.z"} {
		if _, rec, ok := direct(map[string]string{"Authorization": authz}); ok || rec.Code != http.StatusUnauthorized {
			t.Errorf("%q: ok=%v code %d; want refused with 401", authz, ok, rec.Code)
		}
	}
	for _, authz := range []string{"Basic dXNlcjpwYXNz", "Token abc", "x.y.z"} {
		r, rec, ok := direct(map[string]string{"Authorization": authz})
		if !ok {
			t.Fatalf("%q: refused with %d; an unrecognised scheme is an anonymous request", authz, rec.Code)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("%q reached the app", authz)
		}
	}
	r, _, ok := direct(map[string]string{wsProtocolHeader: "chat, privasys.bearer.x.y.z"})
	if !ok {
		t.Fatal("a plain request with subprotocols was refused")
	}
	if got := r.Header.Get(wsProtocolHeader); got != "chat" {
		t.Errorf("subprotocols reaching the app = %q, want only chat", got)
	}
	_, rec, ok := direct(map[string]string{"Connection": "Upgrade", "Upgrade": "websocket", wsProtocolHeader: "Privasys.Bearer.x.y.z"})
	if ok || rec.Code != http.StatusUnauthorized {
		t.Errorf("a bearer subprotocol in another case: ok=%v code %d; want refused with 401", ok, rec.Code)
	}
}

func TestBearerToken(t *testing.T) {
	for in, want := range map[string]string{
		"Bearer abc": "abc", "bearer abc": "abc", " BEARER  abc ": "abc",
		"Basic abc": "", "Bearer": "", "": "", "Bearerabc": "",
	} {
		if got := bearerToken(in); got != want {
			t.Errorf("bearerToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// The clear-leg exemptions hold only for the exempt subtree itself: a dot
// segment, a ";parameter" or a longer segment name keeps a request sealed.
func TestRequiresSealedExemptionsAreSegmentAware(t *testing.T) {
	s := surfServer(t, webManifest)
	for _, p := range []string{
		"/.well-known/../api/secret", "/.well-known;x/../api/secret",
		holderCapabilitiesPath + "X", holderCapabilitiesPath + "/../../../api/secret",
		holderFilesPath + "/../../../../api/secret", capabilityRequestPath + "/../../../api/secret",
		"/.well-known/privasys/capability-other/../../../api/secret",
		"/assets/../api/secret", "/assetsX",
	} {
		if !s.requiresSealed(clearReq("GET", p, nil)) {
			t.Errorf("GET %s was let through in the clear", p)
		}
	}
	for _, p := range []string{
		"/.well-known/openid-configuration", capabilityRequestPath, capabilityResultPath,
		holderCapabilitiesPath, holderCapabilitiesPath + "/abc", holderFilesPath + "/x",
		"/assets/app.js", "/healthz",
	} {
		if s.requiresSealed(clearReq("GET", p, nil)) {
			t.Errorf("GET %s must stay reachable in the clear", p)
		}
	}
}
