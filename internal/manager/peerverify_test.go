package manager

import (
	"net/http"
	"testing"

	ratls "enclave-os-mini/clients/go/ratls"

	"go.uber.org/zap"
)

func newTestVerifier() *ingressVerifier {
	return newIngressVerifier(zap.NewNop(), func() (string, string) { return "", "" }, false)
}

// TestStripPeerHeadersRemovesNamespace proves every X-Privasys-Peer-* header is
// removed while unrelated headers survive — the anti-spoof invariant.
func TestStripPeerHeadersRemovesNamespace(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://app/", nil)
	r.Header.Set("X-Privasys-Peer-Verified", "true")
	r.Header.Set("X-Privasys-Peer-App-Id", "deadbeef")
	r.Header.Set("X-Privasys-Peer-Cert-Der", "spoofed")
	r.Header.Set("Authorization", "Bearer keep-me")
	r.Header.Set("Content-Type", "application/json")

	stripPeerHeaders(r)

	for h := range r.Header {
		if len(h) >= len(peerHeaderPrefix) && http.CanonicalHeaderKey(h)[:len(peerHeaderPrefix)] == peerHeaderPrefix {
			t.Fatalf("peer header survived stripping: %s", h)
		}
	}
	if r.Header.Get("Authorization") != "Bearer keep-me" {
		t.Fatal("Authorization header was wrongly stripped")
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Fatal("Content-Type header was wrongly stripped")
	}
}

// TestEnforceNonMutualHostStripsAndPasses proves that for a host with no
// allowed-caller policy (server-auth only), enforce scrubs any spoofed peer
// headers and permits the request. A caller cannot forge an attested identity.
func TestEnforceNonMutualHostStripsAndPasses(t *testing.T) {
	v := newTestVerifier()
	r, _ := http.NewRequest("GET", "http://not-mutual.example/", nil)
	r.Host = "not-mutual.example"
	r.Header.Set("X-Privasys-Peer-Verified", "true") // forged by the caller

	if err := v.enforce(r); err != nil {
		t.Fatalf("non-mutual host should pass, got %v", err)
	}
	if got := r.Header.Get("X-Privasys-Peer-Verified"); got != "" {
		t.Fatalf("forged peer header survived on non-mutual host: %q", got)
	}
}

// TestEnforceMutualHostWithoutCertPassesAnonymously proves the manager-side
// half of the ALPN split: on a mutual-auth host, a request carrying NO client
// certificate is an anonymous caller (a gateway-terminated browser, which
// cannot produce a TEE-bound cert), not a failed one. It proceeds with the peer
// namespace scrubbed, so the app's own authentication decides and anything
// gated on an attested caller still fails closed.
//
// This is a regression guard: rejecting here would make every mutual-auth app
// unreachable from the web the moment allowed_callers is set — which is exactly
// what would break chat's sealed sessions to confidential-ai.
func TestEnforceMutualHostWithoutCertPassesAnonymously(t *testing.T) {
	v := newTestVerifier()
	v.setPolicy("app.example", &ratls.DependencySet{
		Entries: []ratls.DependencyEntry{{AppID: "deadbeef"}},
	}, nil)

	r, _ := http.NewRequest("GET", "http://app.example/", nil)
	r.Host = "app.example"
	// No X-Privasys-Peer-Cert-Der, and a forged verdict the caller supplied.
	r.Header.Set("X-Privasys-Peer-Verified", "true")
	r.Header.Set("X-Privasys-Peer-App-Id", "cafebabe")

	if err := v.enforce(r); err != nil {
		t.Fatalf("certless request on a mutual host must pass anonymously, got %v", err)
	}
	if got := r.Header.Get("X-Privasys-Peer-Verified"); got != "" {
		t.Fatalf("forged peer verdict survived: %q", got)
	}
	if got := r.Header.Get("X-Privasys-Peer-App-Id"); got != "" {
		t.Fatalf("forged peer app-id survived: %q", got)
	}
}

// TestEnforceMutualHostWithBadCertRejects proves the other side of that rule:
// presenting a certificate that fails verification is an attack, not an
// anonymous call, and must be rejected rather than downgraded.
func TestEnforceMutualHostWithBadCertRejects(t *testing.T) {
	v := newTestVerifier()
	v.setPolicy("app.example", &ratls.DependencySet{
		Entries: []ratls.DependencyEntry{{AppID: "deadbeef"}},
	}, nil)

	r, _ := http.NewRequest("GET", "http://app.example/", nil)
	r.Host = "app.example"
	r.Header.Set("X-Privasys-Peer-Cert-Der", "not-base64-DER!!")
	r.Header.Set("X-Privasys-Peer-Channel-Binder", "AAAA")

	if err := v.enforce(r); err == nil {
		t.Fatal("an undecodable client certificate must be rejected, not downgraded to anonymous")
	}
}

// TestSetPolicyStoreAndRemove proves policy registration and removal, and that
// an empty entry set is treated as "no policy".
func TestSetPolicyStoreAndRemove(t *testing.T) {
	v := newTestVerifier()
	if _, ok := v.policyFor("app.example"); ok {
		t.Fatal("no policy expected initially")
	}
	v.setPolicy("App.Example", &ratls.DependencySet{Entries: []ratls.DependencyEntry{{AppID: "x"}}}, nil)
	if _, ok := v.policyFor("app.example"); !ok {
		t.Fatal("policy should be found case-insensitively")
	}
	v.setPolicy("app.example", nil, nil)
	if _, ok := v.policyFor("app.example"); ok {
		t.Fatal("nil policy should remove the entry")
	}
	v.setPolicy("app.example", &ratls.DependencySet{}, nil) // empty entries
	if _, ok := v.policyFor("app.example"); ok {
		t.Fatal("empty-entry policy should be treated as no policy")
	}
}

// The wildcard is honoured only with a platform allow-list: without one it
// is dropped and the pinned entries stay; alone, it leaves no policy at all.
func TestSetPolicyWildcardNeedsPlatforms(t *testing.T) {
	v := newTestVerifier()
	wild := ratls.DependencyEntry{AppID: anyCallerAppID}
	pinned := ratls.DependencyEntry{AppID: "x"}

	v.setPolicy("a.example", &ratls.DependencySet{Entries: []ratls.DependencyEntry{wild, pinned}}, nil)
	p, ok := v.policyFor("a.example")
	if !ok || p.admitsAnyCaller() || len(p.set.Entries) != 1 || p.set.Entries[0].AppID != "x" {
		t.Fatalf("wildcard without platforms must be dropped, pinned entry kept: %+v", p)
	}

	v.setPolicy("b.example", &ratls.DependencySet{Entries: []ratls.DependencyEntry{wild}}, nil)
	if _, ok := v.policyFor("b.example"); ok {
		t.Fatal("a lone wildcard without platforms must leave no policy")
	}

	v.setPolicy("c.example", &ratls.DependencySet{Entries: []ratls.DependencyEntry{wild}}, []string{"d4602590b11c770aa7b9ee404649e802"})
	p, ok = v.policyFor("c.example")
	if !ok || !p.admitsAnyCaller() || len(p.platforms) != 1 {
		t.Fatalf("wildcard with platforms must be installed: %+v", p)
	}
}

func TestAppIDMatches(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	if !appIDMatches("deadbeef", raw) {
		t.Fatal("lowercase hex app-id should match")
	}
	if !appIDMatches("DEADBEEF", raw) {
		t.Fatal("app-id match should be case-insensitive")
	}
	if appIDMatches("deadbe", raw) {
		t.Fatal("different app-id must not match")
	}
	if appIDMatches("deadbeef", nil) {
		t.Fatal("empty caller app-id must not match")
	}
}
