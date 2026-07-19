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

// TestEnforceMutualHostWithoutCertRejects proves a mutual-auth host fails closed
// when no client certificate was presented.
func TestEnforceMutualHostWithoutCertRejects(t *testing.T) {
	v := newTestVerifier()
	v.setPolicy("app.example", &ratls.DependencySet{
		Entries: []ratls.DependencyEntry{{AppID: "deadbeef"}},
	})

	r, _ := http.NewRequest("GET", "http://app.example/", nil)
	r.Host = "app.example"
	// No X-Privasys-Peer-Cert-Der header: Caddy would have set it after the TLS
	// handshake required a client cert; its absence must be rejected.

	if err := v.enforce(r); err == nil {
		t.Fatal("mutual host with no client cert should be rejected")
	}
}

// TestSetPolicyStoreAndRemove proves policy registration and removal, and that
// an empty entry set is treated as "no policy".
func TestSetPolicyStoreAndRemove(t *testing.T) {
	v := newTestVerifier()
	if _, ok := v.policyFor("app.example"); ok {
		t.Fatal("no policy expected initially")
	}
	v.setPolicy("App.Example", &ratls.DependencySet{Entries: []ratls.DependencyEntry{{AppID: "x"}}})
	if _, ok := v.policyFor("app.example"); !ok {
		t.Fatal("policy should be found case-insensitively")
	}
	v.setPolicy("app.example", nil)
	if _, ok := v.policyFor("app.example"); ok {
		t.Fatal("nil policy should remove the entry")
	}
	v.setPolicy("app.example", &ratls.DependencySet{}) // empty entries
	if _, ok := v.policyFor("app.example"); ok {
		t.Fatal("empty-entry policy should be treated as no policy")
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
