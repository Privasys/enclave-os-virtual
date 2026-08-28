package manager

import "testing"

// TestIsStaticUnsealedPath pins the opt-in static-UI exemption: it must serve
// exactly the declared public prefixes and NEVER the data plane. A regression
// here would either break enclave-served UI reachability or, far worse, expose
// user data to the TLS-terminating gateway.
func TestIsStaticUnsealedPath(t *testing.T) {
	const host = "attested-harness.apps-test.privasys.org"
	s := &Server{}
	s.SetStaticUnsealedPrefixes(host, []string{
		"/", "/assets/", "/privasys/", "/plugins/", "/favicon.svg", "/manifest.webmanifest",
	})

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"root document", "/", true},
		{"hashed bundle", "/assets/index-abc123.js", true},
		{"shell script", "/privasys/privasys-shell.js", true},
		{"sdk iife", "/privasys/privasys-auth-client.iife.js", true},
		{"plugin bundle", "/plugins/some-id/client.js", true},
		{"favicon exact", "/favicon.svg", true},
		{"manifest exact", "/manifest.webmanifest", true},

		// The data plane is never exempt.
		{"api unary", "/api/session.list", false},
		{"api events", "/api/events.mux", false},
		{"api bare", "/api", false},

		// Root is exact-match only — it must not blanket every path.
		{"non-root undeclared", "/secret", false},
		{"attestation stays sealed unless declared prefix", "/privasys/attestation", true},
	}
	for _, c := range cases {
		if got := s.isStaticUnsealedPath(host, c.path); got != c.want {
			t.Errorf("%s: isStaticUnsealedPath(%q) = %v, want %v", c.name, c.path, got, c.want)
		}
	}

	// Unknown host: nothing is exempt.
	if s.isStaticUnsealedPath("other.apps.privasys.org", "/assets/x.js") {
		t.Error("undeclared host must not expose any path")
	}

	// A dangerously broad "/" declaration must still never expose /api.
	s.SetStaticUnsealedPrefixes(host, []string{"/"})
	if s.isStaticUnsealedPath(host, "/api/session.list") {
		t.Error("/api must stay sealed even when the app declares '/'")
	}
	if !s.isStaticUnsealedPath(host, "/") {
		t.Error("'/' must still match the root document")
	}
	if s.isStaticUnsealedPath(host, "/anything") {
		t.Error("'/' must be exact-match only, not a catch-all prefix")
	}

	// Clearing removes the exemption.
	s.SetStaticUnsealedPrefixes(host, nil)
	if s.isStaticUnsealedPath(host, "/") {
		t.Error("cleared host must not expose any path")
	}
}
