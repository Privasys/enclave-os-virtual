package mgrname

import (
	"strings"
	"testing"
)

// The control plane's own vectors (management-service
// enclave_quarantine_test.go: TestManagerHostnameMatchesTheRouteFeed and
// TestManagerHostnameIsAlwaysADNSName), so both sides name the manager
// identically, the SGX-style names with spaces included.
func TestManagerHostnameMatchesTheControlPlane(t *testing.T) {
	if got := ManagerHostname("m6-dev", "apps.privasys.org"); got != "m6-dev-mgr.apps.privasys.org" {
		t.Fatalf("got %q", got)
	}
	if got := ManagerHostname("m6-dev", ""); got != "" {
		t.Fatalf("no app domain must give no manager hostname, got %q", got)
	}
	cases := []struct{ name, want string }{
		{"EU France 1", "eu-france-1-mgr.apps.privasys.org"},
		{"Europe UK 1", "europe-uk-1-mgr.apps.privasys.org"},
		{"  Europe / UK  (1) ", "europe-uk-1-mgr.apps.privasys.org"},
		{"Zürich_2", "z-rich-2-mgr.apps.privasys.org"},
		{"m6-dev", "m6-dev-mgr.apps.privasys.org"},
		{"DEV---eu-paris-1", "DEV---eu-paris-1-mgr.apps.privasys.org"},
		{"mut-dev-fra-8", "mut-dev-fra-8-mgr.apps.privasys.org"},
		{"m1-tdx-france", "m1-tdx-france-mgr.apps.privasys.org"},
		{"", ""},
		{"   ", ""},
		{"???", ""},
	}
	for _, c := range cases {
		got := ManagerHostname(c.name, "apps.privasys.org")
		if got != c.want {
			t.Errorf("ManagerHostname(%q) = %q, want %q", c.name, got, c.want)
		}
		if got == "" {
			continue
		}
		if label := strings.SplitN(got, ".", 2)[0]; !isDNSLabel(label) {
			t.Errorf("ManagerHostname(%q) = %q: %q is not a DNS label", c.name, got, label)
		}
	}
	long := strings.Repeat("Very Long Enclave Name ", 6)
	got := ManagerHostname(long, "apps.privasys.org")
	label := strings.SplitN(got, ".", 2)[0]
	if got == "" || !isDNSLabel(label) || !strings.HasSuffix(label, "-mgr") {
		t.Fatalf("a long name must still give a valid label ending in -mgr, got %q", got)
	}
	// The live names: m6-dev's manager is reached at this exact hostname.
	if got := ManagerHostname("m6-dev", "apps.test.privasys.org"); got != "m6-dev-mgr.apps.test.privasys.org" {
		t.Fatalf("m6-dev on the test fleet: %q", got)
	}
}
