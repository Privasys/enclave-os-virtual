package pinned

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prod(t *testing.T) Settings {
	t.Helper()
	s, ok := For("production")
	if !ok {
		t.Fatal("no production profile")
	}
	return s
}

// An image needs nothing from manager.env: empty settings take the pinned
// production values.
func TestEmptySettingsTakeThePinnedValues(t *testing.T) {
	g, err := prod(t).Resolve(Given{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if g.Issuer != "https://privasys.id" || g.Audience != "privasys-platform" ||
		g.ManagerRole != "privasys-platform:manager" || g.MonitoringRole != "privasys-platform:monitoring" ||
		len(g.AttestationServers) != 1 || g.AttestationServers[0] != "https://as.privasys.org/verify" ||
		g.MgmtURL != "https://api.developer.privasys.org" {
		t.Fatalf("resolved %+v", g)
	}
	// Unregistered: no control plane is invented.
	if g, _ := prod(t).Resolve(Given{}, false); g.MgmtURL != "" {
		t.Fatalf("unregistered mgmt url %q", g.MgmtURL)
	}
}

// Any setting from outside the measurement that the profile does not allow
// refuses the start, and the error names it.
func TestAForeignSettingIsRefused(t *testing.T) {
	for name, g := range map[string]Given{
		"oidc-issuer":          {Issuer: "https://evil.example"},
		"oidc-audience":        {Audience: "privasys-platform-test"},
		"oidc-manager-role":    {ManagerRole: "privasys-platform:admin"},
		"oidc-monitoring-role": {MonitoringRole: "x"},
		"attestation-server":   {AttestationServers: []string{"https://as.privasys.org/verify", "https://evil.example/verify"}},
		"mgmt-url":             {MgmtURL: "https://api-test.developer.privasys.org"},
		"wallet-provider-jwks": {WalletProviderJWKS: "https://evil.example/jwks"},
	} {
		_, err := prod(t).Resolve(g, true)
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	// The issuer's own JWKS is accepted.
	if _, err := prod(t).Resolve(Given{WalletProviderJWKS: "https://privasys.id/wallet-provider/jwks"}, true); err != nil {
		t.Fatal(err)
	}
}

// The dev profile serves the test platform, never production's audience.
func TestDevServesTheTestPlatform(t *testing.T) {
	s, _ := For("dev")
	g, err := s.Resolve(Given{MgmtURL: "https://api.developer.test.privasys.org"}, true)
	if err != nil || g.Audience != "privasys-platform-test" || g.ManagerRole != "privasys-platform-test:manager" {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := s.Resolve(Given{Audience: "privasys-platform"}, true); err == nil {
		t.Fatal("dev accepted the production audience")
	}
}

func TestProfileFile(t *testing.T) {
	dir := t.TempDir()
	// Every image writes the file: a missing one never means "unpinned".
	if _, err := Profile(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a missing profile was accepted")
	}
	f := filepath.Join(dir, "image-profile")
	_ = os.WriteFile(f, []byte("production\n"), 0o644)
	if p, err := Profile(f); p != "production" || err != nil {
		t.Fatalf("production: %q %v", p, err)
	}
	_ = os.WriteFile(f, []byte("custom\n"), 0o644)
	if _, err := Profile(f); err == nil {
		t.Fatal("an unknown profile was accepted")
	}
}

func TestMgmtURLForRegistration(t *testing.T) {
	s := prod(t)
	if got := s.MgmtURL("https://evil.example"); got != "https://api.developer.privasys.org" {
		t.Fatalf("foreign candidate kept: %s", got)
	}
	if got := s.MgmtURL(""); got != "https://api.developer.privasys.org" {
		t.Fatalf("empty: %s", got)
	}
}

func TestCurrentAndAttestationServerCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image-profile")
	if _, _, err := Current(path); err == nil {
		t.Fatal("Current read settings with no profile file")
	}
	if err := os.WriteFile(path, []byte("dev\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, s, err := Current(path)
	if err != nil || p != "dev" || s.AppDomain != "apps.test.privasys.org" {
		t.Fatalf("Current: %q %+v %v", p, s, err)
	}
	if err := s.CheckAttestationServer("https://as.privasys.org/verify"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "https://as.privasys.org/verify/", "https://evil.example/verify"} {
		if s.CheckAttestationServer(v) == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}
