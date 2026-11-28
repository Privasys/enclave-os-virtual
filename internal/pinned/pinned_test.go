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

// The control plane is the one setting read from outside the measurement: a
// registered enclave given none calls the profile's, an unregistered one
// calls none, and a name the profile does not allow refuses the start.
func TestResolveMgmtURL(t *testing.T) {
	if got, err := prod(t).ResolveMgmtURL("", true); err != nil || got != "https://api.developer.privasys.org" {
		t.Fatalf("registered, none given: %q %v", got, err)
	}
	if got, err := prod(t).ResolveMgmtURL("", false); err != nil || got != "" {
		t.Fatalf("unregistered: %q %v", got, err)
	}
	if _, err := prod(t).ResolveMgmtURL("https://api-test.developer.privasys.org", true); err == nil || !strings.Contains(err.Error(), "mgmt-url") {
		t.Fatalf("a foreign control plane: %v", err)
	}
	dev, _ := For("dev")
	for _, name := range dev.MgmtURLs {
		if got, err := dev.ResolveMgmtURL(name, true); err != nil || got != name {
			t.Fatalf("dev %s: %q %v", name, got, err)
		}
	}
}

// The dev profile serves the test platform, never production's audience.
func TestDevServesTheTestPlatform(t *testing.T) {
	s, _ := For("dev")
	if s.Audience != "privasys-platform-test" || s.ManagerRole != "privasys-platform-test:manager" {
		t.Fatalf("%+v", s)
	}
	if s.WalletProviderJWKS() != "https://privasys.id/wallet-provider/jwks" {
		t.Fatalf("wallet provider %q", s.WalletProviderJWKS())
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
