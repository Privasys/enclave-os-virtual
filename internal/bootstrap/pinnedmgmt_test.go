package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withProfile points the bootstrap at an image-profile file holding profile,
// or at no file when profile is empty.
func withProfile(t *testing.T, profile string) {
	t.Helper()
	old := pinnedProfileFile
	t.Cleanup(func() { pinnedProfileFile = old })
	pinnedProfileFile = filepath.Join(t.TempDir(), "image-profile")
	if profile != "" {
		if err := os.WriteFile(pinnedProfileFile, []byte(profile+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Registration on a production image never follows a management URL from
// instance metadata that is not pinned.
func TestRegistrationUsesThePinnedControlPlane(t *testing.T) {
	withProfile(t, "")
	// No profile file: refused, never "unpinned".
	if _, err := pinnedMgmtURL("https://anything.example"); err == nil {
		t.Fatal("registration ran without an image profile")
	}
	withProfile(t, "production")
	for in, want := range map[string]string{
		"https://evil.example":               "https://api.developer.privasys.org",
		"":                                   "https://api.developer.privasys.org",
		"https://api.developer.privasys.org": "https://api.developer.privasys.org",
	} {
		if got, err := pinnedMgmtURL(in); err != nil || got != want {
			t.Fatalf("%q -> %q %v, want %q", in, got, err, want)
		}
	}
}

func locatorBlob(t *testing.T, mut func(*vaultLocator)) []byte {
	t.Helper()
	loc := locFixture()
	if mut != nil {
		mut(loc)
	}
	b, err := json.Marshal(loc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The LUKS2 header is host-writable: a control plane it names is replaced by
// the pinned one, never followed.
func TestHeaderLocatorUsesThePinnedControlPlane(t *testing.T) {
	withProfile(t, "production")
	loc, err := parseLocator(locatorBlob(t, func(l *vaultLocator) { l.MgmtURL = "https://evil.example" }))
	if err != nil {
		t.Fatal(err)
	}
	if loc.MgmtURL != "https://api.developer.privasys.org" {
		t.Fatalf("header control plane followed: %q", loc.MgmtURL)
	}
}

// An attestation server the image does not pin fails the boot: it would
// verify the quotes of whatever vaults the header names.
func TestHeaderLocatorWithAForeignAttestationServerIsRefused(t *testing.T) {
	withProfile(t, "production")
	for _, as := range []string{"https://evil.example/verify", ""} {
		_, err := parseLocator(locatorBlob(t, func(l *vaultLocator) { l.AttestationServer = as }))
		if err == nil || !strings.Contains(err.Error(), "not pinned") {
			t.Fatalf("attestation server %q: err = %v, want a refusal", as, err)
		}
	}
	if _, err := parseLocator(locatorBlob(t, nil)); err != nil {
		t.Fatalf("a pinned locator was refused: %v", err)
	}
}

// Without an image profile nothing is read from the header.
func TestHeaderLocatorNeedsAnImageProfile(t *testing.T) {
	withProfile(t, "")
	if _, err := parseLocator(locatorBlob(t, nil)); err == nil {
		t.Fatal("a locator was accepted with no image profile")
	}
}

// A rotation or renewal bundle that names an attestation server must name a
// pinned one; an empty one keeps the header's (already pinned).
func TestBundleAttestationServerIsPinned(t *testing.T) {
	withProfile(t, "production")
	b := bundleFixture()
	b.AttestationServer = "https://evil.example/verify"
	if err := b.validate(locFixture()); err == nil || !strings.Contains(err.Error(), "not pinned") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	b.AttestationServer = "https://as.privasys.org/verify"
	if err := b.validate(locFixture()); err != nil {
		t.Fatalf("a pinned attestation server was refused: %v", err)
	}
}
