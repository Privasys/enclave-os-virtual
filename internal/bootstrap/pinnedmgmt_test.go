package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
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

// withHeader makes device a LUKS volume whose header holds blob as its
// locator token, or no token at all when blob is nil.
func withHeader(t *testing.T, blob []byte) {
	t.Helper()
	oldLuks, oldExport := isLuks, exportToken
	t.Cleanup(func() { isLuks, exportToken = oldLuks, oldExport })
	isLuks = func(context.Context, string) bool { return true }
	exportToken = func(_ context.Context, _, id string) ([]byte, error) {
		if blob == nil || id != luksTokenID {
			return nil, errors.New("token not found")
		}
		return blob, nil
	}
}

// A locator that is there but refused fails the boot. It must never read as
// "no locator", which falls back to a passphrase from instance metadata.
func TestARefusedLocatorFailsTheBootInsteadOfFallingBack(t *testing.T) {
	withProfile(t, "production")
	t.Setenv("BOOTSTRAP_TOKEN", "unused")
	for name, blob := range map[string][]byte{
		"unpinned attestation server": locatorBlob(t, func(l *vaultLocator) { l.AttestationServer = "https://evil.example/verify" }),
		"incomplete":                  locatorBlob(t, func(l *vaultLocator) { l.Handle = "" }),
		"unreadable":                  []byte("{"),
	} {
		withHeader(t, blob)
		_, err := ResolveDataDEK(context.Background(), zap.NewNop(), Config{}, "/dev/fake")
		if err == nil || errors.Is(err, ErrNotVaultManaged) {
			t.Fatalf("%s: err = %v, want a boot failure", name, err)
		}
	}
	// No token at all is a BYOK volume.
	withHeader(t, nil)
	if _, err := ResolveDataDEK(context.Background(), zap.NewNop(), Config{}, "/dev/fake"); !errors.Is(err, ErrNotVaultManaged) {
		t.Fatalf("no token: err = %v, want ErrNotVaultManaged", err)
	}
}

// A renewal bundle naming an unpinned attestation server is refused before
// any vault is contacted.
func TestRenewBundleAttestationServerIsPinned(t *testing.T) {
	withProfile(t, "production")
	withHeader(t, locatorBlob(t, nil))
	b := bundleFixture()
	b.Handle = "apps.privasys.org/1efff2acfa6745bd9fd10c9ecbbcb9a4/manager/data/v2"
	b.AttestationServer = "https://evil.example/verify"
	_, _, err := RenewDataDEK(context.Background(), zap.NewNop(), Config{}, "/dev/fake", b)
	if err == nil || !strings.Contains(err.Error(), "not pinned") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

// A bundle naming no attestation server uses the header's, pinned on read.
func TestBundleWithoutAttestationServerKeepsTheHeaders(t *testing.T) {
	b := bundleFixture()
	if got := b.attestationServer(locFixture()); got != "https://as.privasys.org/verify" {
		t.Fatalf("got %q", got)
	}
}

// On a dev image the header may name either pinned control plane; it is kept.
func TestDevHeaderKeepsEitherPinnedControlPlane(t *testing.T) {
	withProfile(t, "dev")
	for _, u := range []string{"https://api-test.developer.privasys.org", "https://api.developer.test.privasys.org"} {
		loc, err := parseLocator(locatorBlob(t, func(l *vaultLocator) { l.MgmtURL = u }))
		if err != nil || loc.MgmtURL != u {
			t.Fatalf("%q -> %+v %v", u, loc, err)
		}
	}
}
