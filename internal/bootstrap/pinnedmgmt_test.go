package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

// Registration on a production image never follows a management URL from
// instance metadata that is not pinned.
func TestRegistrationUsesThePinnedControlPlane(t *testing.T) {
	old := pinnedProfileFile
	defer func() { pinnedProfileFile = old }()
	dir := t.TempDir()
	pinnedProfileFile = filepath.Join(dir, "image-profile")

	// No profile file: refused, never "unpinned".
	if _, err := pinnedMgmtURL("https://anything.example"); err == nil {
		t.Fatal("registration ran without an image profile")
	}
	_ = os.WriteFile(pinnedProfileFile, []byte("production\n"), 0o644)
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
