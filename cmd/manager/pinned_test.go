package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Privasys/enclave-os-virtual/internal/pinned"
)

// The manager runs only on an image: no profile file refuses the start, and
// the settings are the profile's.
func TestTheManagerRunsOnlyWithItsImagesPins(t *testing.T) {
	dir := t.TempDir()
	if _, err := resolvePinned(filepath.Join(dir, "absent"), pinned.Given{Issuer: "https://privasys.id"}, false); err == nil {
		t.Fatal("started without an image profile")
	}

	prod := filepath.Join(dir, "image-profile")
	_ = os.WriteFile(prod, []byte("production\n"), 0o644)
	// manager.env empty for trust settings: the pinned values are used.
	g, err := resolvePinned(prod, pinned.Given{}, true)
	if err != nil || g.Issuer != "https://privasys.id" || g.Audience != "privasys-platform" || g.MgmtURL != "https://api.developer.privasys.org" {
		t.Fatalf("pinned: %+v %v", g, err)
	}
	// A foreign issuer from manager.env refuses the start.
	if _, err := resolvePinned(prod, pinned.Given{Issuer: "https://evil.example"}, true); err == nil {
		t.Fatal("a foreign issuer was accepted on a production image")
	}
	if pinnedAppDomain(prod) != "apps.privasys.org" || pinnedAppDomain(filepath.Join(dir, "absent")) != "" {
		t.Fatal("app domain")
	}
}
