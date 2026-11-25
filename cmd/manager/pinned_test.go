package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Privasys/enclave-os-virtual/internal/pinned"
)

// The manager is an image's by default: no profile file refuses the start,
// and only an explicit unpinned run takes the settings as given.
func TestTheManagerNeverRunsUnpinnedByAccident(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent")
	if _, err := resolvePinned(absent, false, pinned.Given{Issuer: "https://privasys.id"}, false); err == nil {
		t.Fatal("started without an image profile")
	}
	g, err := resolvePinned(absent, true, pinned.Given{Issuer: "https://idp.example"}, false)
	if err != nil || g.Issuer != "https://idp.example" || g.Audience != defaultOIDCAudience || g.ManagerRole != defaultManagerRole {
		t.Fatalf("unpinned run: %+v %v", g, err)
	}

	prod := filepath.Join(dir, "image-profile")
	_ = os.WriteFile(prod, []byte("production\n"), 0o644)
	// manager.env empty for trust settings: the pinned values are used.
	g, err = resolvePinned(prod, false, pinned.Given{}, true)
	if err != nil || g.Issuer != "https://privasys.id" || g.Audience != "privasys-platform" || g.MgmtURL != "https://api.developer.privasys.org" {
		t.Fatalf("pinned: %+v %v", g, err)
	}
	// A foreign issuer from manager.env refuses the start.
	if _, err := resolvePinned(prod, false, pinned.Given{Issuer: "https://evil.example"}, true); err == nil {
		t.Fatal("a foreign issuer was accepted on a production image")
	}
}
