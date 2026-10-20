package manager

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

func TestRegistry_NilNoOp(t *testing.T) {
	r := newRegistry("")
	if r != nil {
		t.Fatal("empty path should return nil")
	}
	if err := r.Save(launcher.LoadRequest{Name: "x"}); err != nil {
		t.Fatalf("nil Save: %v", err)
	}
	if err := r.Remove("x"); err != nil {
		t.Fatalf("nil Remove: %v", err)
	}
	got, err := r.List()
	if err != nil || got != nil {
		t.Fatalf("nil List: got=%v err=%v", got, err)
	}
}

func TestRegistry_SaveReplaceRemove(t *testing.T) {
	dir := t.TempDir()
	r := newRegistry(filepath.Join(dir, "manager-apps.json"))

	// First boot — file does not exist.
	got, err := r.List()
	if err != nil {
		t.Fatalf("List on missing file: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}

	a := launcher.LoadRequest{Name: "alpha", Image: "img@sha256:aaa", Port: 8000}
	b := launcher.LoadRequest{Name: "beta", Image: "img@sha256:bbb", Port: 9090}
	if err := r.Save(a); err != nil {
		t.Fatalf("Save a: %v", err)
	}
	if err := r.Save(b); err != nil {
		t.Fatalf("Save b: %v", err)
	}
	got, err = r.List()
	if err != nil || len(got) != 2 {
		t.Fatalf("after 2 saves: got=%d err=%v", len(got), err)
	}

	// Replace existing entry (new image digest, same name).
	a2 := launcher.LoadRequest{Name: "alpha", Image: "img@sha256:zzz", Port: 8000}
	if err := r.Save(a2); err != nil {
		t.Fatalf("Save a2: %v", err)
	}
	got, _ = r.List()
	if len(got) != 2 {
		t.Fatalf("replace should not grow list, got %d", len(got))
	}
	for _, e := range got {
		if e.Name == "alpha" && e.Image != "img@sha256:zzz" {
			t.Fatalf("alpha not replaced: %+v", e)
		}
	}

	if err := r.Remove("alpha"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, _ = r.List()
	if len(got) != 1 || got[0].Name != "beta" {
		t.Fatalf("after remove: %+v", got)
	}

	// Remove unknown is a no-op.
	if err := r.Remove("ghost"); err != nil {
		t.Fatalf("Remove unknown: %v", err)
	}
}

// TestRegistryPurgedForOrphan proves the orphan-cleanup contract that the
// unload handler depends on: an entry whose container has NO live spec must
// still be removable from the persisted registry.
//
// This is the regression that made orphans permanent. The handler used to
// return as soon as launcher.Unload reported "not loaded", so registry.Remove
// never ran; the entry survived, replayed on every boot, and could not be
// cleared by hand because production enclaves ship no shell. The handler now
// treats launcher.ErrNotLoaded as "nothing to stop, still purge" — this test
// pins the registry half of that, and errors.Is(err, launcher.ErrNotLoaded)
// is what lets the handler tell this case apart from a real failure.
func TestRegistryPurgedForOrphan(t *testing.T) {
	dir := t.TempDir()
	r := newRegistry(filepath.Join(dir, "manager-apps.json"))

	if err := r.Save(launcher.LoadRequest{Name: "release-probe-d"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := r.Save(launcher.LoadRequest{Name: "keep-me"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	// The orphan never loads, so nothing else will ever remove this entry.
	if err := r.Remove("release-probe-d"); err != nil {
		t.Fatalf("remove orphan: %v", err)
	}

	got, err := r.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Name != "keep-me" {
		t.Fatalf("registry = %+v, want only keep-me (the orphan must not replay again)", got)
	}

	// Idempotent: removing it again is not an error, so a repeated DELETE
	// after the entry is already gone still reports success.
	if err := r.Remove("release-probe-d"); err != nil {
		t.Fatalf("second remove should be a no-op, got %v", err)
	}
}

func registryWith(t *testing.T, entries ...launcher.LoadRequest) *registry {
	t.Helper()
	r := newRegistry(filepath.Join(t.TempDir(), "manager-apps.json"))
	for _, e := range entries {
		if err := r.Save(e); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func entry(t *testing.T, r *registry, name string) launcher.LoadRequest {
	t.Helper()
	list, err := r.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no registry entry %q", name)
	return launcher.LoadRequest{}
}

// A migration onto another constellation moves the replay to the new key and
// the new vaults, and drops the creation grant the key no longer needs.
func TestRebindKeyAcrossConstellations(t *testing.T) {
	r := registryWith(t, launcher.LoadRequest{
		Name:                   "app",
		KeyHandle:              "apps.privasys.org/x/storage-kek/v1",
		KeyCreationGrant:       "grant-for-v1",
		VaultEndpoints:         []string{"old-a:1", "old-b:2"},
		VaultMrenclave:         "old",
		VaultAttestationServer: "https://as.example/verify",
	})

	moved, err := r.RebindKey("app", launcher.RotateRequest{
		Phase:                     launcher.RotatePhaseAdd,
		OldHandle:                 "apps.privasys.org/x/storage-kek/v1",
		NewHandle:                 "apps.privasys.org/x/storage-kek/v2",
		NewVaultEndpoints:         []string{"new-a:3", "new-b:4"},
		NewVaultMrenclave:         "new",
		NewVaultAttestationServer: "https://as.example/verify",
	})
	if err != nil || !moved {
		t.Fatalf("moved=%v err=%v, want a move", moved, err)
	}
	got := entry(t, r, "app")
	if got.KeyHandle != "apps.privasys.org/x/storage-kek/v2" {
		t.Errorf("handle = %q, want v2", got.KeyHandle)
	}
	if !reflect.DeepEqual(got.VaultEndpoints, []string{"new-a:3", "new-b:4"}) || got.VaultMrenclave != "new" {
		t.Errorf("vaults = %v / %q, want the new constellation", got.VaultEndpoints, got.VaultMrenclave)
	}
	if got.KeyCreationGrant != "" {
		t.Errorf("creation grant kept (%q), want it dropped", got.KeyCreationGrant)
	}
}

// A rotation within one constellation moves the handle and keeps the vaults.
func TestRebindKeySameConstellation(t *testing.T) {
	r := registryWith(t, launcher.LoadRequest{
		Name:           "app",
		KeyHandle:      "h/v1",
		VaultEndpoints: []string{"a:1"},
		VaultMrenclave: "m",
	})
	if moved, err := r.RebindKey("app", launcher.RotateRequest{OldHandle: "h/v1", NewHandle: "h/v2"}); err != nil || !moved {
		t.Fatalf("moved=%v err=%v", moved, err)
	}
	got := entry(t, r, "app")
	if got.KeyHandle != "h/v2" || !reflect.DeepEqual(got.VaultEndpoints, []string{"a:1"}) || got.VaultMrenclave != "m" {
		t.Errorf("got %q %v %q, want h/v2 on the same vaults", got.KeyHandle, got.VaultEndpoints, got.VaultMrenclave)
	}
}

// An app reloaded between the add and this update is on neither handle: its
// newer request wins and is left alone. A retried add (already on the new
// handle) is accepted, and other entries are never touched.
func TestRebindKeyLeavesOthersAlone(t *testing.T) {
	r := registryWith(t,
		launcher.LoadRequest{Name: "app", KeyHandle: "h/v5"},
		launcher.LoadRequest{Name: "other", KeyHandle: "h/v1"},
	)
	if moved, _ := r.RebindKey("app", launcher.RotateRequest{OldHandle: "h/v1", NewHandle: "h/v2"}); moved {
		t.Error("moved an entry that is on neither the old nor the new handle")
	}
	if got := entry(t, r, "app").KeyHandle; got != "h/v5" {
		t.Errorf("reloaded entry changed to %q", got)
	}
	if got := entry(t, r, "other").KeyHandle; got != "h/v1" {
		t.Errorf("unrelated entry changed to %q", got)
	}
	if moved, err := r.RebindKey("app", launcher.RotateRequest{OldHandle: "h/v4", NewHandle: "h/v5"}); err != nil || !moved {
		t.Errorf("retried add: moved=%v err=%v, want accepted", moved, err)
	}
	if moved, _ := r.RebindKey("missing", launcher.RotateRequest{OldHandle: "a", NewHandle: "b"}); moved {
		t.Error("moved an entry that does not exist")
	}
}
