package manager

import (
	"path/filepath"
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
