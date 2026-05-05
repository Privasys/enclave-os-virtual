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

	a := launcher.LoadRequest{Name: "alpha", Image: "img@sha256:aaa", Port: 8080}
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
	a2 := launcher.LoadRequest{Name: "alpha", Image: "img@sha256:zzz", Port: 8080}
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
