package container

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsDiskRef(t *testing.T) {
	for _, tc := range []struct {
		ref  string
		want bool
	}{
		{"disk://confidential-ai-prod", true},
		{"disk://x", true},
		{"disk:/x", false},
		{"https://x", false},
		{"ghcr.io/foo/bar:latest", false},
		{"", false},
	} {
		if got := IsDiskRef(tc.ref); got != tc.want {
			t.Errorf("IsDiskRef(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestDiskRefDir(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		got, err := diskRefDir("disk://confidential-ai-prod")
		if err != nil {
			t.Fatal(err)
		}
		want := "/var/lib/images/confidential-ai-prod"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("nested name", func(t *testing.T) {
		got, err := diskRefDir("disk://confidential-ai/prod")
		if err != nil {
			t.Fatal(err)
		}
		want := "/var/lib/images/confidential-ai/prod"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("rejects parent traversal", func(t *testing.T) {
		_, err := diskRefDir("disk://../etc/passwd")
		if err == nil {
			t.Fatal("expected error for path traversal")
		}
		if !strings.Contains(err.Error(), "..") {
			t.Errorf("expected error to mention '..', got %v", err)
		}
	})

	t.Run("rejects empty", func(t *testing.T) {
		_, err := diskRefDir("disk://")
		if err == nil {
			t.Fatal("expected error for empty ref")
		}
	})

	t.Run("rejects non-disk ref", func(t *testing.T) {
		_, err := diskRefDir("ghcr.io/foo:latest")
		if err == nil {
			t.Fatal("expected error for non-disk ref")
		}
	})
}

func TestTarOCILayoutSkipsLostFound(t *testing.T) {
	dir := t.TempDir()
	// Real OCI layout files we expect to be tarred.
	for _, f := range []string{"oci-layout", "index.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", "abc"), []byte("blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Simulate ext4's lost+found: a directory we shouldn't recurse
	// into and that may be unreadable. We use mode 0 so Walk cannot
	// list its contents (matches real on-disk permissions).
	lf := filepath.Join(dir, "lost+found")
	if err := os.Mkdir(lf, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(lf, 0o755)

	var buf bytes.Buffer
	if err := tarOCILayout(dir, &buf); err != nil {
		t.Fatalf("tarOCILayout failed: %v", err)
	}

	tr := tar.NewReader(&buf)
	got := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		got[h.Name] = true
	}
	for _, want := range []string{"oci-layout", "index.json", "blobs/", "blobs/sha256/", "blobs/sha256/abc"} {
		if !got[want] {
			t.Errorf("expected %q in tar, got entries: %v", want, got)
		}
	}
	if got["lost+found"] || got["lost+found/"] {
		t.Errorf("lost+found should not appear in tar, got: %v", got)
	}
}
