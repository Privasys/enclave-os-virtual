package container

import (
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
