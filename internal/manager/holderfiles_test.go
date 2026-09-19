package manager

import (
	"os"
	"path/filepath"
	"testing"
)

// The window never leaves the folder: "..", absolute paths and symlinks an
// app planted all resolve inside it or are refused.
func TestHolderFilesPathIsConfinedToTheFolder(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "folder")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "workspace", "Demo"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skip("symlinks unavailable here")
	}

	for _, ok := range []string{"", "/", ".", "..", "workspace", "workspace/Demo", "/workspace/../workspace/Demo"} {
		if _, _, err := confineToFolder(root, ok); err != nil {
			t.Errorf("%q must be inside the folder: %v", ok, err)
		}
	}
	if target, rel, err := confineToFolder(root, "workspace/Demo"); err != nil || rel != "workspace/Demo" || filepath.Base(target) != "Demo" {
		t.Errorf("workspace/Demo resolved to %q %q %v", target, rel, err)
	}
	for _, bad := range []string{"../outside", "escape", "escape/secret", "/../../etc/passwd"} {
		if target, _, err := confineToFolder(root, bad); err == nil {
			t.Errorf("%q must be refused, resolved to %q", bad, target)
		}
	}
	if _, _, err := confineToFolder(root, "workspace/Missing"); err == nil || err.Error() != "no such path" {
		t.Errorf("a missing path answers not found: %v", err)
	}
}
