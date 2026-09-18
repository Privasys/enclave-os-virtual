//go:build linux

// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package holders

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHolderFoldersOnALoopDevice replays the verification of 2026-09-17 on
// a loop-backed ext4 (no LUKS: the kernel's per-directory encryption does
// not care what block device is underneath). Needs root, losetup and
// mkfs.ext4; skipped otherwise.
func TestHolderFoldersOnALoopDevice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, bin := range []string{"losetup", "mkfs.ext4", "tune2fs", "dumpe2fs"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("needs %s", bin)
		}
	}
	img := filepath.Join(t.TempDir(), "vol.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(img, 256<<20); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("losetup", "-f", "--show", img).Output()
	if err != nil {
		t.Skipf("losetup: %v", err)
	}
	dev := strings.TrimSpace(string(out))
	defer exec.Command("losetup", "-d", dev).Run()
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", dev).CombinedOutput(); err != nil {
		t.Fatalf("mkfs: %s", out)
	}
	mount := filepath.Join(t.TempDir(), "mnt")
	_ = os.Mkdir(mount, 0o755)
	if out, err := exec.Command("mount", dev, mount).CombinedOutput(); err != nil {
		t.Skipf("mount: %s", out)
	}
	defer func() {
		_ = setImmutable(mount, false)
		_ = setImmutable(filepath.Join(mount, Dir), false)
		exec.Command("umount", "-l", mount).Run()
	}()

	// Enable on a MOUNTED volume without the feature: tune2fs -O encrypt.
	if err := Enable(mount, dev); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := Enable(mount, dev); err != nil {
		t.Fatalf("enable twice: %v", err)
	}
	// Immutable root: nothing can be created outside holders/.
	if err := os.Mkdir(filepath.Join(mount, "appdata"), 0o755); err == nil {
		t.Fatal("the volume root must be immutable")
	}

	// A kernel without CONFIG_FS_ENCRYPTION (a workstation's WSL, say) cannot
	// run the rest.
	if probe, _ := NewRawKey(); probe != nil {
		if _, err := AddKey(mount, probe); err != nil {
			t.Skipf("this kernel has no filesystem encryption: %v", err)
		}
	}
	holderA := strings.Repeat("a", 32)
	holderB := strings.Repeat("b", 32)
	keyA, _ := NewRawKey()
	keyB, _ := NewRawKey()
	idA, err := Create(mount, holderA, keyA)
	if err != nil {
		t.Fatalf("create A: %v", err)
	}
	if _, err := Create(mount, holderB, keyB); err != nil {
		t.Fatalf("create B: %v", err)
	}
	secret := filepath.Join(FolderPath(mount, holderA), "notes.md")
	if err := os.WriteFile(secret, []byte("alice"), 0o600); err != nil {
		t.Fatalf("write in A: %v", err)
	}
	if err := os.WriteFile(filepath.Join(FolderPath(mount, holderB), "b.txt"), []byte("bob"), 0o600); err != nil {
		t.Fatalf("write in B: %v", err)
	}
	// The same key again is the same identifier, another key is refused.
	if id2, err := Create(mount, holderA, keyA); err != nil || id2 != idA {
		t.Fatalf("create A again: %v %q", err, id2)
	}
	if _, err := Create(mount, holderA, keyB); err == nil {
		t.Fatal("a folder must not accept another key")
	}

	// Close: locked, B untouched.
	if st, _, err := Close(mount, holderA, idA); err != nil || st != Absent {
		t.Fatalf("close: %v %v", st, err)
	}
	if _, err := os.ReadFile(secret); err == nil {
		t.Fatal("locked folder must not be readable")
	}
	if b, err := os.ReadFile(filepath.Join(FolderPath(mount, holderB), "b.txt")); err != nil || string(b) != "bob" {
		t.Fatalf("B must stay readable: %v", err)
	}
	if st, err := KeyStatus(mount, idA); err != nil || st != Absent {
		t.Fatalf("status: %v %v", st, err)
	}

	// Open again, then the busy case: a file held open keeps the key.
	if _, err := Open(mount, holderA, keyA, -1); err != nil {
		t.Fatalf("open: %v", err)
	}
	f, err := os.Open(secret)
	if err != nil {
		t.Fatal(err)
	}
	st, pids, err := Close(mount, holderA, idA)
	if err != ErrBusy || st != IncompletelyRemoved {
		t.Fatalf("busy close: %v %v", st, err)
	}
	if len(pids) == 0 {
		t.Fatal("the process holding the file must be reported")
	}
	f.Close()
	time.Sleep(100 * time.Millisecond)
	if st, _, err := Close(mount, holderA, idA); err != nil || st != Absent {
		t.Fatalf("close after release: %v %v", st, err)
	}

	// Delete without the key.
	if err := Delete(mount, holderA); err != nil {
		t.Fatalf("delete locked: %v", err)
	}
	if _, err := os.Stat(FolderPath(mount, holderA)); err == nil {
		t.Fatal("folder must be gone")
	}
	// The app (no LINUX_IMMUTABLE) could not have done that: holders/ stays
	// immutable after our own write.
	if err := os.Mkdir(filepath.Join(mount, Dir, strings.Repeat("c", 32)), 0o700); err == nil {
		t.Fatal("holders/ must be immutable again")
	}
}
