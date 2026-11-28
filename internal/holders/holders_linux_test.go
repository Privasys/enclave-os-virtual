//go:build linux

// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package holders

import (
	"crypto/rand"
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
		if _, err := addKey(mount, probe); err != nil {
			t.Skipf("this kernel has no filesystem encryption: %v", err)
		}
	}
	holderA := strings.Repeat("a", 32)
	holderB := strings.Repeat("b", 32)
	keyA, _ := NewRawKey()
	keyB, _ := NewRawKey()
	create := func(holder string, key []byte) string {
		t.Helper()
		if created, err := MakeFolder(mount, holder); err != nil || !created {
			t.Fatalf("make %s: %v %v", holder, created, err)
		}
		id, err := Seal(mount, holder, key)
		if err != nil {
			t.Fatalf("seal %s: %v", holder, err)
		}
		return id
	}
	idA := create(holderA, keyA)
	create(holderB, keyB)
	// A folder that is not empty when sealed is refused: nothing unkeyed
	// ever sits under a policy.
	holderC := strings.Repeat("c", 32)
	if _, err := MakeFolder(mount, holderC); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(FolderPath(mount, holderC), "early"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyC, _ := NewRawKey()
	if _, err := Seal(mount, holderC, keyC); err == nil {
		t.Fatal("a folder written before its seal was sealed")
	}
	if err := RemoveFolder(mount, holderC); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(FolderPath(mount, holderA), "notes.md")
	if err := os.WriteFile(secret, []byte("alice"), 0o600); err != nil {
		t.Fatalf("write in A: %v", err)
	}
	if err := os.WriteFile(filepath.Join(FolderPath(mount, holderB), "b.txt"), []byte("bob"), 0o600); err != nil {
		t.Fatalf("write in B: %v", err)
	}
	// An existing folder is opened: the same key is the same identifier,
	// another key is refused and does not stay loaded.
	if created, err := MakeFolder(mount, holderA); err != nil || created {
		t.Fatalf("make A again: %v %v", created, err)
	}
	if id2, err := Open(mount, holderA, keyA); err != nil || id2 != idA {
		t.Fatalf("open A again: %v %q", err, id2)
	}
	wrong, _ := NewRawKey()
	if _, err := Open(mount, holderA, wrong); err == nil {
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
	if _, err := Open(mount, holderA, keyA); err != nil {
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
}

// NewRawKey returns a fresh 64-byte key (the wallet generates a holder's key).
func NewRawKey() ([]byte, error) {
	k := make([]byte, RawKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}
