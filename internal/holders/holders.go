//go:build linux

// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package holders manages holder folders: one directory per (app, holder)
// inside the app's own encrypted volume, each encrypted with that holder's
// key by the kernel (fscrypt v2 on ext4), so the app can read a holder's
// data only while the runtime has loaded that key.
//
// The runtime is the only door. The app never names a path, never sees a key
// and cannot create, open or re-key a folder itself: it asks the manager for
// "this holder's folder" and gets a directory that is open or locked.
//
// # Layout
//
//	<volume mount>/            immutable: the app cannot create entries here
//	  holders/                 immutable: only this package creates folders
//	    <holder key>/          fscrypt policy bound to the holder's key
//
// The immutable flags mean an app that declares holder folders has no
// unkeyed corner of its volume to copy a holder's data into. They are lifted
// around this package's own writes only.
//
// # What a locked folder still shows
//
// The number of files, their sizes, the shape of the tree and timestamps.
// Never names, never content. Nobody outside the app sees even that: the
// whole volume is under the app's LUKS.
//
// # Revoke is verified, not assumed
//
// Removing a key while a process holds a file open leaves the key
// "incompletely removed": that file stays readable, even to new opens, and
// names stay in clear. Close reports that, with the processes at fault, so
// the manager can kill them and remove again; only an "absent" status is a
// revoke.
package holders

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// Dir is the directory under the volume mount that holds the folders.
	Dir = "holders"

	// RawKeySize is the size of a holder's key: fscrypt v2 keys are 64 bytes.
	RawKeySize = 64

	// fsImmutableFL is the inode flag chattr calls +i (linux/fs.h).
	fsImmutableFL = 0x00000010
)

// Status of a holder's key on a filesystem, as the kernel reports it.
type Status int

const (
	// Absent: no key loaded, the folder is locked.
	Absent Status = iota + 1
	// Present: the key is loaded, the folder is open.
	Present
	// IncompletelyRemoved: a removal ran while files were in use; those
	// files are still readable. Not a revoke.
	IncompletelyRemoved
)

func (s Status) String() string {
	switch s {
	case Absent:
		return "absent"
	case Present:
		return "present"
	case IncompletelyRemoved:
		return "incompletely_removed"
	}
	return "unknown"
}

// ErrBusy is returned by Close when files under the folder are still in
// use and the key could not be fully removed.
var ErrBusy = errors.New("holders: files in use, key incompletely removed")

// FolderPath is the folder of one holder under a volume mount.
func FolderPath(mount, holderKey string) string {
	return filepath.Join(mount, Dir, holderKey)
}

// ValidHolderKey accepts the hash form the manager derives (hex, 32 chars):
// nothing else ever becomes a path component under holders/.
func ValidHolderKey(k string) bool {
	if len(k) != 32 {
		return false
	}
	for _, c := range k {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Enable prepares a mounted volume for holder folders: the ext4 `encrypt`
// feature (settable on a mounted filesystem), the holders/ directory, and
// the immutable flags on the volume root and on holders/. Idempotent.
func Enable(mount, device string) error {
	if device != "" {
		if err := ensureEncryptFeature(device); err != nil {
			return err
		}
	}
	dir := filepath.Join(mount, Dir)
	if err := withMutable(mount, func() error {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return nil // already there, and immutable: leave it
		}
		if err := os.Mkdir(dir, 0o711); err != nil {
			return err
		}
		return os.Chmod(dir, 0o711)
	}); err != nil {
		return err
	}
	if err := setImmutable(dir, true); err != nil {
		return err
	}
	return setImmutable(mount, true)
}

// ensureEncryptFeature turns the ext4 `encrypt` feature on when it is
// absent. dumpe2fs and tune2fs are in the image with e2fsprogs.
func ensureEncryptFeature(device string) error {
	out, err := exec.Command("dumpe2fs", "-h", device).CombinedOutput()
	if err != nil {
		return fmt.Errorf("holders: dumpe2fs %s: %s (%w)", device, strings.TrimSpace(string(out)), err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Filesystem features:") && strings.Contains(line, " encrypt") {
			return nil
		}
	}
	if out, err := exec.Command("tune2fs", "-O", "encrypt", device).CombinedOutput(); err != nil {
		return fmt.Errorf("holders: tune2fs -O encrypt %s: %s (%w)", device, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// Create makes a holder's folder under an enabled volume and binds it to
// rawKey: the key is loaded, the folder created, the policy set. A folder
// that already exists must carry a policy for this very key; a different
// key is refused rather than silently opening nothing. Returns the kernel's
// identifier of the key (16 bytes, hex), which the policy carries.
func Create(mount, holderKey string, rawKey []byte) (keyID string, err error) {
	if !ValidHolderKey(holderKey) {
		return "", errors.New("holders: invalid holder key")
	}
	id, err := AddKey(mount, rawKey)
	if err != nil {
		return "", err
	}
	folder := FolderPath(mount, holderKey)
	if fi, statErr := os.Stat(folder); statErr == nil && fi.IsDir() {
		have, pErr := policyIdentifier(folder)
		if pErr != nil {
			return "", pErr
		}
		if have != id {
			return "", fmt.Errorf("holders: folder %s is bound to another key", holderKey)
		}
		return id, nil
	}
	dir := filepath.Join(mount, Dir)
	err = withMutableDir(dir, func() error {
		if err := os.Mkdir(folder, 0o700); err != nil {
			return err
		}
		return setPolicy(folder, id)
	})
	if err != nil {
		_ = os.Remove(folder)
		return "", err
	}
	return id, nil
}

// Open loads a holder's key and hands the folder to hostUID. The folder must
// exist and be bound to this key.
func Open(mount, holderKey string, rawKey []byte, hostUID int) (keyID string, err error) {
	if !ValidHolderKey(holderKey) {
		return "", errors.New("holders: invalid holder key")
	}
	folder := FolderPath(mount, holderKey)
	if fi, statErr := os.Stat(folder); statErr != nil || !fi.IsDir() {
		return "", fmt.Errorf("holders: no folder for %s", holderKey)
	}
	id, err := AddKey(mount, rawKey)
	if err != nil {
		return "", err
	}
	have, err := policyIdentifier(folder)
	if err != nil {
		return "", err
	}
	if have != id {
		_, _ = removeKey(mount, id)
		return "", fmt.Errorf("holders: folder %s is bound to another key", holderKey)
	}
	if hostUID >= 0 {
		if err := os.Chown(folder, hostUID, hostUID); err != nil {
			return "", fmt.Errorf("holders: chown: %w", err)
		}
	}
	return id, nil
}

// Close removes the holder's key from the kernel. It answers ErrBusy, with
// the processes still holding files under the folder, when the removal was
// incomplete; the caller kills them and calls again. Only an Absent status
// is a closed folder.
func Close(mount, holderKey, keyID string) (Status, []int, error) {
	st, err := removeKey(mount, keyID)
	if err != nil {
		return 0, nil, err
	}
	if st == Absent {
		return st, nil, nil
	}
	return st, holdersOf(FolderPath(mount, holderKey)), ErrBusy
}

// KeyStatus reports whether the key is loaded on the filesystem.
func KeyStatus(mount, keyID string) (Status, error) {
	f, err := os.Open(mount)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var a unix.FscryptGetKeyStatusArg
	a.Key_spec = specifier(keyID)
	if err := ioctl(f.Fd(), unix.FS_IOC_GET_ENCRYPTION_KEY_STATUS, unsafe.Pointer(&a)); err != nil {
		return 0, fmt.Errorf("holders: key status: %w", err)
	}
	return Status(a.Status), nil
}

// Delete removes a holder's folder, key or no key: a locked folder can be
// deleted by name (verified 2026-09-17), which is what lets a holder erase
// their data from a phone that never held the key.
func Delete(mount, holderKey string) error {
	if !ValidHolderKey(holderKey) {
		return errors.New("holders: invalid holder key")
	}
	return withMutableDir(filepath.Join(mount, Dir), func() error {
		return os.RemoveAll(FolderPath(mount, holderKey))
	})
}

// Usage returns the bytes under a holder's folder, walked by name (works
// locked: sizes are visible without the key).
func Usage(mount, holderKey string) (int64, error) {
	var total int64
	err := filepath.Walk(FolderPath(mount, holderKey), func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// NewRawKey returns a fresh 64-byte key. The wallet generates the holder's
// key; this exists for tests and for a runtime asked to key a folder itself.
func NewRawKey() ([]byte, error) {
	k := make([]byte, RawKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// ---- the ioctls ---------------------------------------------------------

// AddKey loads rawKey into the filesystem's keyring and returns the
// identifier the kernel derives from it (hex). Loading the same key twice
// is a no-op with the same identifier.
func AddKey(mount string, rawKey []byte) (string, error) {
	if len(rawKey) != RawKeySize {
		return "", fmt.Errorf("holders: key must be %d bytes", RawKeySize)
	}
	f, err := os.Open(mount)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var hdr unix.FscryptAddKeyArg
	hdr.Key_spec.Type = unix.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER
	hdr.Raw_size = uint32(len(rawKey))
	buf := make([]byte, int(unsafe.Sizeof(hdr))+len(rawKey))
	copy(buf, (*[unsafe.Sizeof(hdr)]byte)(unsafe.Pointer(&hdr))[:])
	copy(buf[unsafe.Sizeof(hdr):], rawKey)
	defer zero(buf)
	if err := ioctl(f.Fd(), unix.FS_IOC_ADD_ENCRYPTION_KEY, unsafe.Pointer(&buf[0])); err != nil {
		return "", fmt.Errorf("holders: add key: %w", err)
	}
	out := (*unix.FscryptAddKeyArg)(unsafe.Pointer(&buf[0]))
	return fmt.Sprintf("%x", out.Key_spec.U[:16]), nil
}

func removeKey(mount, keyID string) (Status, error) {
	f, err := os.Open(mount)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	a := unix.FscryptRemoveKeyArg{Key_spec: specifier(keyID)}
	if err := ioctl(f.Fd(), unix.FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS, unsafe.Pointer(&a)); err != nil {
		if errors.Is(err, unix.ENOKEY) {
			return Absent, nil
		}
		return 0, fmt.Errorf("holders: remove key: %w", err)
	}
	return KeyStatus(mount, keyID)
}

func setPolicy(folder, keyID string) error {
	f, err := os.Open(folder)
	if err != nil {
		return err
	}
	defer f.Close()
	p := unix.FscryptPolicyV2{
		Version:                   unix.FSCRYPT_POLICY_V2,
		Contents_encryption_mode:  unix.FSCRYPT_MODE_AES_256_XTS,
		Filenames_encryption_mode: unix.FSCRYPT_MODE_AES_256_CTS,
		Flags:                     unix.FSCRYPT_POLICY_FLAGS_PAD_32,
	}
	id, err := parseKeyID(keyID)
	if err != nil {
		return err
	}
	copy(p.Master_key_identifier[:], id)
	if err := ioctl(f.Fd(), unix.FS_IOC_SET_ENCRYPTION_POLICY, unsafe.Pointer(&p)); err != nil {
		return fmt.Errorf("holders: set policy: %w", err)
	}
	return nil
}

// policyIdentifier reads the master key identifier of a folder's policy.
func policyIdentifier(folder string) (string, error) {
	f, err := os.Open(folder)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// FS_IOC_GET_ENCRYPTION_POLICY_EX takes {policy_size, union policy}.
	var arg struct {
		Size   uint64
		Policy unix.FscryptPolicyV2
	}
	arg.Size = uint64(unsafe.Sizeof(arg.Policy))
	if err := ioctl(f.Fd(), unix.FS_IOC_GET_ENCRYPTION_POLICY_EX, unsafe.Pointer(&arg)); err != nil {
		return "", fmt.Errorf("holders: get policy: %w", err)
	}
	if arg.Policy.Version != unix.FSCRYPT_POLICY_V2 {
		return "", errors.New("holders: folder carries a policy this runtime did not set")
	}
	return fmt.Sprintf("%x", arg.Policy.Master_key_identifier[:]), nil
}

func specifier(keyID string) (s unix.FscryptKeySpecifier) {
	s.Type = unix.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER
	id, _ := parseKeyID(keyID)
	copy(s.U[:], id)
	return
}

func parseKeyID(keyID string) ([]byte, error) {
	if len(keyID) != 32 {
		return nil, errors.New("holders: key identifier must be 16 bytes hex")
	}
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(keyID[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, errors.New("holders: key identifier must be hex")
		}
		out[i] = byte(v)
	}
	return out, nil
}

func ioctl(fd uintptr, req uint, p unsafe.Pointer) error {
	_, _, e := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(req), uintptr(p))
	if e != 0 {
		return e
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---- immutable flags ----------------------------------------------------

func getFlags(path string) (int32, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	var flags int32
	if err := ioctl(f.Fd(), unix.FS_IOC_GETFLAGS, unsafe.Pointer(&flags)); err != nil {
		f.Close()
		return 0, nil, fmt.Errorf("holders: get flags %s: %w", path, err)
	}
	return flags, f, nil
}

func setImmutable(path string, on bool) error {
	flags, f, err := getFlags(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if on {
		flags |= fsImmutableFL
	} else {
		flags &^= fsImmutableFL
	}
	if err := ioctl(f.Fd(), unix.FS_IOC_SETFLAGS, unsafe.Pointer(&flags)); err != nil {
		return fmt.Errorf("holders: set flags %s: %w", path, err)
	}
	return nil
}

// withMutable lifts the immutable flag on path around fn and restores it.
func withMutable(path string, fn func() error) error {
	flags, f, err := getFlags(path)
	if err != nil {
		return err
	}
	f.Close()
	was := flags&fsImmutableFL != 0
	if was {
		if err := setImmutable(path, false); err != nil {
			return err
		}
		defer func() { _ = setImmutable(path, true) }()
	}
	return fn()
}

func withMutableDir(dir string, fn func() error) error { return withMutable(dir, fn) }

// ---- who holds files -------------------------------------------------------

// holdersOf lists the pids with an open file, a working directory or a
// mapping under folder: what keeps a key "incompletely removed". A container
// process sees the folder under its own mount (/data/holders/<key>), so the
// match is on the path element holders/<key> and the volume's device, not on
// the host path.
func holdersOf(folder string) []int {
	var st unix.Stat_t
	if err := unix.Stat(folder, &st); err != nil {
		return nil
	}
	marker := "/" + Dir + "/" + filepath.Base(folder)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		if pidUses(pid, marker, st.Dev) {
			pids = append(pids, pid)
		}
	}
	return pids
}

func under(target, marker string) bool {
	return target == strings.TrimPrefix(marker, "/") || strings.Contains(target+"/", marker+"/")
}

func onDevice(path string, dev uint64) bool {
	var st unix.Stat_t
	return unix.Stat(path, &st) == nil && st.Dev == dev
}

func pidUses(pid int, marker string, dev uint64) bool {
	base := "/proc/" + strconv.Itoa(pid)
	for _, link := range []string{base + "/cwd", base + "/exe"} {
		if target, err := os.Readlink(link); err == nil && under(target, marker) && onDevice(link, dev) {
			return true
		}
	}
	if fds, err := os.ReadDir(base + "/fd"); err == nil {
		for _, fd := range fds {
			p := base + "/fd/" + fd.Name()
			if target, err := os.Readlink(p); err == nil && under(target, marker) && onDevice(p, dev) {
				return true
			}
		}
	}
	if maps, err := os.ReadFile(base + "/maps"); err == nil && bytes.Contains(maps, []byte(marker+"/")) {
		return true
	}
	return false
}

// Chown hands an existing folder to hostUID (the app named a uid on open).
func Chown(mount, holderKey string, hostUID int) error {
	if !ValidHolderKey(holderKey) {
		return errors.New("holders: invalid holder key")
	}
	return os.Chown(FolderPath(mount, holderKey), hostUID, hostUID)
}
