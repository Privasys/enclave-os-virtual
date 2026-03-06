// Package volume manages per-container encrypted storage using LVM + LUKS2.
//
// Each container that requests persistent encrypted storage gets its own
// LVM Logical Volume (LV) on the "containers" Volume Group (VG), formatted
// with LUKS2 + AEAD integrity.  The decrypted block device is mounted at
// /run/containers/<name> and bind-mounted into the container's rootfs via
// the existing Volumes mechanism.
//
// # Disk layout
//
//	GPT partition "containers"   (by-partlabel)
//	  └── LVM PV  →  VG "containers"
//	        ├── LV "vol-<name>"  →  LUKS2  → ext4  →  /run/containers/<name>
//	        ├── LV "vol-<name>"  →  ...
//	        └── (free space for future containers)
//
// # Key management
//
// Volume keys are either:
//   - Supplied by the operator in the LoadRequest ("byok:<fingerprint>"),
//     where <fingerprint> is the hex SHA-256 of the raw key bytes, or
//   - Randomly generated inside the enclave ("generated").
//
// Keys are never persisted to the OS data partition — they exist only in
// TEE memory while the container is loaded.
//
// # Thread safety
//
// The caller (launcher) holds a mutex during Load/Unload, so volume
// operations are not called concurrently for the same container name.
package volume

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

const (
	// VGName is the LVM Volume Group name for container volumes.
	VGName = "containers"

	// MountBase is the directory under which container volumes are mounted.
	MountBase = "/run/containers"

	// DefaultSize is the default LV size when none is specified.
	DefaultSize = "1G"
)

// Manager handles per-container encrypted volume lifecycle.
type Manager struct {
	log *zap.Logger
}

// NewManager creates a new volume Manager.
func NewManager(log *zap.Logger) *Manager {
	return &Manager{log: log.Named("volume")}
}

// VolumeInfo describes the state of a provisioned container volume.
type VolumeInfo struct {
	// Name is the container name this volume belongs to.
	Name string

	// KeyOrigin is "byok:<fingerprint>" or "generated".
	// The fingerprint is the hex SHA-256 of the raw key bytes.
	KeyOrigin string

	// MountPath is the host path where the volume is mounted.
	MountPath string

	// LVName is the LVM logical volume name (e.g. "vol-myapp").
	LVName string
}

// IsVGReady returns true if the "containers" VG exists and is available.
func (m *Manager) IsVGReady() bool {
	err := exec.Command("vgs", "--noheadings", "-o", "vg_name", VGName).Run()
	return err == nil
}

// Create provisions a new encrypted volume for a container:
//  1. Create an LVM LV in the "containers" VG
//  2. Format it with LUKS2 + AEAD integrity
//  3. Open (decrypt) the LUKS volume
//  4. Create an ext4 filesystem
//  5. Mount at /run/containers/<name>
//
// If key is empty, a random 256-bit key is generated (enclave-generated).
// Returns VolumeInfo describing the provisioned volume.
func (m *Manager) Create(name, size, key string) (*VolumeInfo, error) {
	if size == "" {
		size = DefaultSize
	}

	lvName := "vol-" + name
	mapperName := "container-" + name
	mountPath := MountBase + "/" + name

	m.log.Info("creating encrypted volume",
		zap.String("container", name),
		zap.String("lv", lvName),
		zap.String("size", size),
	)

	// Determine key origin.
	var keyOrigin string
	if key == "" {
		// Generate random 256-bit key.
		raw, err := randomKey()
		if err != nil {
			return nil, fmt.Errorf("volume: failed to generate key: %w", err)
		}
		key = raw
		keyOrigin = "generated"
	} else {
		fingerprint := sha256.Sum256([]byte(key))
		keyOrigin = fmt.Sprintf("byok:%x", fingerprint)
	}

	// 1. Create LV.
	if err := run("lvcreate", "-L", size, "-n", lvName, VGName, "-y"); err != nil {
		return nil, fmt.Errorf("volume: lvcreate failed: %w", err)
	}

	lvPath := "/dev/" + VGName + "/" + lvName

	// 2. LUKS format.
	if err := runStdin(key, "cryptsetup", "luksFormat",
		"--type", "luks2",
		"--cipher", "aes-xts-plain64",
		"--key-size", "512",
		"--hash", "sha256",
		"--integrity", "aead",
		"--iter-time", "2000",
		"--key-file=-",
		"--batch-mode",
		lvPath,
	); err != nil {
		// Clean up the LV on failure.
		_ = run("lvremove", "-f", lvPath)
		return nil, fmt.Errorf("volume: luksFormat failed: %w", err)
	}

	// 3. Open LUKS.
	if err := runStdin(key, "cryptsetup", "luksOpen",
		lvPath, mapperName, "--key-file=-",
	); err != nil {
		_ = run("lvremove", "-f", lvPath)
		return nil, fmt.Errorf("volume: luksOpen failed: %w", err)
	}

	// 4. Create ext4 filesystem.
	if err := run("mkfs.ext4", "-L", name, "/dev/mapper/"+mapperName); err != nil {
		_ = run("cryptsetup", "luksClose", mapperName)
		_ = run("lvremove", "-f", lvPath)
		return nil, fmt.Errorf("volume: mkfs.ext4 failed: %w", err)
	}

	// 5. Mount.
	if err := os.MkdirAll(mountPath, 0700); err != nil {
		_ = run("cryptsetup", "luksClose", mapperName)
		_ = run("lvremove", "-f", lvPath)
		return nil, fmt.Errorf("volume: failed to create mount point: %w", err)
	}
	if err := run("mount", "/dev/mapper/"+mapperName, mountPath); err != nil {
		_ = run("cryptsetup", "luksClose", mapperName)
		_ = run("lvremove", "-f", lvPath)
		return nil, fmt.Errorf("volume: mount failed: %w", err)
	}

	m.log.Info("encrypted volume ready",
		zap.String("container", name),
		zap.String("mount", mountPath),
		zap.String("key_origin", keyOrigin),
	)

	return &VolumeInfo{
		Name:      name,
		KeyOrigin: keyOrigin,
		MountPath: mountPath,
		LVName:    lvName,
	}, nil
}

// Close unmounts and locks a container's encrypted volume without
// removing the LV.  This is used during container unload.
func (m *Manager) Close(name string) error {
	mountPath := MountBase + "/" + name
	mapperName := "container-" + name

	m.log.Info("closing encrypted volume",
		zap.String("container", name),
	)

	// Unmount.
	if err := run("umount", mountPath); err != nil {
		m.log.Warn("umount failed (may already be unmounted)", zap.Error(err))
	}
	_ = os.Remove(mountPath)

	// Close LUKS.
	if err := run("cryptsetup", "luksClose", mapperName); err != nil {
		return fmt.Errorf("volume: luksClose failed: %w", err)
	}

	return nil
}

// Remove closes and destroys a container's encrypted volume completely.
// The LV is removed — all data is permanently lost.
func (m *Manager) Remove(name string) error {
	if err := m.Close(name); err != nil {
		// Log but continue with LV removal.
		m.log.Warn("close failed during remove, continuing with LV removal",
			zap.String("container", name), zap.Error(err))
	}

	lvPath := "/dev/" + VGName + "/vol-" + name

	m.log.Info("removing logical volume",
		zap.String("container", name),
		zap.String("lv", lvPath),
	)

	if err := run("lvremove", "-f", lvPath); err != nil {
		return fmt.Errorf("volume: lvremove failed: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// randomKey generates a 256-bit random key encoded as base64.
func randomKey() (string, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 32)
	if _, err := f.Read(buf); err != nil {
		return "", err
	}

	// Use hex encoding for simplicity (cryptsetup reads raw bytes from stdin).
	return fmt.Sprintf("%x", buf), nil
}

// run executes a command and returns an error with combined output on failure.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}

// runStdin executes a command with data written to stdin.
func runStdin(stdin string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}
