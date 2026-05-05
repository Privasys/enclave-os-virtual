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
	cmd := exec.Command("vgs", "--noheadings", "-o", "vg_name", VGName)
	cmd.Env = lvmEnv(os.Environ(), "vgs")
	return cmd.Run() == nil
}

// Create provisions (or re-attaches to) a per-container encrypted volume:
//
//	First time:
//	  1. Create an LVM LV in the "containers" VG
//	  2. Format it with LUKS2 + dm-integrity (hmac-sha256)
//	  3. Open (decrypt) the LUKS volume
//	  4. Create an ext4 filesystem
//	  5. Mount at /run/containers/<name>
//
//	Subsequent (after manager restart / host reboot — registry replay):
//	  • LV already exists → skip step 1
//	  • mapper already open (manager restart only) → reuse, skip step 3
//	  • ext4 already present → skip mkfs (step 4)
//	  • mount already there → reuse, skip step 5
//
// This idempotency is REQUIRED for self-healing: on host reboot the LV
// persists on disk, the registry replays the LoadRequest with the same
// `storage_key`, and we must reattach to the existing encrypted volume
// rather than wipe it.  Wiping would also defeat the whole point of
// persistent /data.
//
// If key is empty, a random 256-bit key is generated (enclave-generated).
// Returns VolumeInfo describing the (re)attached volume.
func (m *Manager) Create(name, size, key string) (*VolumeInfo, error) {
	if size == "" {
		size = DefaultSize
	}

	lvName := "vol-" + name
	mapperName := "container-" + name
	mountPath := MountBase + "/" + name
	lvPath := "/dev/" + VGName + "/" + lvName
	mapperPath := "/dev/mapper/" + mapperName

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

	// 1. Create LV (skip if already present from a previous incarnation).
	lvExisted := false
	if _, err := os.Stat(lvPath); err == nil {
		lvExisted = true
		m.log.Info("LV already exists — reattaching", zap.String("lv", lvName))
	} else {
		if err := run("lvcreate", "-L", size, "-n", lvName, VGName, "-y"); err != nil {
			return nil, fmt.Errorf("volume: lvcreate failed: %w", err)
		}
	}

	// 2. LUKS format — only on freshly created LVs.
	//
	// NOTE: aes-xts-plain64 is NOT an AEAD cipher; cryptsetup rejects
	// `--integrity aead` with "Cipher aes-xts-plain64 (key size 512 bits)
	// is not available". Use `--integrity hmac-sha256` instead, which
	// gives per-sector authenticated encryption via dm-integrity tags.
	// (Same fix as the host data partition luks-setup script.)
	if !lvExisted {
		if err := runStdin(key, "cryptsetup", "luksFormat",
			"--type", "luks2",
			"--cipher", "aes-xts-plain64",
			"--key-size", "512",
			"--hash", "sha256",
			"--integrity", "hmac-sha256",
			"--iter-time", "2000",
			"--key-file=-",
			"--batch-mode",
			lvPath,
		); err != nil {
			// Clean up the LV on failure.
			_ = run("lvremove", "-f", lvPath)
			return nil, fmt.Errorf("volume: luksFormat failed: %w", err)
		}
	}

	// 3. Open LUKS (skip if mapper already exists from prior open).
	mapperExisted := false
	if _, err := os.Stat(mapperPath); err == nil {
		mapperExisted = true
		m.log.Info("LUKS mapper already open — reusing", zap.String("mapper", mapperName))
	} else {
		if err := runStdin(key, "cryptsetup", "luksOpen",
			lvPath, mapperName, "--key-file=-",
		); err != nil {
			if !lvExisted {
				_ = run("lvremove", "-f", lvPath)
			}
			return nil, fmt.Errorf("volume: luksOpen failed: %w", err)
		}
	}

	// 4. Create ext4 filesystem — only on freshly formatted volumes.
	if !lvExisted {
		if err := run("mkfs.ext4", "-L", name, mapperPath); err != nil {
			if !mapperExisted {
				_ = run("cryptsetup", "luksClose", mapperName)
			}
			_ = run("lvremove", "-f", lvPath)
			return nil, fmt.Errorf("volume: mkfs.ext4 failed: %w", err)
		}
	}

	// 5. Mount (skip if already mounted).
	if err := os.MkdirAll(mountPath, 0700); err != nil {
		if !mapperExisted {
			_ = run("cryptsetup", "luksClose", mapperName)
		}
		if !lvExisted {
			_ = run("lvremove", "-f", lvPath)
		}
		return nil, fmt.Errorf("volume: failed to create mount point: %w", err)
	}
	if !isMountpoint(mountPath) {
		if err := run("mount", mapperPath, mountPath); err != nil {
			if !mapperExisted {
				_ = run("cryptsetup", "luksClose", mapperName)
			}
			if !lvExisted {
				_ = run("lvremove", "-f", lvPath)
			}
			return nil, fmt.Errorf("volume: mount failed: %w", err)
		}
	} else {
		m.log.Info("mountpoint already mounted — reusing", zap.String("path", mountPath))
	}

	m.log.Info("encrypted volume ready",
		zap.String("container", name),
		zap.String("mount", mountPath),
		zap.String("key_origin", keyOrigin),
		zap.Bool("reattached", lvExisted),
	)

	return &VolumeInfo{
		Name:      name,
		KeyOrigin: keyOrigin,
		MountPath: mountPath,
		LVName:    lvName,
	}, nil
}

// isMountpoint returns true if `path` is a mount point.
func isMountpoint(path string) bool {
	out, err := exec.Command("mountpoint", "-q", path).CombinedOutput()
	if err == nil {
		return true
	}
	// `mountpoint` returns 1 when not a mountpoint; any other error is
	// treated as "not a mountpoint" (e.g. tool missing). The captured
	// output is intentionally discarded.
	_ = out
	return false
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
//
// For LVM commands (lvcreate, lvremove, vgs, pvs), if LVM_SYSTEM_DIR is not
// already set in the environment, point it at /run/lvm-conf so that the LVM
// archive/backup directories live on a writable tmpfs (the root filesystem
// is read-only erofs in production, which makes the default
// /etc/lvm/{archive,backup} unwritable and causes lvcreate to fail with
// "Internal error: Failed command did not use log_error" / status 5).
// The /run/lvm-conf directory is provisioned by container-volumes.service.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = lvmEnv(os.Environ(), name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}

// runStdin executes a command with data written to stdin.
func runStdin(stdin string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = lvmEnv(os.Environ(), name)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}

// lvmEnv augments env with LVM_SYSTEM_DIR=/run/lvm-conf for LVM tools when
// not already set. Non-LVM tools get env unchanged.
func lvmEnv(env []string, name string) []string {
	switch name {
	case "lvcreate", "lvremove", "lvs", "vgcreate", "vgs", "pvcreate", "pvs":
	default:
		return env
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "LVM_SYSTEM_DIR=") {
			return env
		}
	}
	return append(env, "LVM_SYSTEM_DIR=/run/lvm-conf")
}
