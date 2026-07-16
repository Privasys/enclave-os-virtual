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
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
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
// lvremoveAudit removes a per-container LV, loudly. Every per-container volume
// deletion is logged at WARN so accidental data loss is always traceable in the
// journal (these calls are rollbacks after a volume-creation step failed).
func (m *Manager) lvremoveAudit(lvPath string) {
	m.log.Warn("removing per-container LV (rollback after volume-creation failure)",
		zap.String("lv", lvPath))
	_ = run("lvremove", "-f", lvPath)
}

// expectExisting=true means the DEK was reconstructed from the constellation
// (the key already existed), so an on-disk LV MUST be present to reattach. If it
// is absent, Create refuses rather than mkfs'ing a fresh empty volume — that
// would silently mask data loss. Pass false on a first deploy (key freshly
// created), where a fresh volume is correct.
func (m *Manager) Create(name, size, key string, expectExisting bool) (*VolumeInfo, error) {
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
		// Data-loss guard (fail closed): the key was reconstructed, so data was
		// expected here, but the LV is gone. Do NOT create a fresh empty volume
		// — that would silently mask the loss. Surface it loudly instead.
		if expectExisting {
			m.log.Error("vault-backed volume expected existing data but its LV is absent — refusing to create an empty volume",
				zap.String("container", name), zap.String("lv", lvName))
			return nil, fmt.Errorf("volume: %q expects existing data (key reconstructed) but LV %s is absent — refusing to create an empty volume that would mask data loss", name, lvName)
		}
		if err := run("lvcreate", "-L", size, "-n", lvName, VGName, "-y"); err != nil {
			// The pool may simply not have grown into a disk the cloud-ops
			// agent already resized: rescan the PV's device and pvresize,
			// then retry once. Capacity is bought just-in-time (GCP-side PD
			// resize is online); this is the in-guest half.
			m.log.Warn("lvcreate failed — rescanning the containers pool for a grown disk and retrying",
				zap.String("lv", lvName), zap.String("size", size), zap.Error(err))
			m.growPool()
			if err := run("lvcreate", "-L", size, "-n", lvName, VGName, "-y"); err != nil {
				return nil, fmt.Errorf("volume: lvcreate failed (pool exhausted? grow the containers disk via cloud-ops, it is picked up automatically): %w", err)
			}
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
			m.lvremoveAudit(lvPath)
			return nil, fmt.Errorf("volume: luksFormat failed: %w", err)
		}
	}

	// 3. Open LUKS (skip if mapper already exists from prior open).
	mapperExisted := false
	staleReformatted := false
	if _, err := os.Stat(mapperPath); err == nil {
		mapperExisted = true
		m.log.Info("LUKS mapper already open — reusing", zap.String("mapper", mapperName))
	} else {
		if err := runStdin(key, "cryptsetup", "luksOpen",
			lvPath, mapperName, "--key-file=-",
		); err != nil {
			// STALE-LV recovery. A key that was freshly CREATED (not
			// reconstructed) means every vault reported the handle absent, so
			// nothing was ever encrypted under it. If an LV nonetheless exists
			// and this key cannot open it, that LV belongs to a superseded key
			// generation which no longer exists (e.g. a clean vault-constellation
			// cutover discarded it) — its data is ALREADY unrecoverable. Reformat
			// instead of failing forever: a production enclave has no SSH, so an
			// operator cannot lvremove it by hand, and the app would be stranded.
			// The expectExisting guard keeps the reconstructed-key path (real
			// data) failing closed exactly as before.
			if lvExisted && !expectExisting {
				m.log.Warn("existing LV cannot be opened with the freshly created key — treating it as STALE and reformatting (its key generation is gone; the data was already unrecoverable)",
					zap.String("container", name), zap.String("lv", lvName), zap.Error(err))
				if ferr := runStdin(key, "cryptsetup", "luksFormat",
					"--type", "luks2",
					"--cipher", "aes-xts-plain64",
					"--key-size", "512",
					"--hash", "sha256",
					"--integrity", "hmac-sha256",
					"--iter-time", "2000",
					"--key-file=-",
					"--batch-mode",
					lvPath,
				); ferr != nil {
					return nil, fmt.Errorf("volume: stale LV reformat failed: %w", ferr)
				}
				if oerr := runStdin(key, "cryptsetup", "luksOpen",
					lvPath, mapperName, "--key-file=-",
				); oerr != nil {
					return nil, fmt.Errorf("volume: luksOpen after stale reformat failed: %w", oerr)
				}
				staleReformatted = true
			} else {
				if !lvExisted {
					m.lvremoveAudit(lvPath)
				}
				return nil, fmt.Errorf("volume: luksOpen failed: %w", err)
			}
		}
	}

	// 4. Create ext4 filesystem — on freshly formatted volumes, and on a
	// stale LV we just reformatted (it holds no readable filesystem).
	if !lvExisted || staleReformatted {
		if err := run("mkfs.ext4", "-L", name, mapperPath); err != nil {
			if !mapperExisted {
				_ = run("cryptsetup", "luksClose", mapperName)
			}
			m.lvremoveAudit(lvPath)
			return nil, fmt.Errorf("volume: mkfs.ext4 failed: %w", err)
		}
	}

	// 5. Mount (skip if already mounted).
	if err := os.MkdirAll(mountPath, 0700); err != nil {
		if !mapperExisted {
			_ = run("cryptsetup", "luksClose", mapperName)
		}
		if !lvExisted {
			m.lvremoveAudit(lvPath)
		}
		return nil, fmt.Errorf("volume: failed to create mount point: %w", err)
	}
	if !isMountpoint(mountPath) {
		if err := run("mount", mapperPath, mountPath); err != nil {
			if !mapperExisted {
				_ = run("cryptsetup", "luksClose", mapperName)
			}
			if !lvExisted {
				m.lvremoveAudit(lvPath)
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
// Key rotation (KEK re-wrap)
// ---------------------------------------------------------------------------
//
// The volume key handed in by the caller is a LUKS2 keyslot passphrase, NOT
// the cipher key on disk: the data is encrypted under the LUKS2 master key
// (generated at luksFormat, wrapped in the header). So rotating the key is a
// re-wrap, not a re-encrypt — add the new passphrase to a free keyslot, then
// kill the slot holding the old one. The master key, and therefore the data,
// never moves; the operation is online (it touches the LUKS header on the LV,
// not the active dm-crypt mapping), so the volume may stay mounted throughout.
// See the key-rotation design.

// AddKey adds newKey to a free LUKS keyslot on the container's volume,
// authorising the change with existingKey. After this call BOTH keys unlock
// the volume — the caller advances any key pointer here, then RemoveKey's the
// old one, so no single failure can leave the volume unopenable.
//
// Both keys are passed to cryptsetup over pipes exposed to the child as
// /proc/self/fd/3 (existing) and /proc/self/fd/4 (new); key material is never
// written to a file (even tmpfs). cryptsetup reads each fd as a key file
// verbatim (no newline stripping — matching how the volume was formatted from
// stdin in Create).
func (m *Manager) AddKey(name, existingKey, newKey string) error {
	lvPath := "/dev/" + VGName + "/vol-" + name
	if _, err := os.Stat(lvPath); err != nil {
		return fmt.Errorf("volume: AddKey: LV %s not present: %w", lvPath, err)
	}
	m.log.Info("adding LUKS keyslot (key rotation)", zap.String("container", name))
	return runCryptsetupTwoKeys(existingKey, newKey,
		"luksAddKey",
		lvPath,
		"/proc/self/fd/4",            // new key to add (positional)
		"--key-file=/proc/self/fd/3", // existing key (authorises the change)
		"--batch-mode",
	)
}

// RemoveKey kills the LUKS keyslot that `key` unlocks on the container's
// volume. Used to retire the old key after AddKey + the pointer advance.
func (m *Manager) RemoveKey(name, key string) error {
	lvPath := "/dev/" + VGName + "/vol-" + name
	if _, err := os.Stat(lvPath); err != nil {
		return fmt.Errorf("volume: RemoveKey: LV %s not present: %w", lvPath, err)
	}
	m.log.Info("removing LUKS keyslot (key rotation)", zap.String("container", name))
	return runStdin(key, "cryptsetup", "luksRemoveKey", lvPath, "--key-file=-", "--batch-mode")
}

// Rekey re-wraps the volume's master key from oldKey to newKey in one call
// (AddKey then RemoveKey). The live rotation flow does NOT use this — it splits
// the two halves around the key-pointer advance so a crash mid-rotation always
// leaves the volume openable (see the key-rotation design). Rekey is the
// single-call convenience for tests and for callers that own both ends.
func (m *Manager) Rekey(name, oldKey, newKey string) error {
	if err := m.AddKey(name, oldKey, newKey); err != nil {
		return fmt.Errorf("volume: rekey add: %w", err)
	}
	if err := m.RemoveKey(name, oldKey); err != nil {
		// The new slot is in place; the volume still opens with newKey. The
		// stale old slot is harmless but should be retried.
		return fmt.Errorf("volume: rekey remove old (new key is live; retry retire): %w", err)
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
// growPool picks up an out-of-band resize of the containers pool disk (the
// cloud-ops agent grows the PD online on the cloud side): rescan each of the
// VG's physical devices so the kernel sees the new size, then pvresize so LVM
// can allocate from it. Best-effort — the caller retries lvcreate and reports
// the real failure if capacity is still short.
func (m *Manager) growPool() {
	cmd := exec.Command("pvs", "--noheadings", "-o", "pv_name", "--select", "vg_name="+VGName)
	cmd.Env = lvmEnv(os.Environ(), "pvs")
	out, err := cmd.CombinedOutput()
	if err != nil {
		m.log.Warn("growPool: pvs failed", zap.Error(err), zap.String("out", string(out)))
		return
	}
	for _, pv := range strings.Fields(string(out)) {
		// /dev/sdb1 -> sdb, /dev/nvme0n1p1 -> nvme0n1 (partition suffix off);
		// bare-disk PVs pass through unchanged.
		base := strings.TrimPrefix(pv, "/dev/")
		if i := strings.LastIndexByte(base, 'p'); i > 0 && strings.ContainsAny(base[i+1:], "0123456789") && strings.HasPrefix(base, "nvme") {
			base = base[:i]
		} else {
			base = strings.TrimRight(base, "0123456789")
		}
		rescan := "/sys/class/block/" + base + "/device/rescan"
		if err := os.WriteFile(rescan, []byte("1"), 0o200); err != nil {
			m.log.Debug("growPool: rescan not available", zap.String("path", rescan), zap.Error(err))
		}
		if err := run("pvresize", pv); err != nil {
			m.log.Warn("growPool: pvresize failed", zap.String("pv", pv), zap.Error(err))
		} else {
			m.log.Info("growPool: pvresize ok", zap.String("pv", pv))
		}
	}
}

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

// runCryptsetupTwoKeys runs `cryptsetup` with two distinct keys delivered over
// pipes, never the filesystem. The child receives the read ends as fd 3 (the
// existing/authorising key) and fd 4 (the new key); the command refers to them
// as /proc/self/fd/3 and /proc/self/fd/4. cryptsetup treats a non-seekable fd
// keyfile exactly like stdin (`--key-file=-`): it reads to EOF without newline
// stripping, so the bytes must match how the slot was originally written.
func runCryptsetupTwoKeys(existingKey, newKey string, args ...string) error {
	oldR, oldW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe (existing key): %w", err)
	}
	newR, newW, err := os.Pipe()
	if err != nil {
		oldR.Close()
		oldW.Close()
		return fmt.Errorf("pipe (new key): %w", err)
	}

	cmd := exec.Command("cryptsetup", args...)
	cmd.Env = os.Environ()
	// ExtraFiles[0] -> child fd 3 (existing), ExtraFiles[1] -> child fd 4 (new).
	cmd.ExtraFiles = []*os.File{oldR, newR}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		oldR.Close()
		oldW.Close()
		newR.Close()
		newW.Close()
		return fmt.Errorf("cryptsetup start: %w", err)
	}
	// The child holds its own dup'd read ends now; close ours so the writes
	// below are the only holders and EOF propagates when we finish.
	oldR.Close()
	newR.Close()

	// Write each key (no trailing newline) and close the write end to signal
	// EOF to cryptsetup.
	_, e1 := io.WriteString(oldW, existingKey)
	c1 := oldW.Close()
	_, e2 := io.WriteString(newW, newKey)
	c2 := newW.Close()

	werr := cmd.Wait()
	if werr != nil {
		return fmt.Errorf("cryptsetup %s: %w\n%s", strings.Join(args, " "), werr, out.String())
	}
	for _, e := range []error{e1, c1, e2, c2} {
		if e != nil {
			return fmt.Errorf("feed key material: %w", e)
		}
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
