package volume

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

// SnapshotMountBase is where a volume snapshot is mounted read-only while a
// backup reads it.
const SnapshotMountBase = "/run/backups"

// snapshotCOW sizes the copy-on-write area of a backup snapshot: it absorbs the
// origin's writes for as long as the backup reads the snapshot. A snapshot whose
// COW fills up is invalidated by LVM and the backup fails cleanly (reads return
// EIO); it never affects the origin.
const snapshotCOW = "20%ORIGIN"

// Snapshot is a point-in-time, read-only view of a container volume, opened
// for a backup. Close releases it.
type Snapshot struct {
	m          *Manager
	name       string
	lvPath     string
	mapperName string

	// MountPath is where the snapshot's filesystem is mounted read-only.
	MountPath string
}

func snapshotNames(name string) (lvName, lvPath, mapperName, mountPath string) {
	lvName = "snap-" + name
	return lvName, "/dev/" + VGName + "/" + lvName, "backup-" + name, SnapshotMountBase + "/" + name
}

// OpenSnapshot takes an LVM snapshot of a container's volume and opens it
// read-only at /run/backups/<name>:
//
//  1. freeze the origin filesystem (when mounted), so the snapshot holds a
//     clean filesystem instead of a crash image;
//  2. lvcreate -s of the encrypted LV (the snapshot is ciphertext, like the
//     origin), then thaw immediately: the app is paused only for this step;
//  3. luksOpen the snapshot with the volume key, read-write on the COW so the
//     dm-integrity and ext4 journals can replay if the freeze was not possible;
//  4. mount the filesystem read-only.
//
// key is the volume's LUKS passphrase (the vault DEK). The snapshot carries the
// origin's LUKS header, so the same key opens it.
func (m *Manager) OpenSnapshot(name, key string) (*Snapshot, error) {
	originLV := "/dev/" + VGName + "/vol-" + name
	if _, err := os.Stat(originLV); err != nil {
		return nil, fmt.Errorf("volume: %q has no LV on this host", name)
	}
	lvName, lvPath, mapperName, mountPath := snapshotNames(name)
	s := &Snapshot{m: m, name: name, lvPath: lvPath, mapperName: mapperName, MountPath: mountPath}

	// A previous backup that died mid-way leaves its snapshot behind; clear it,
	// so this one starts from the origin's current state.
	if _, err := os.Stat(lvPath); err == nil {
		m.log.Warn("stale backup snapshot found — removing it first", zap.String("container", name))
		if err := s.Close(); err != nil {
			return nil, fmt.Errorf("volume: remove stale snapshot of %q: %w", name, err)
		}
	}

	originMount := MountBase + "/" + name
	frozen := false
	if isMountpoint(originMount) {
		if err := run("fsfreeze", "-f", originMount); err != nil {
			// Not fatal: the snapshot is then crash-consistent, and step 3
			// replays the journals like after a power cut.
			m.log.Warn("fsfreeze failed — the snapshot will be crash-consistent",
				zap.String("container", name), zap.Error(err))
		} else {
			frozen = true
		}
	}
	err := run("lvcreate", "-s", "-l", snapshotCOW, "-n", lvName, originLV, "-y")
	if err != nil {
		m.growPool()
		err = run("lvcreate", "-s", "-l", snapshotCOW, "-n", lvName, originLV, "-y")
	}
	if frozen {
		if uerr := run("fsfreeze", "-u", originMount); uerr != nil {
			m.log.Error("fsfreeze thaw failed — the app's volume may be stuck frozen",
				zap.String("container", name), zap.Error(uerr))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("volume: snapshot of %q failed (no free space in the containers pool for the copy-on-write area?): %w", name, err)
	}

	// --disable-keyring: the snapshot carries the origin's LUKS UUID, so a
	// keyring entry for it would share the origin's description. Keep the
	// snapshot's key out of the keyring entirely.
	if err := runStdin(key, "cryptsetup", "luksOpen", lvPath, mapperName,
		"--key-file=-", "--disable-keyring"); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("volume: open snapshot of %q: %w", name, err)
	}
	if err := os.MkdirAll(mountPath, 0o700); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("volume: snapshot mount point: %w", err)
	}
	if err := run("mount", "-o", "ro,nosuid,nodev,noexec", "/dev/mapper/"+mapperName, mountPath); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("volume: mount snapshot of %q: %w", name, err)
	}
	m.log.Info("backup snapshot opened",
		zap.String("container", name), zap.Bool("frozen", frozen), zap.String("mount", mountPath))
	return s, nil
}

// Close unmounts, closes and removes the snapshot. Safe on a partly opened
// snapshot; every step that applies is attempted.
func (s *Snapshot) Close() error {
	var errs []error
	if isMountpoint(s.MountPath) {
		if err := run("umount", s.MountPath); err != nil {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(s.MountPath)
	if _, err := os.Stat("/dev/mapper/" + s.mapperName); err == nil {
		if err := run("cryptsetup", "luksClose", s.mapperName); err != nil {
			errs = append(errs, err)
		}
	}
	if _, err := os.Stat(s.lvPath); err == nil {
		if err := run("lvremove", "-f", s.lvPath); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("volume: close snapshot of %q: %w", s.name, errors.Join(errs...))
	}
	s.m.log.Info("backup snapshot removed", zap.String("container", s.name))
	return nil
}

// isSnapshotLV reports whether an LV on the containers VG is a backup snapshot
// rather than a container volume.
func isSnapshotLV(lvName string) bool {
	return strings.HasPrefix(lvName, "snap-")
}
