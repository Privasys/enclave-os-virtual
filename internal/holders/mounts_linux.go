//go:build linux

package holders

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// A holder's folder lives on the app's volume, which the container sees at
// /data through an rslave bind of the volume's mount point (the EXPOSED
// path). For a read-only grant the folder is bound onto itself read-only on
// that path, so the container sees it read-only and, holding no
// CAP_SYS_ADMIN, cannot undo it. The runtime does its own work (the key,
// ownership, the holder's file API) through a PRIVATE writable view of the
// volume that is never propagated into any container.

// EnsureView makes view a private, writable bind of src (idempotent).
func EnsureView(src, view string) error {
	if same, err := sameDir(src, view); err == nil && same {
		return nil
	}
	if err := os.MkdirAll(view, 0o700); err != nil {
		return fmt.Errorf("holders: view dir: %w", err)
	}
	if err := unix.Mount(src, view, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("holders: bind view: %w", err)
	}
	if err := unix.Mount("", view, "", unix.MS_PRIVATE, ""); err != nil {
		_ = unix.Unmount(view, unix.MNT_DETACH)
		return fmt.Errorf("holders: private view: %w", err)
	}
	return nil
}

// BindReadOnly binds dir onto itself read-only (idempotent: a dir that is
// already a read-only mount point is left as is).
func BindReadOnly(dir string) error {
	if ro, err := isReadOnlyMount(dir); err == nil && ro {
		return nil
	}
	if err := unix.Mount(dir, dir, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("holders: bind %s: %w", dir, err)
	}
	if err := unix.Mount("", dir, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		_ = unix.Unmount(dir, unix.MNT_DETACH)
		return fmt.Errorf("holders: remount %s read-only: %w", dir, err)
	}
	return nil
}

// Unbind removes a read-only bind made by BindReadOnly (a dir that is not a
// separate mount is left alone).
func Unbind(dir string) error {
	for {
		ro, err := isReadOnlyMount(dir)
		if err != nil || !ro {
			return nil
		}
		if err := unix.Unmount(dir, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("holders: unbind %s: %w", dir, err)
		}
	}
}

// isReadOnlyMount reports whether dir sits on a read-only mount. The app
// volume itself is mounted writable, so under it a read-only mount can only
// be the bind BindReadOnly made.
func isReadOnlyMount(dir string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.ST_RDONLY != 0, nil
}

// sameDir reports whether a and b are the same directory (a bind in place).
func sameDir(a, b string) (bool, error) {
	var sa, sb unix.Stat_t
	if err := unix.Stat(a, &sa); err != nil {
		return false, err
	}
	if err := unix.Stat(b, &sb); err != nil {
		return false, err
	}
	return sa.Dev == sb.Dev && sa.Ino == sb.Ino, nil
}
