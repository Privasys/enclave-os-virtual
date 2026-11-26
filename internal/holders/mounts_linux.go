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

// BindReadOnly binds dir onto itself read-only, as a mount that is ALREADY
// read-only when it is attached: open_tree clones dir detached,
// mount_setattr makes the clone read-only, move_mount attaches it. Mount
// propagation copies the mount with its read-only flag into every slave
// (the containers' /data). Binding first and remounting read-only after
// does NOT work: the bind propagates writable and a remount never
// propagates, so the container kept a writable copy. There is no fallback
// to that method: if the new mount API fails, the bind fails, and a
// read-only open is refused.
//
// Any earlier bind on dir is removed first, so a bind made the old way is
// never kept just because the host's copy looks read-only.
func BindReadOnly(dir string) error {
	if err := Unbind(dir); err != nil {
		return err
	}
	fd, err := unix.OpenTree(unix.AT_FDCWD, dir, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		return fmt.Errorf("holders: open_tree %s: %w", dir, err)
	}
	defer unix.Close(fd)
	attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}
	if err := unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH, &attr); err != nil {
		return fmt.Errorf("holders: mount_setattr %s read-only: %w", dir, err)
	}
	if err := unix.MoveMount(fd, "", unix.AT_FDCWD, dir, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("holders: move_mount %s: %w", dir, err)
	}
	if ro, err := isReadOnlyMount(dir); err != nil || !ro {
		_ = unix.Unmount(dir, unix.MNT_DETACH)
		return fmt.Errorf("holders: %s is not read-only after the bind", dir)
	}
	return nil
}

// ContainerViewReadOnly reports whether the container whose init process is
// pid sees containerPath as its own read-only mount, read from
// /proc/<pid>/mountinfo (no setns needed).
func ContainerViewReadOnly(pid int, containerPath string) (bool, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return false, fmt.Errorf("holders: container mountinfo: %w", err)
	}
	return MountInfoReadOnly(data, containerPath), nil
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
