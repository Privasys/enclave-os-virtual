package holders

import (
	"strconv"
	"strings"
)

// MountInfoReadOnly reports whether, in a /proc/<pid>/mountinfo listing,
// the topmost mount AT mountPoint exists and carries the per-mount "ro"
// option. A path that is not its own mount point is not read-only by this
// test, whatever its parent is: the read-only bind is always its own mount.
// The last matching line wins (the kernel lists stacked mounts in order).
func MountInfoReadOnly(mountinfo []byte, mountPoint string) bool {
	ro, found := false, false
	for _, line := range strings.Split(string(mountinfo), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || unescapeMountInfo(f[4]) != mountPoint {
			continue
		}
		found = true
		ro = false
		for _, opt := range strings.Split(f[5], ",") {
			if opt == "ro" {
				ro = true
			}
		}
	}
	return found && ro
}

// unescapeMountInfo undoes the kernel's octal escapes (\040 for a space,
// \011, \012, \134) in a mountinfo path field.
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
