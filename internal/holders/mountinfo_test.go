package holders

import "testing"

// The lines below are the ones 145-dev showed live: the host's bind was
// read-only, the container's propagated copy writable. Only the container's
// own view decides.
func TestMountInfoReadOnlyReadsTheMountItself(t *testing.T) {
	const key = "9261a17bc4fd0bc52ae504fa7ae837c5"
	const at = "/data/holders/" + key
	writable := "717 702 252:30 / /data rw,relatime master:371 - ext4 /dev/mapper/c rw\n" +
		"498 608 252:20 /holders/" + key + " " + at + " rw,relatime master:155 - ext4 /dev/mapper/c rw\n"
	readOnly := "717 702 252:30 / /data rw,relatime master:371 - ext4 /dev/mapper/c rw\n" +
		"498 608 252:20 /holders/" + key + " " + at + " ro,relatime master:155 - ext4 /dev/mapper/c rw\n"
	noOwnMount := "717 702 252:30 / /data ro,relatime master:371 - ext4 /dev/mapper/c rw\n"
	stackedLastWritable := readOnly + "499 498 252:20 /holders/" + key + " " + at + " rw,relatime - ext4 /dev/mapper/c rw\n"
	otherKey := "498 608 252:20 /holders/x " + at + "0 ro,relatime - ext4 /dev/mapper/c rw\n"

	for name, c := range map[string]struct {
		info string
		want bool
	}{
		"propagated writable (the 145 defect)": {writable, false},
		"read-only bind":                       {readOnly, true},
		"no mount of its own, even under ro":   {noOwnMount, false},
		"topmost of a stack is writable":       {stackedLastWritable, false},
		"a longer path is not this folder":     {otherKey, false},
		"empty":                                {"", false},
	} {
		if got := mountInfoReadOnly([]byte(c.info), at); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	if !mountInfoReadOnly([]byte("1 2 0:1 / /data/a\\040b ro - tmpfs x rw\n"), "/data/a b") {
		t.Error("an escaped space in the mount point was not read")
	}
}
