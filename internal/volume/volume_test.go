package volume

import (
	"encoding/binary"
	"testing"
)

// The mkfs decision hangs on this check: read it wrong and the manager either
// reformats a volume that holds real data, or leaves an app permanently
// undeployable because it keeps skipping mkfs on a volume that has none.
func TestHasExt4Magic(t *testing.T) {
	// A freshly luksFormat'd volume that mkfs never reached: readable, zeroed,
	// no superblock. This is the case that used to strand an app forever.
	t.Run("zeroed volume has no filesystem", func(t *testing.T) {
		if hasExt4Magic(make([]byte, 4096)) {
			t.Fatal("reported a filesystem on a zeroed volume")
		}
	})

	t.Run("ext4 superblock is recognised", func(t *testing.T) {
		head := make([]byte, 4096)
		binary.LittleEndian.PutUint16(head[1024+0x38:], 0xEF53)
		if !hasExt4Magic(head) {
			t.Fatal("failed to recognise the ext4 magic at s_magic")
		}
	})

	// The magic must be read at s_magic, not merely found somewhere: a byte
	// pattern that happens to appear elsewhere is not a filesystem.
	t.Run("magic at the wrong offset is not a filesystem", func(t *testing.T) {
		head := make([]byte, 4096)
		binary.LittleEndian.PutUint16(head[0:], 0xEF53)         // device head
		binary.LittleEndian.PutUint16(head[1024:], 0xEF53)      // superblock start
		binary.LittleEndian.PutUint16(head[1024+0x36:], 0xEF53) // two bytes early
		if hasExt4Magic(head) {
			t.Fatal("matched the magic away from s_magic")
		}
	})

	// Byte order matters: the magic is little-endian, so the swapped value must
	// not match.
	t.Run("big-endian magic does not match", func(t *testing.T) {
		head := make([]byte, 4096)
		binary.BigEndian.PutUint16(head[1024+0x38:], 0xEF53)
		if hasExt4Magic(head) {
			t.Fatal("matched a big-endian magic")
		}
	})

	// A short read must never be reported as a filesystem — that would be the
	// unsafe direction (skip mkfs, fail to mount forever).
	t.Run("short buffer is not a filesystem", func(t *testing.T) {
		for _, n := range []int{0, 512, 1024, 1024 + 0x38 + 1} {
			if hasExt4Magic(make([]byte, n)) {
				t.Fatalf("reported a filesystem from a %d-byte buffer", n)
			}
		}
	})
}
