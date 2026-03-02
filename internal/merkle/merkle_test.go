package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestEmptyTree(t *testing.T) {
	tree := New(nil)
	// Root of an empty tree is SHA-256 of nothing.
	expected := sha256.Sum256(nil)
	if tree.Root() != expected {
		t.Fatalf("empty tree root mismatch: got %x, want %x", tree.Root(), expected)
	}
}

func TestSingleLeaf(t *testing.T) {
	tree := New([]Leaf{
		{Name: "test", Data: []byte("hello")},
	})
	leafHash := sha256.Sum256([]byte("hello"))
	expectedRoot := sha256.Sum256(leafHash[:])
	if tree.Root() != expectedRoot {
		t.Fatalf("single leaf root mismatch: got %x, want %x", tree.Root(), expectedRoot)
	}
}

func TestDeterministicOrdering(t *testing.T) {
	a := New([]Leaf{
		{Name: "b", Data: []byte("second")},
		{Name: "a", Data: []byte("first")},
	})
	b := New([]Leaf{
		{Name: "a", Data: []byte("first")},
		{Name: "b", Data: []byte("second")},
	})
	if a.Root() != b.Root() {
		t.Fatal("trees with same leaves in different order should have same root")
	}
}

func TestAbsentLeaf(t *testing.T) {
	tree := New([]Leaf{
		{Name: "present", Data: []byte("data")},
		{Name: "absent", Data: nil},
	})
	hashes := tree.LeafHashes()
	// "absent" sorts before "present", so index 0 should be zero.
	if hashes[0] != [32]byte{} {
		t.Fatal("absent leaf should have zero hash")
	}
}

func TestManifestRoundTrip(t *testing.T) {
	tree := New([]Leaf{
		{Name: "ca_cert", Data: []byte("cert-data")},
		{Name: "container.image", Data: []byte("sha256:abc")},
	})

	manifest := tree.Manifest()
	if len(manifest) == 0 {
		t.Fatal("manifest should not be empty")
	}

	// Parse: count.
	count := binary.LittleEndian.Uint32(manifest[:4])
	if count != 2 {
		t.Fatalf("expected 2 entries, got %d", count)
	}

	// The last 32 bytes should be the root.
	var rootFromManifest [32]byte
	copy(rootFromManifest[:], manifest[len(manifest)-32:])
	if rootFromManifest != tree.Root() {
		t.Fatal("root in manifest does not match tree root")
	}
}
