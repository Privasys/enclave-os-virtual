// Package merkle implements a deterministic Merkle tree for configuration
// attestation. It mirrors the design used in Enclave OS (Mini) (SGX) but
// operates on container workload configurations instead of WASM modules.
//
// The tree is constructed from named leaves, each containing arbitrary data.
// Leaves are sorted by name for determinism, then hashed individually with
// SHA-256. The root is SHA-256 of the concatenated leaf hashes.
//
// This Merkle root is embedded in RA-TLS certificates (OID 1.3.6.1.4.1.65230.1.1)
// so that verifiers can confirm the exact configuration of a running platform.
package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// Leaf is a single entry in the configuration Merkle tree.
type Leaf struct {
	// Name is a stable, human-readable identifier for this configuration
	// input (e.g. "container.postgres.image_digest", "platform.ca_cert").
	Name string

	// Data is the raw bytes to be hashed. For absent/empty inputs, leave
	// nil — the leaf hash will be 32 zero bytes.
	Data []byte
}

// Tree is a deterministic Merkle tree of configuration leaves.
type Tree struct {
	leaves     []Leaf
	leafHashes [][32]byte
	root       [32]byte
	computed   bool
}

// New creates a new Merkle tree from the given leaves. Leaves are sorted
// by Name for determinism — the caller does not need to pre-sort.
func New(leaves []Leaf) *Tree {
	// Copy and sort by name for determinism.
	sorted := make([]Leaf, len(leaves))
	copy(sorted, leaves)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	t := &Tree{leaves: sorted}
	t.compute()
	return t
}

// Root returns the 32-byte Merkle root hash.
func (t *Tree) Root() [32]byte {
	return t.root
}

// LeafHashes returns a copy of the ordered leaf hashes.
func (t *Tree) LeafHashes() [][32]byte {
	out := make([][32]byte, len(t.leafHashes))
	copy(out, t.leafHashes)
	return out
}

// Leaves returns a copy of the ordered leaves.
func (t *Tree) Leaves() []Leaf {
	out := make([]Leaf, len(t.leaves))
	copy(out, t.leaves)
	return out
}

// Manifest returns the binary-encoded manifest that allows independent
// verification of the Merkle root. Format:
//
//	[4 bytes: num_entries (u32 LE)]
//	For each entry:
//	  [2 bytes: name_len (u16 LE)]
//	  [name_len bytes: name (UTF-8)]
//	  [32 bytes: leaf_hash]
//	[32 bytes: root]
func (t *Tree) Manifest() []byte {
	var buf []byte

	// Entry count.
	count := make([]byte, 4)
	binary.LittleEndian.PutUint32(count, uint32(len(t.leaves)))
	buf = append(buf, count...)

	// Each entry.
	for i, leaf := range t.leaves {
		nameLen := make([]byte, 2)
		binary.LittleEndian.PutUint16(nameLen, uint16(len(leaf.Name)))
		buf = append(buf, nameLen...)
		buf = append(buf, []byte(leaf.Name)...)
		buf = append(buf, t.leafHashes[i][:]...)
	}

	// Root.
	buf = append(buf, t.root[:]...)
	return buf
}

// compute calculates leaf hashes and the root.
func (t *Tree) compute() {
	t.leafHashes = make([][32]byte, len(t.leaves))

	for i, leaf := range t.leaves {
		if leaf.Data == nil {
			// Absent input: 32 zero bytes.
			t.leafHashes[i] = [32]byte{}
		} else {
			t.leafHashes[i] = sha256.Sum256(leaf.Data)
		}
	}

	// Root = SHA-256( leaf_hash_0 || leaf_hash_1 || … || leaf_hash_N )
	h := sha256.New()
	for _, lh := range t.leafHashes {
		h.Write(lh[:])
	}
	copy(t.root[:], h.Sum(nil))
	t.computed = true
}
