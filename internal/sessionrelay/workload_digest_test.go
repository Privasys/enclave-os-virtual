// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessionrelay

import (
	"encoding/hex"
	"testing"
)

// Workload-digest KAT. The same vector is pinned in the wallet jest test
// (auth/wallet/src/services/encauth.workload-digest.test.ts) and both must
// reproduce these digests byte-for-byte — this is the gate for arming the Sc 1
// per-app workload-digest wake (SetExpectedWorkloadDigest). The expected hex
// was computed independently (Python SHA-256 over the canonical string), so a
// match proves Go ↔ TS agreement, not mutual agreement on a wrong value.
//
// Canonical string (keys sorted ascending, `key=value`, '\n'-joined, then
// SHA-256), changing any pinned constant is a wire-format break — bump a
// version and add a new vector instead.
const (
	katWDConfigMerkleRoot = "1111111111111111111111111111111111111111111111111111111111111111"
	katWDCodeHash         = "2222222222222222222222222222222222222222222222222222222222222222"
	katWDImageRef         = "ghcr.io/privasys/container-app-example"
	katWDKeySource        = "generated"

	// All four fields present.
	katWDVec1Hex = "518939c94cf5980105541518a33140d99f7f19cffaeee131bdbe0bc3c9b851a3"
	// key_source empty -> dropped from the canonical string.
	katWDVec2Hex = "471017351a58db1e6e8ce4b70f8e68129b1444110d06229dc80998c39cef4f37"
)

func TestWorkloadDigestKAT(t *testing.T) {
	v1 := WorkloadDigest(map[string]string{
		WorkloadConfigMerkleRoot: katWDConfigMerkleRoot,
		WorkloadCodeHash:         katWDCodeHash,
		WorkloadImageRef:         katWDImageRef,
		WorkloadKeySource:        katWDKeySource,
	})
	if got := hex.EncodeToString(v1[:]); got != katWDVec1Hex {
		t.Fatalf("vec1 digest = %s, want %s", got, katWDVec1Hex)
	}

	// Empty value must be dropped (not rendered as `key=`), matching the
	// wallet's `value !== ''` filter.
	v2 := WorkloadDigest(map[string]string{
		WorkloadConfigMerkleRoot: katWDConfigMerkleRoot,
		WorkloadCodeHash:         katWDCodeHash,
		WorkloadImageRef:         katWDImageRef,
		WorkloadKeySource:        "",
	})
	if got := hex.EncodeToString(v2[:]); got != katWDVec2Hex {
		t.Fatalf("vec2 digest = %s, want %s", got, katWDVec2Hex)
	}

	// An absent key behaves identically to an empty value.
	v2b := WorkloadDigest(map[string]string{
		WorkloadConfigMerkleRoot: katWDConfigMerkleRoot,
		WorkloadCodeHash:         katWDCodeHash,
		WorkloadImageRef:         katWDImageRef,
	})
	if v2b != v2 {
		t.Fatal("absent key must equal empty value")
	}

	// Sensitivity: changing the 3.2 code hash changes the digest (the wake).
	v3 := WorkloadDigest(map[string]string{
		WorkloadConfigMerkleRoot: katWDConfigMerkleRoot,
		WorkloadCodeHash:         "3333333333333333333333333333333333333333333333333333333333333333",
		WorkloadImageRef:         katWDImageRef,
		WorkloadKeySource:        katWDKeySource,
	})
	if v3 == v1 {
		t.Fatal("a code-hash change must change the workload digest")
	}
}
