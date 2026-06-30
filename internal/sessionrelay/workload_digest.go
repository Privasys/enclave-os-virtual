// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessionrelay

import (
	"crypto/sha256"
	"sort"
	"strings"
)

// Workload-digest field names. These are the JS object keys the wallet uses
// in workloadDigestHash (auth/wallet/src/services/encauth.ts) and are part of
// the canonical serialisation — renaming one is a wire-format break (it
// silently changes the digest), so they are pinned by the KAT.
const (
	WorkloadConfigMerkleRoot = "workload_config_merkle_root" // OID 3.1
	WorkloadCodeHash         = "workload_code_hash"          // OID 3.2
	WorkloadImageRef         = "workload_image_ref"          // OID 3.3
	WorkloadKeySource        = "workload_key_source"         // OID 3.4
)

// WorkloadDigest computes the per-app workload-measurement digest (the
// voucher's field 4, named `app_id` on the wire) over the workload OID
// values, byte-identical to the wallet's `workloadDigestHash`
// (auth/wallet/src/services/encauth.ts → hashOidSubset).
//
// Canonical form (must match the wallet exactly): drop entries with an empty
// value, sort the remaining keys ascending, render each as `key=value`, join
// with '\n', then SHA-256 the UTF-8 bytes. The manager arms this per app via
// SetExpectedWorkloadDigest (Sc 1, enc-pub-plan.md) so an app code/config
// change (the value at OID 3.2 / 3.1 / 3.3 / 3.4 moving) wakes the user.
//
// The caller MUST pass the same value encodings the wallet derives from the
// RA-TLS leaf (hex for the 3.1/3.2 digests, the raw string for 3.3 image-ref
// and 3.4 key-source). The KAT (workload_digest_test.go + the wallet jest
// test) pins a vector both sides reproduce byte-for-byte.
func WorkloadDigest(fields map[string]string) [32]byte {
	keys := make([]string, 0, len(fields))
	for k, v := range fields {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(fields[k])
	}
	return sha256.Sum256([]byte(b.String()))
}
