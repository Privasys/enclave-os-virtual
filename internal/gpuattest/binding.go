// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gpuattest

import (
	"crypto/sha256"
	"time"
)

// The GPU attestation report is bound to a 32-byte nonce derived from the
// RA-TLS attestation mode, mirroring the platform's two modes:
//
//   - deterministic — the nonce is derived from a COARSE UTC day window, so
//     the (expensive, ~1-2s) NVML report is regenerated at most once per day.
//     The boundary race is therefore once a day at midnight; a verifier
//     tolerates the current OR previous day (see WindowMatches). Per-handshake
//     freshness does NOT depend on this nonce — it comes from the fresh TDX
//     quote's REPORTDATA committing to SHA-256(evidence).
//
//   - challenge — the nonce is derived from the fresh ClientHello nonce, so an
//     interactive `attest` gets a genuinely fresh GPU report.
//
// Both derivations are domain-separated and versioned so the enclave (which
// mints) and the verifier (which recomputes) agree byte-for-byte.
const (
	detNonceDomain  = "privasys-gpu-attest/deterministic/v1\n"
	chalNonceDomain = "privasys-gpu-attest/challenge/v1\n"
	// DayWindowFormat is the UTC day the deterministic nonce is bound to.
	DayWindowFormat = "2006-01-02"
)

// DeterministicNonce is the GPU report nonce for the deterministic mode,
// bound to the UTC day of t.
func DeterministicNonce(t time.Time) [NonceSize]byte {
	return sha256.Sum256([]byte(detNonceDomain + t.UTC().Format(DayWindowFormat)))
}

// ChallengeNonce is the GPU report nonce for the challenge mode, derived from
// the client-supplied RA-TLS challenge.
func ChallengeNonce(clientNonce []byte) [NonceSize]byte {
	h := sha256.New()
	h.Write([]byte(chalNonceDomain))
	h.Write(clientNonce)
	var out [NonceSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// WindowMatches reports whether nonce is a valid deterministic GPU nonce for
// the certificate's NotBefore day — accepting the previous UTC day too so a
// report minted just before a midnight rollover still verifies.
func WindowMatches(nonce [NonceSize]byte, notBefore time.Time) bool {
	if nonce == DeterministicNonce(notBefore) {
		return true
	}
	return nonce == DeterministicNonce(notBefore.AddDate(0, 0, -1))
}
