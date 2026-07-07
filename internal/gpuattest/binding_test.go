// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gpuattest

import (
	"testing"
	"time"
)

func TestDeterministicNonceIsPerDay(t *testing.T) {
	a := time.Date(2026, 7, 7, 3, 0, 0, 0, time.UTC)
	b := time.Date(2026, 7, 7, 23, 59, 0, 0, time.UTC) // same UTC day
	c := time.Date(2026, 7, 8, 0, 1, 0, 0, time.UTC)   // next day
	if DeterministicNonce(a) != DeterministicNonce(b) {
		t.Fatal("nonce must be stable within a UTC day")
	}
	if DeterministicNonce(a) == DeterministicNonce(c) {
		t.Fatal("nonce must change across the day boundary")
	}
}

func TestWindowMatchesToleratesPreviousDay(t *testing.T) {
	notBefore := time.Date(2026, 7, 8, 0, 0, 30, 0, time.UTC)
	// A report minted on the same day verifies.
	if !WindowMatches(DeterministicNonce(notBefore), notBefore) {
		t.Fatal("same-day nonce must match")
	}
	// A report minted just before midnight (previous day) still verifies.
	prev := DeterministicNonce(notBefore.AddDate(0, 0, -1))
	if !WindowMatches(prev, notBefore) {
		t.Fatal("previous-day nonce must be tolerated")
	}
	// Two days stale must NOT verify.
	twoAgo := DeterministicNonce(notBefore.AddDate(0, 0, -2))
	if WindowMatches(twoAgo, notBefore) {
		t.Fatal("two-day-stale nonce must be rejected")
	}
}

func TestChallengeNonceDomainSeparated(t *testing.T) {
	cn := []byte{0xde, 0xad, 0xbe, 0xef}
	if ChallengeNonce(cn) == ChallengeNonce([]byte{0x00}) {
		t.Fatal("distinct client nonces must give distinct GPU nonces")
	}
	// Challenge and deterministic domains must never collide.
	if ChallengeNonce([]byte("2026-07-07")) == DeterministicNonce(time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("challenge and deterministic domains must be separated")
	}
}
