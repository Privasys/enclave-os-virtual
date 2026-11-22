// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package launcher

import (
	"bytes"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestMintIdentityIsCappedPerContainer(t *testing.T) {
	const name = "app1"
	l := &Launcher{
		log:              zap.NewNop(),
		imageDigests:     map[string][]byte{name: bytes.Repeat([]byte{1}, 32)},
		appIDs:           map[string][]byte{name: bytes.Repeat([]byte{2}, 16)},
		mintedIdentities: map[string]map[[32]byte]time.Time{},
	}
	live := time.Now().Add(time.Hour)
	minted := map[[32]byte]time.Time{}
	for i := 0; i < maxMintedIdentities-1; i++ {
		var h [32]byte
		h[0], h[1] = byte(i), byte(i>>8)
		minted[h] = live
	}
	l.mintedIdentities[name] = minted

	if _, _, err := l.MintIdentity(name); err != nil {
		t.Fatalf("the last free slot: %v", err)
	}
	if _, _, err := l.MintIdentity(name); err == nil {
		t.Fatal("a mint past the cap must be refused")
	}
	if n := len(l.mintedIdentities[name]); n != maxMintedIdentities {
		t.Fatalf("table holds %d, want %d", n, maxMintedIdentities)
	}

	// Expired entries free room, but only once the sweep interval has passed.
	for h := range minted {
		minted[h] = time.Now().Add(-time.Minute)
	}
	if _, _, err := l.MintIdentity(name); err == nil {
		t.Fatal("the table was swept again inside the interval")
	}
	l.mintedSweptAt[name] = time.Now().Add(-2 * mintedSweepInterval)
	if _, _, err := l.MintIdentity(name); err != nil {
		t.Fatalf("after the sweep: %v", err)
	}
	if n := len(l.mintedIdentities[name]); n != 1 {
		t.Fatalf("after the sweep the table holds %d, want only the new identity", n)
	}
}
