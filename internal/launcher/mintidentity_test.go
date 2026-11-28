// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package launcher

import (
	"bytes"
	"testing"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/ttlmap"
	"go.uber.org/zap"
)

func TestMintIdentityIsCappedPerContainer(t *testing.T) {
	const name = "app1"
	clock := time.Now()
	old := mintedNow
	mintedNow = func() (time.Time, bool) { return clock, true }
	t.Cleanup(func() { mintedNow = old })
	l := &Launcher{
		log:              zap.NewNop(),
		imageDigests:     map[string][]byte{name: bytes.Repeat([]byte{1}, 32)},
		appIDs:           map[string][]byte{name: bytes.Repeat([]byte{2}, 16)},
		mintedIdentities: map[string]*ttlmap.Map[[32]byte, time.Time]{},
	}
	l.mu.Lock()
	minted := l.mintedFor(name)
	for i := 0; i < maxMintedIdentities-1; i++ {
		var h [32]byte
		h[0], h[1] = byte(i), byte(i>>8)
		minted.Put(h, clock.Add(time.Hour))
	}
	l.mu.Unlock()

	if _, _, err := l.MintIdentity(name); err != nil {
		t.Fatalf("the last free slot: %v", err)
	}
	if _, _, err := l.MintIdentity(name); err == nil {
		t.Fatal("a mint past the cap must be refused")
	}
	if n := minted.Len(); n != maxMintedIdentities {
		t.Fatalf("table holds %d, want %d", n, maxMintedIdentities)
	}

	// Expired entries free room, but only once the sweep interval has passed.
	l.mu.Lock()
	for h := range minted.All() {
		minted.Put(h, clock.Add(-time.Minute))
	}
	l.mu.Unlock()
	if _, _, err := l.MintIdentity(name); err == nil {
		t.Fatal("the table was swept again inside the interval")
	}
	clock = clock.Add(2 * mintedSweepInterval)
	if _, _, err := l.MintIdentity(name); err != nil {
		t.Fatalf("after the sweep: %v", err)
	}
	if n := minted.Len(); n != 1 {
		t.Fatalf("after the sweep the table holds %d, want only the new identity", n)
	}
}
