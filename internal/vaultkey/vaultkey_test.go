package vaultkey

import (
	"bytes"
	"encoding/hex"
	"testing"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"
)

func TestShareEncodeDecodeRoundtrip(t *testing.T) {
	gen := bytes.Repeat([]byte{0xAB}, generationSize)
	s := &vault.Share{X: 3, Data: []byte("some share data bytes")}

	payload := encodeShare(gen, s)
	gotGen, gotShare, err := decodeShare(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotGen != hex.EncodeToString(gen) {
		t.Errorf("generation = %q, want %q", gotGen, hex.EncodeToString(gen))
	}
	if gotShare.X != s.X || !bytes.Equal(gotShare.Data, s.Data) {
		t.Errorf("share roundtrip mismatch: %+v != %+v", gotShare, s)
	}
}

func TestDecodeShareTooShort(t *testing.T) {
	if _, _, err := decodeShare(make([]byte, generationSize)); err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

// Mixed-generation reconstruction: shares from an aborted first fill
// must never combine with shares of the live generation.
func TestBestGroupPicksLargestQuorum(t *testing.T) {
	secretOld := bytes.Repeat([]byte{1}, dekSize)
	secretNew := bytes.Repeat([]byte{2}, dekSize)
	oldShares, err := vault.ShamirSplit(secretOld, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	newShares, err := vault.ShamirSplit(secretNew, 2, 4)
	if err != nil {
		t.Fatal(err)
	}

	// Vault A kept a share of the aborted generation; B, C, D hold the
	// live one.
	byGen := map[string][]*vault.Share{
		"old": {oldShares[0]},
		"new": {newShares[1], newShares[2], newShares[3]},
	}
	best := bestGroup(byGen, 2)
	if len(best) != 3 {
		t.Fatalf("bestGroup picked %d shares, want 3", len(best))
	}
	dek, err := vault.ShamirReconstruct(best)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, secretNew) {
		t.Error("reconstructed the wrong generation")
	}

	// No group meets the threshold -> nil.
	if got := bestGroup(map[string][]*vault.Share{"old": {oldShares[0]}}, 2); got != nil {
		t.Errorf("expected nil for sub-threshold groups, got %d shares", len(got))
	}
}

func TestConfigValidate(t *testing.T) {
	good := Config{
		Endpoints:            []string{"a:8443", "b:8443"},
		MrenclaveHex:         "015ff920efbe97be7593a657169d10fb9f7ab285805c7b02d81a807431c427ae",
		AttestationServerURL: "https://as.privasys.org/verify",
		MgmtURL:              "https://api-test.developer.privasys.org",
		EnclaveID:            "bc60c540-6d11-4a7c-97b3-1c55182f2663",
		EnclaveToken:         "tok",
	}
	if err := good.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := good
	bad.MrenclaveHex = "nope"
	if err := bad.validate(); err == nil {
		t.Error("bad mrenclave accepted")
	}
	bad = good
	bad.Endpoints = []string{"a:8443"}
	bad.Threshold = 2
	if err := bad.validate(); err == nil {
		t.Error("threshold > endpoints accepted")
	}
}
