package launcher

import (
	"bytes"
	"testing"

	"go.uber.org/zap"
)

func TestSovereignSealKey(t *testing.T) {
	dekHex := "9f2c4a1e9f2c4a1e9f2c4a1e9f2c4a1e9f2c4a1e9f2c4a1e9f2c4a1e9f2c4a1e"
	digestA := bytes.Repeat([]byte{0xaa}, 32)
	digestB := bytes.Repeat([]byte{0xbb}, 32)

	l := &Launcher{
		log: zap.NewNop(),
		imageDigests: map[string][]byte{
			"app":     digestA,
			"novault": digestA,
		},
		sovereignBranches: map[string][]byte{
			"app": deriveSovereignBranch(dekHex),
		},
	}

	k1, gotDigest, err := l.SovereignSealKey("app")
	if err != nil {
		t.Fatalf("SovereignSealKey: %v", err)
	}
	if len(k1) != 32 || !bytes.Equal(gotDigest, digestA) {
		t.Fatalf("key len %d, digest %x", len(k1), gotDigest)
	}

	// Deterministic for the same (DEK, digest).
	k2, _, err := l.SovereignSealKey("app")
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("derivation must be deterministic: %v", err)
	}

	// A version change (new image digest) yields a DIFFERENT key: the
	// consent boundary. Same DEK, same branch.
	l.imageDigests["app"] = digestB
	k3, _, err := l.SovereignSealKey("app")
	if err != nil {
		t.Fatalf("SovereignSealKey after upgrade: %v", err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("S_N must change with the image digest")
	}

	// A different DEK yields a different key for the same digest.
	other := &Launcher{
		log:               zap.NewNop(),
		imageDigests:      map[string][]byte{"app": digestB},
		sovereignBranches: map[string][]byte{"app": deriveSovereignBranch("00" + dekHex[2:])},
	}
	k4, _, err := other.SovereignSealKey("app")
	if err != nil || bytes.Equal(k3, k4) {
		t.Fatalf("S_N must be bound to the app's own DEK: %v", err)
	}

	// The branch must never equal the raw DEK (one-way derivation).
	rawDek := deriveSovereignBranch(dekHex)
	if len(rawDek) != 32 || string(rawDek) == dekHex {
		t.Fatal("branch must be a derived value")
	}

	// Fail closed: unknown container, and container without a branch.
	if _, _, err := l.SovereignSealKey("ghost"); err == nil {
		t.Fatal("unknown container must fail")
	}
	if _, _, err := l.SovereignSealKey("novault"); err == nil {
		t.Fatal("container without a vault-backed volume must fail")
	}
}
