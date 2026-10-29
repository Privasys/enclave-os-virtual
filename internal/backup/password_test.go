package backup

import (
	"encoding/hex"
	"testing"
)

// The vector is computed independently (RFC 5869 by hand: HMAC-SHA256 with a
// zero salt, then one expand block), so the recovery contract the owner relies
// on cannot drift with the implementation.
func TestRepositoryPasswordVector(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	got, err := RepositoryPassword(hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	const want = "6cfb67512396b8fdade1b023d37f24e64838d7ec6468b255030e35331684bc29"
	if got != want {
		t.Fatalf("password = %s, want %s", got, want)
	}
}

func TestRepositoryPasswordRejectsBadKeys(t *testing.T) {
	for _, k := range []string{"", "zz", hex.EncodeToString(make([]byte, 16))} {
		if _, err := RepositoryPassword(k); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
}
