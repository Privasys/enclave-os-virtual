package apifees

import (
	"os"
	"testing"
)

// The identity-verifier's real manifest must produce exactly the price we
// intend: the heavy verification priced, every other endpoint free, and
// the configure surface never priced.
func TestParseIdentityVerifierManifest(t *testing.T) {
	raw, err := os.ReadFile("testdata/identity-verifier.json")
	if err != nil {
		t.Skip("fixture not present")
	}
	tbl, err := ParseManifest(string(raw))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(tbl) != 1 {
		t.Fatalf("expected exactly one priced endpoint, got %d: %#v", len(tbl), tbl)
	}
	pt, ok := tbl["/verify-identity"]
	if !ok {
		t.Fatalf("/verify-identity not priced: %#v", tbl)
	}
	if pt.Rule.Credits != 100000 {
		t.Fatalf("credits = %d, want 100000", pt.Rule.Credits)
	}
	if !pt.Rule.FreeForWallet() {
		t.Fatal("wallet exemption missing")
	}
	if _, priced := tbl["/configure"]; priced {
		t.Fatal("the configure surface must never be priced")
	}
}
