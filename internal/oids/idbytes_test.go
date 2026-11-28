package oids

import (
	"encoding/hex"
	"testing"
)

// The platform writes ids as UUIDs, with or without hyphens; anything else
// stamps nothing.
func TestIDBytes(t *testing.T) {
	want := "dfe7de7bec364fdaa4e45b8422f851a3"
	for _, in := range []string{"dfe7de7b-ec36-4fda-a4e4-5b8422f851a3", want, " DFE7DE7B-EC36-4FDA-A4E4-5B8422F851A3 "} {
		if got := hex.EncodeToString(IDBytes(in)); got != want {
			t.Errorf("%q: %s", in, got)
		}
	}
	for _, in := range []string{"", "dfe7de7b", "zfe7de7b-ec36-4fda-a4e4-5b8422f851a3", want + "00"} {
		if IDBytes(in) != nil {
			t.Errorf("%q decoded", in)
		}
	}
}
