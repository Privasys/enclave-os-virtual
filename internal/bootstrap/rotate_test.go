package bootstrap

import (
	"strings"
	"testing"
)

func locFixture() *vaultLocator {
	return &vaultLocator{
		Type:              "privasys-vault",
		Handle:            "apps.privasys.org/1efff2acfa6745bd9fd10c9ecbbcb9a4/manager/data/v1",
		Endpoints:         []string{"a:8559", "b:8559", "a:8560", "b:8560"},
		Mrenclave:         "9fcc4f74",
		AttestationServer: "https://as.privasys.org/verify",
		Threshold:         2,
		MgmtURL:           "https://api.developer.privasys.org",
		EnclaveID:         "1efff2ac-fa67-45bd-9fd1-0c9ecbbcb9a4",
	}
}

func bundleFixture() *RotateBundle {
	return &RotateBundle{
		Handle:    "apps.privasys.org/1efff2acfa6745bd9fd10c9ecbbcb9a4/manager/data/v1",
		Grant:     "eyJ.grant",
		Endpoints: []string{"a:8563", "b:8563", "a:8564", "b:8564"},
		Mrenclave: "b219bc35",
		Threshold: 2,
		EnclaveID: "1efff2ac-fa67-45bd-9fd1-0c9ecbbcb9a4",
	}
}

// A bundle for a DIFFERENT key handle must be refused: rotating onto it would
// leave the volume's data addressed by a key nothing holds.
func TestRotateRefusesForeignHandle(t *testing.T) {
	b := bundleFixture()
	b.Handle = "apps.privasys.org/1efff2acfa6745bd9fd10c9ecbbcb9a4/manager/data/v2"
	err := b.validate(locFixture())
	if err == nil || !strings.Contains(err.Error(), "not this volume's handle") {
		t.Fatalf("err = %v, want a handle mismatch", err)
	}
}

// A bundle minted for another enclave must be refused even if the handle were
// to match: the grant is bound to an attested id, and mixing them up would
// mean creating this volume's key under someone else's identity.
func TestRotateRefusesForeignEnclave(t *testing.T) {
	b := bundleFixture()
	b.EnclaveID = "c7d28e26-11a8-4905-beda-3944419d79cc"
	err := b.validate(locFixture())
	if err == nil || !strings.Contains(err.Error(), "is for enclave") {
		t.Fatalf("err = %v, want an enclave mismatch", err)
	}
}

func TestRotateRequiresGrantAndAddressing(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*RotateBundle)
		want string
	}{
		{"no grant", func(b *RotateBundle) { b.Grant = "" }, "no grant"},
		{"no endpoints", func(b *RotateBundle) { b.Endpoints = nil }, "no endpoints"},
		{"no mrenclave", func(b *RotateBundle) { b.Mrenclave = "" }, "no mrenclave"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bundleFixture()
			tc.mut(b)
			err := b.validate(locFixture())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRotateAcceptsMatchingBundle(t *testing.T) {
	if err := bundleFixture().validate(locFixture()); err != nil {
		t.Fatalf("a matching bundle was refused: %v", err)
	}
}

// Re-running against the constellation the volume is already on must be a
// no-op, so the rotation is safe to retry and safe to run fleet-wide.
func TestSameConstellationIsIdempotent(t *testing.T) {
	loc := locFixture()
	b := bundleFixture()
	b.Endpoints = append([]string{}, loc.Endpoints...)
	b.Mrenclave = strings.ToUpper(loc.Mrenclave) // case must not matter
	if !sameConstellation(loc, b) {
		t.Fatal("the same constellation was not recognised; a retry would re-key needlessly")
	}
}

func TestSameConstellationDistinguishesEndpointSets(t *testing.T) {
	loc := locFixture()
	b := bundleFixture()
	b.Mrenclave = loc.Mrenclave
	// Same count, one endpoint different: a genuinely different deployment.
	b.Endpoints = []string{"a:8559", "b:8559", "a:8560", "c:8560"}
	if sameConstellation(loc, b) {
		t.Fatal("a different endpoint set was treated as the same constellation")
	}
}

func TestPipeForRejectsNonHex(t *testing.T) {
	if _, err := pipeFor("not-hex"); err == nil {
		t.Fatal("a non-hex passphrase was accepted; luks-setup feeds hex at boot")
	}
}

func TestPipeForCarriesTheKeyWithoutNewline(t *testing.T) {
	const key = "00112233445566778899aabbccddeeff"
	r, err := pipeFor(key)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	buf := make([]byte, 64)
	n, _ := r.Read(buf)
	if got := string(buf[:n]); got != key {
		t.Fatalf("pipe carried %q, want exactly the hex key with no trailing newline", got)
	}
}
