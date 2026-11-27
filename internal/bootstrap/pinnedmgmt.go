package bootstrap

import (
	"fmt"
	"os"

	"github.com/Privasys/enclave-os-virtual/internal/pinned"
)

// pinnedProfileFile is the measured image-profile marker (tests replace it).
var pinnedProfileFile = pinned.ProfileFile

// pinnedMgmtURL is the control plane every bootstrap call talks to. On an
// Enclave OS image it is the profile's pinned value: a candidate from the
// environment, instance metadata, /data or the LUKS2 header (all outside the
// measurement) is kept only when the profile allows it, and otherwise ignored
// with a warning, so whoever controls the VM cannot send the enclave to
// another control plane. manager-bootstrap runs only on an image, so a
// missing profile is an error.
func pinnedMgmtURL(candidate string) (string, error) {
	profile, s, err := pinned.Current(pinnedProfileFile)
	if err != nil {
		return "", err
	}
	got := s.MgmtURL(candidate)
	if candidate != "" && got != candidate {
		fmt.Fprintf(os.Stderr, "manager-bootstrap: WARNING: ignoring management URL %q, not pinned for the %s image; using %s\n", candidate, profile, got)
	}
	return got, nil
}

// checkAttestationServer refuses an attestation server the image does not
// pin. The server verifies each vault's quote, so one chosen by the host
// (through the LUKS2 header) or by a bundle could vouch for any vault.
func checkAttestationServer(v string) error {
	_, s, err := pinned.Current(pinnedProfileFile)
	if err != nil {
		return err
	}
	return s.CheckAttestationServer(v)
}

// pinLocator holds a locator read from the LUKS2 header, which the host can
// rewrite, to the image's pins: the control plane is always the pinned one,
// and an attestation server the image does not pin fails the boot.
func pinLocator(loc *vaultLocator) error {
	if err := checkAttestationServer(loc.AttestationServer); err != nil {
		return fmt.Errorf("locator: %w", err)
	}
	mgmtURL, err := pinnedMgmtURL(loc.MgmtURL)
	if err != nil {
		return fmt.Errorf("locator: %w", err)
	}
	loc.MgmtURL = mgmtURL
	return nil
}
