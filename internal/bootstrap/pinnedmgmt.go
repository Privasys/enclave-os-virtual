package bootstrap

import (
	"fmt"
	"os"

	"github.com/Privasys/enclave-os-virtual/internal/pinned"
)

// pinnedProfileFile is the measured image-profile marker (tests replace it).
var pinnedProfileFile = pinned.ProfileFile

// pinnedMgmtURL is the control plane registration talks to. On an Enclave OS
// image it is the profile's pinned value: a candidate from the environment or
// instance metadata (outside the measurement) is kept only when the profile
// allows it, and otherwise ignored with a warning, so whoever controls the
// VM's metadata cannot send the enclave to another control plane.
// manager-bootstrap runs only on an image, so a missing profile is an error.
func pinnedMgmtURL(candidate string) (string, error) {
	profile, err := pinned.Profile(pinnedProfileFile)
	if err != nil {
		return "", err
	}
	s, _ := pinned.For(profile)
	got := s.MgmtURL(candidate)
	if candidate != "" && got != candidate {
		fmt.Fprintf(os.Stderr, "manager-bootstrap: WARNING: ignoring management URL %q, not pinned for the %s image; using %s\n", candidate, profile, got)
	}
	return got, nil
}
