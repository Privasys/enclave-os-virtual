// Package pinned holds the trust settings an Enclave OS image accepts, per
// image profile, compiled into the measured manager.
//
// An image runs only with the values compiled here for its profile: the
// profile comes from /etc/privasys/image-profile on the dm-verity root, so it
// is measured too. Nothing outside the measurement (/data/manager.env, which
// instance metadata can rewrite) names the issuer, audience, roles or
// attestation server. Only the control plane is read from there, because the
// dev profile answers on two names, and one the profile does not allow is
// refused.
package pinned

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// ProfileFile is the measured image-profile marker.
const ProfileFile = "/etc/privasys/image-profile"

// Settings are the trust settings one profile accepts. A value is compared
// exactly.
type Settings struct {
	Issuer            string
	Audience          string
	ManagerRole       string
	MonitoringRole    string
	AttestationServer string
	// MgmtURLs are the names the control plane answers on; the first is the
	// one a manager calls when it is given none.
	MgmtURLs []string
	// AppDomain is the domain the control plane names this fleet's apps and
	// managers under (its APP_DOMAIN): a manager is reached as
	// <enclave name>-mgr.<AppDomain> (internal/mgrname). Not a trust setting:
	// it only names the hostname whose certificate carries the platform
	// extensions.
	AppDomain string
}

// profiles: production images serve the production platform only; dev
// images serve the test platform (and its legacy control-plane name).
var profiles = map[string]Settings{
	"production": {
		Issuer:            "https://privasys.id",
		Audience:          "privasys-platform",
		ManagerRole:       "privasys-platform:manager",
		MonitoringRole:    "privasys-platform:monitoring",
		AttestationServer: "https://as.privasys.org/verify",
		MgmtURLs:          []string{"https://api.developer.privasys.org"},
		AppDomain:         "apps.privasys.org",
	},
	"dev": {
		Issuer:            "https://privasys.id",
		Audience:          "privasys-platform-test",
		ManagerRole:       "privasys-platform-test:manager",
		MonitoringRole:    "privasys-platform-test:monitoring",
		AttestationServer: "https://as.privasys.org/verify",
		MgmtURLs:          []string{"https://api-test.developer.privasys.org", "https://api.developer.test.privasys.org"},
		AppDomain:         "apps.test.privasys.org",
	},
}

// For returns the settings of profile, or false for an unknown one.
func For(profile string) (Settings, bool) {
	s, ok := profiles[profile]
	return s, ok
}

// Profile reads the image profile from path. Every Enclave OS image writes
// it on its dm-verity root, so a missing or unknown profile is an error:
// nothing on an image runs unpinned.
func Profile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("no image profile at %s: refusing to run unpinned", path)
	}
	if err != nil {
		return "", fmt.Errorf("read image profile: %w", err)
	}
	p := strings.TrimSpace(string(b))
	if _, ok := profiles[p]; !ok {
		return "", fmt.Errorf("image profile %q has no pinned trust settings", p)
	}
	return p, nil
}

// Current reads the image profile at path and returns it with its settings:
// the one way every binary on the image loads them.
func Current(path string) (string, Settings, error) {
	p, err := Profile(path)
	if err != nil {
		return "", Settings{}, err
	}
	return p, profiles[p], nil
}

// WalletProviderJWKS is where the wallet provider (the issuer) publishes the
// keys that sign wallet instance attestations.
func (s Settings) WalletProviderJWKS() string {
	return strings.TrimRight(s.Issuer, "/") + "/wallet-provider/jwks"
}

// ResolveMgmtURL is the control plane the manager runs with: given, which
// must be one the profile allows, or when none is given the profile's first
// for a registered enclave and none for an unregistered one (there is no
// control plane to talk to yet).
func (s Settings) ResolveMgmtURL(given string, registered bool) (string, error) {
	if given == "" {
		if registered {
			return s.MgmtURLs[0], nil
		}
		return "", nil
	}
	if !slices.Contains(s.MgmtURLs, given) {
		return "", fmt.Errorf("mgmt-url %q is outside this image's pinned values (allowed: %s)", given, strings.Join(s.MgmtURLs, ", "))
	}
	return given, nil
}

// MgmtURL is the profile's control plane for a caller that has none yet
// (registration). A candidate that the profile allows is kept; anything else
// gives the profile's first value.
func (s Settings) MgmtURL(candidate string) string {
	if slices.Contains(s.MgmtURLs, candidate) {
		return candidate
	}
	return s.MgmtURLs[0]
}

// CheckAttestationServer refuses an attestation server the profile does not
// allow.
func (s Settings) CheckAttestationServer(v string) error {
	if v != s.AttestationServer {
		return fmt.Errorf("attestation server %q is not pinned for this image (allowed: %s)", v, s.AttestationServer)
	}
	return nil
}
