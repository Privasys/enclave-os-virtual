// Package pinned holds the trust settings an Enclave OS image accepts, per
// image profile, compiled into the measured manager.
//
// The manager's issuer, audience, roles, attestation servers and control
// plane used to reach it through /data/manager.env, which instance metadata
// (outside the measurement, set by whoever controls the VM) could rewrite.
// An image now runs only with the values compiled here for its profile:
// the profile comes from /etc/privasys/image-profile on the dm-verity root,
// so it is measured too. A value from the environment that differs is
// refused, never used, and never replaced silently.
package pinned

import (
	"fmt"
	"os"
	"strings"
)

// ProfileFile is the measured image-profile marker.
const ProfileFile = "/etc/privasys/image-profile"

// Settings are the trust settings one profile accepts. Each list holds every
// value allowed; a setting must equal one of them exactly.
type Settings struct {
	Issuers            []string
	Audiences          []string
	ManagerRoles       []string
	MonitoringRoles    []string
	AttestationServers []string
	MgmtURLs           []string
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
		Issuers:            []string{"https://privasys.id"},
		Audiences:          []string{"privasys-platform"},
		ManagerRoles:       []string{"privasys-platform:manager"},
		MonitoringRoles:    []string{"privasys-platform:monitoring"},
		AttestationServers: []string{"https://as.privasys.org/verify"},
		MgmtURLs:           []string{"https://api.developer.privasys.org"},
		AppDomain:          "apps.privasys.org",
	},
	"dev": {
		Issuers:            []string{"https://privasys.id"},
		Audiences:          []string{"privasys-platform-test"},
		ManagerRoles:       []string{"privasys-platform-test:manager"},
		MonitoringRoles:    []string{"privasys-platform-test:monitoring"},
		AttestationServers: []string{"https://as.privasys.org/verify"},
		MgmtURLs:           []string{"https://api-test.developer.privasys.org", "https://api.developer.test.privasys.org"},
		AppDomain:          "apps.test.privasys.org",
	},
}

// For returns the settings of profile, or false for an unknown one.
func For(profile string) (Settings, bool) {
	s, ok := profiles[profile]
	return s, ok
}

// Profile reads the image profile from path. Every Enclave OS image writes
// it on its dm-verity root, so a missing or unknown profile is an error:
// nothing on an image runs unpinned. (A run off an image says so explicitly;
// see the manager's --unpinned.)
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

// Given are the settings the manager was started with.
type Given struct {
	Issuer             string
	Audience           string
	ManagerRole        string
	MonitoringRole     string
	AttestationServers []string
	MgmtURL            string // empty: no control plane configured yet
	WalletProviderJWKS string // empty, or the issuer-derived default
}

// Resolve gives the settings the manager runs with: an empty setting takes
// the profile's value, so an image needs nothing from manager.env to trust
// the right parties; a setting that is given must be one the profile allows.
// MgmtURL stays empty when none is given and the enclave is not registered
// (no control plane to talk to); registered reports whether it is.
func (s Settings) Resolve(g Given, registered bool) (Given, error) {
	if g.Issuer == "" {
		g.Issuer = s.Issuers[0]
	}
	if g.Audience == "" {
		g.Audience = s.Audiences[0]
	}
	if g.ManagerRole == "" {
		g.ManagerRole = s.ManagerRoles[0]
	}
	if g.MonitoringRole == "" {
		g.MonitoringRole = s.MonitoringRoles[0]
	}
	if len(g.AttestationServers) == 0 {
		g.AttestationServers = append([]string(nil), s.AttestationServers...)
	}
	if g.MgmtURL == "" && registered {
		g.MgmtURL = s.MgmtURLs[0]
	}
	return g, s.Check(g)
}

// Check refuses any setting the profile does not allow. Every problem is
// listed, so one log line names them all.
func (s Settings) Check(g Given) error {
	var bad []string
	one := func(name, v string, allowed []string) {
		if !contains(allowed, v) {
			bad = append(bad, fmt.Sprintf("%s %q (allowed: %s)", name, v, strings.Join(allowed, ", ")))
		}
	}
	one("oidc-issuer", g.Issuer, s.Issuers)
	one("oidc-audience", g.Audience, s.Audiences)
	one("oidc-manager-role", g.ManagerRole, s.ManagerRoles)
	one("oidc-monitoring-role", g.MonitoringRole, s.MonitoringRoles)
	if len(g.AttestationServers) == 0 {
		bad = append(bad, "attestation-servers: none given")
	}
	for _, a := range g.AttestationServers {
		one("attestation-server", a, s.AttestationServers)
	}
	if g.MgmtURL != "" {
		one("mgmt-url", g.MgmtURL, s.MgmtURLs)
	}
	if g.WalletProviderJWKS != "" && g.WalletProviderJWKS != strings.TrimRight(g.Issuer, "/")+"/wallet-provider/jwks" {
		bad = append(bad, fmt.Sprintf("wallet-provider-jwks %q is not the issuer's", g.WalletProviderJWKS))
	}
	if len(bad) > 0 {
		return fmt.Errorf("settings outside this image's pinned values: %s", strings.Join(bad, "; "))
	}
	return nil
}

// MgmtURL is the profile's control plane for a caller that has none yet
// (registration). A candidate that the profile allows is kept; anything else
// gives the profile's first value.
func (s Settings) MgmtURL(candidate string) string {
	if contains(s.MgmtURLs, candidate) {
		return candidate
	}
	return s.MgmtURLs[0]
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
