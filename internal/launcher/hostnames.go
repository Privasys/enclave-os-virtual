package launcher

// One owner per hostname. Every name this host serves belongs to exactly
// one owner: the platform (its own hostname and the manager's), or one app
// (its canonical hostname and its direct domains). A second claim on a name
// is refused, whoever makes it, so one app can never take another's traffic,
// certificate marker or extensions file.
//
// The registry is the launcher state itself (l.specs, l.reserved,
// l.directDomains), read under l.mu, so it cannot drift from what is served.
//
// With an app domain pinned, the namespaces are also split: a canonical
// hostname is one label under the app domain (the control plane names every
// app <app name>.<app domain>), and a direct domain is never under it. The
// app domain is assigned, not claimed.

import (
	"fmt"
	"strings"

	"github.com/Privasys/enclave-os-virtual/internal/hostname"
)

// checkPlatformName refuses the names the platform keeps for itself. A pure
// function of the config: safe with or without l.mu.
func (l *Launcher) checkPlatformName(name string) error {
	if mgr := l.managerHostname(); mgr != "" && strings.EqualFold(name, mgr) {
		return fmt.Errorf("hostname %s is this enclave's manager hostname", name)
	}
	if l.cfg.PlatformHostname != "" && strings.EqualFold(name, l.cfg.PlatformHostname) {
		return fmt.Errorf("hostname %s is this enclave's platform hostname", name)
	}
	return nil
}

// ValidateLoadHostname checks the hostname of a load request before any work
// is done: a concrete lowercase FQDN, one label under the app domain when one
// is pinned, and not a platform name. Ownership is checked again, under l.mu,
// when the load reserves it.
func (l *Launcher) ValidateLoadHostname(name string) error {
	if name == "" {
		return nil
	}
	if err := l.checkPlatformName(name); err != nil {
		return err
	}
	if !hostname.Valid(name) {
		return fmt.Errorf("hostname %q is not one concrete lowercase hostname", name)
	}
	if d := l.cfg.AppDomain; d != "" {
		label, ok := strings.CutSuffix(name, "."+d)
		if !ok || strings.Contains(label, ".") {
			return fmt.Errorf("hostname %s is not a name directly under the app domain %s", name, d)
		}
	}
	return nil
}

// validateDirectDomain checks one direct domain of container: not a platform
// name, and not under the app domain, whose names are assigned. The shape
// was checked with the policy (apppolicy.ValidateDomains) and is checked
// again here, since this is the last gate before Caddy and the ACME client.
func (l *Launcher) validateDirectDomain(name string) error {
	if err := l.checkPlatformName(name); err != nil {
		return err
	}
	if !hostname.Valid(name) {
		return fmt.Errorf("direct domain %q is not one concrete lowercase hostname", name)
	}
	if d := l.cfg.AppDomain; d != "" && (name == d || hostname.Under(name, d)) {
		return fmt.Errorf("direct domain %s is under the app domain %s, whose names are assigned", name, d)
	}
	return nil
}

// hostOwnerLocked returns the container that serves name on this host, as a
// canonical hostname, a load on its way or a direct domain, or "" when no
// app holds it.
//
// Must be called with l.mu held.
func (l *Launcher) hostOwnerLocked(name string) string {
	for n, s := range l.specs {
		if s.Hostname != "" && strings.EqualFold(s.Hostname, name) {
			return n
		}
	}
	for n, r := range l.reserved {
		if r.hostname != "" && strings.EqualFold(r.hostname, name) {
			return n
		}
	}
	for n, ds := range l.directDomains {
		for _, d := range ds {
			if strings.EqualFold(d, name) {
				return n
			}
		}
	}
	return ""
}

// CheckDirectDomains checks, without changing anything, that container may
// serve these direct domains as far as this host can tell now: their shape,
// the names the platform keeps and the app domain's, and no other app
// holding them. The policy route calls it before accepting a document, so a
// claim that would be refused is never stored. Who owns a domain durably is
// the policy store's check (apppolicy.Store.Accept); SetDirectDomains runs
// both again before anything is served.
func (l *Launcher) CheckDirectDomains(containerName string, domains []string) error {
	if len(domains) == 0 || !l.DirectSupported() {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	spec, ok := l.specs[containerName]
	if !ok {
		return fmt.Errorf("container %q not loaded", containerName)
	}
	return l.checkDirectDomainsLocked(containerName, spec.Hostname, domains)
}

// checkDirectDomainsLocked refuses a direct domain that is the app's own
// hostname, a platform or app-domain name, not one concrete hostname, or
// held by another container.
//
// Must be called with l.mu held.
func (l *Launcher) checkDirectDomainsLocked(containerName, canonical string, domains []string) error {
	for _, d := range domains {
		if strings.EqualFold(d, canonical) {
			return fmt.Errorf("direct domain %s is the app's own hostname", d)
		}
		if err := l.validateDirectDomain(d); err != nil {
			return err
		}
		if err := l.claimHostLocked(containerName, d); err != nil {
			return err
		}
	}
	return nil
}

// claimHostLocked refuses name for owner when another container holds it.
//
// Must be called with l.mu held.
func (l *Launcher) claimHostLocked(owner, name string) error {
	if other := l.hostOwnerLocked(name); other != "" && other != owner {
		return fmt.Errorf("hostname %s is already served by %q", name, other)
	}
	return nil
}
