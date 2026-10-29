package launcher

// Direct domains: adopter hostnames whose TLS ends in this enclave with a
// publicly trusted certificate (internal/directtls). The owner names them in
// the signed app policy; the launcher turns that list into:
//
//   - a Caddy route per name, onto the app's own route (Host rewritten to the
//     app's platform hostname, so every per-host rule of the manager applies
//     unchanged);
//   - an extensions file per name, identical to the app host's, so a client
//     that asks for RA-TLS on the adopter name gets the full attested leaf;
//   - certificates obtained under the app's ACME account, whose key is a
//     one-way branch of the app's vault-backed volume key;
//   - OID 7.4 on the app's leaves, binding each name to the key of its
//     public certificate, so anyone attesting the app can check that the key
//     serving the adopter name was born here.

import (
	"crypto/ecdsa"
	"encoding/json"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"go.uber.org/zap"

	"enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-os-virtual/internal/directtls"
	"github.com/Privasys/enclave-os-virtual/internal/extensions"
)

// directBranchInfo is the HKDF label of the direct-TLS branch of an app's
// volume key. The ACME account key derives from it, and adopters pin that
// account in CAA, so changing this label breaks every direct domain.
const directBranchInfo = "privasys-direct-tls/v1"

// ApprovedDomains reports the direct adopter hostnames an app's owner
// approved (the policy store).
type ApprovedDomains interface {
	DomainsFor(appIDHex string) []string
}

// SignedPolicy reports the members of an app's accepted owner-signed policy
// (the policy store): a load applies them over the control plane's copy.
type SignedPolicy interface {
	SignedFor(appIDHex string) (callers, deps json.RawMessage, owners []string)
}

// SetSignedPolicy installs the source of accepted owner-signed policies.
func (l *Launcher) SetSignedPolicy(src SignedPolicy) {
	if l == nil {
		return
	}
	l.approvedMu.Lock()
	defer l.approvedMu.Unlock()
	l.signedPolicy = src
}

// applySignedPolicy overwrites a load request's allowed callers, dependency
// set and owners with those of the app's accepted signed policy, when the
// owner signed them. The request's values are the control plane's unsigned
// copy, which goes stale for a pinned app (its owner changes them by
// signing, applied live), so without this every redeploy, boot replay or
// reconciler load would bring the old ones back.
func (l *Launcher) applySignedPolicy(req *LoadRequest) {
	l.approvedMu.Lock()
	src := l.signedPolicy
	l.approvedMu.Unlock()
	raw := parseAppID(req.AppId)
	if src == nil || len(raw) == 0 {
		return
	}
	callers, deps, owners := src.SignedFor(hex.EncodeToString(raw))
	if len(callers) > 0 {
		var c struct {
			Entries   []ratls.DependencyEntry `json:"entries"`
			Platforms []string                `json:"platforms"`
		}
		if err := json.Unmarshal(callers, &c); err == nil {
			if len(c.Entries) > 0 {
				req.IngressAllowedCallers = &ratls.DependencySet{Entries: c.Entries}
			} else {
				req.IngressAllowedCallers = nil
			}
			req.IngressAllowedPlatforms = c.Platforms
		} else {
			l.log.Warn("signed allowed callers unreadable; keeping the load request's", zap.String("container", req.Name), zap.Error(err))
		}
	}
	if len(deps) > 0 {
		var set ratls.DependencySet
		if err := json.Unmarshal(deps, &set); err == nil {
			if len(set.Entries) > 0 {
				req.Dependencies = &set
			} else {
				req.Dependencies = nil
			}
		} else {
			l.log.Warn("signed dependencies unreadable; keeping the load request's", zap.String("container", req.Name), zap.Error(err))
		}
	}
	if len(owners) > 0 {
		req.Owners = owners
	}
	if len(callers) > 0 || len(deps) > 0 || len(owners) > 0 {
		l.log.Info("load uses the owner-signed policy over the request's copy", zap.String("container", req.Name),
			zap.Bool("callers", len(callers) > 0), zap.Bool("dependencies", len(deps) > 0), zap.Bool("owners", len(owners) > 0))
	}
}

// SetApprovedDomains installs the source of owner-approved direct domains.
func (l *Launcher) SetApprovedDomains(src ApprovedDomains) {
	if l == nil {
		return
	}
	l.approvedMu.Lock()
	defer l.approvedMu.Unlock()
	l.approvedDomains = src
}

// deriveDirectBranch derives the direct-TLS branch from the volume key as
// resolved at Load. Nil only on an empty key.
func deriveDirectBranch(keyHex string) []byte {
	if keyHex == "" {
		return nil
	}
	secret, err := hex.DecodeString(keyHex)
	if err != nil || len(secret) == 0 {
		secret = []byte(keyHex)
	}
	branch, err := hkdf.Key(sha256.New, secret, []byte(directBranchInfo), "branch", 32)
	if err != nil {
		return nil
	}
	return branch
}

// DirectSupported reports whether this host serves direct domains.
func (l *Launcher) DirectSupported() bool {
	return l != nil && l.direct != nil && l.caddyClient != nil
}

// DirectDomainsOf returns the direct adopter names a container serves now.
// Lock-free (a request path reads it, and a load holds l.mu for minutes).
func (l *Launcher) DirectDomainsOf(containerName string) []string {
	if l == nil {
		return nil
	}
	if v, ok := l.directView.Load(containerName); ok {
		return append([]string(nil), v.([]string)...)
	}
	return nil
}

// DirectStatus reports a container's direct domains for the control plane.
func (l *Launcher) DirectStatus(containerName string) (directtls.Status, error) {
	if !l.DirectSupported() {
		return directtls.Status{}, fmt.Errorf("direct domains are not configured on this host")
	}
	l.mu.Lock()
	_, ok := l.specs[containerName]
	l.mu.Unlock()
	if !ok {
		return directtls.Status{}, fmt.Errorf("container %q not loaded", containerName)
	}
	st := l.direct.Status(containerName)
	st.ProxyProtocol = l.ProxyProtocolStatus()
	return st, nil
}

// applyApprovedDomains applies the domains the policy store holds for a
// container's app, as a load does: the document that approved them was
// accepted before this load and is not re-accepted.
func (l *Launcher) applyApprovedDomains(containerName string) {
	l.approvedMu.Lock()
	src := l.approvedDomains
	l.approvedMu.Unlock()
	appID := l.AppIDOf(containerName)
	if src == nil || appID == "" {
		return
	}
	domains := src.DomainsFor(appID)
	if len(domains) == 0 {
		return
	}
	if err := l.SetDirectDomains(containerName, domains); err != nil {
		l.log.Warn("direct domains not applied at load",
			zap.String("container", containerName), zap.Strings("domains", domains), zap.Error(err))
	}
}

// SetDirectDomains makes a container serve exactly these direct domains. An
// empty list removes them.
func (l *Launcher) SetDirectDomains(containerName string, domains []string) error {
	if len(domains) > 0 && !l.DirectSupported() {
		return fmt.Errorf("direct domains are not configured on this host")
	}
	if !l.DirectSupported() {
		return nil
	}
	l.mu.Lock()
	spec, ok := l.specs[containerName]
	if !ok {
		l.mu.Unlock()
		return fmt.Errorf("container %q not loaded", containerName)
	}
	if spec.Hostname == "" || spec.Internal {
		l.mu.Unlock()
		return fmt.Errorf("container %q serves no hostname", containerName)
	}
	branch := l.directBranches[containerName]
	if len(domains) > 0 && branch == nil {
		l.mu.Unlock()
		return fmt.Errorf("direct domains need a vault-backed volume, so the ACME account survives upgrades")
	}
	previous := l.directDomains[containerName]
	// The RA-TLS leaf on an adopter name carries the app host's extensions.
	for _, d := range domains {
		if err := l.writeContainerExtensions(containerName, d, spec.Port); err != nil {
			l.mu.Unlock()
			return fmt.Errorf("extensions for %s: %w", d, err)
		}
	}
	l.directDomains[containerName] = append([]string(nil), domains...)
	l.directView.Store(containerName, append([]string(nil), domains...))
	hostname := spec.Hostname
	l.mu.Unlock()

	for _, d := range previous {
		if !contains(domains, d) {
			_ = extensions.Remove(l.cfg.ExtensionsDir, d)
		}
	}

	var key *ecdsa.PrivateKey
	if len(domains) > 0 {
		k, err := directtls.AccountKey(branch)
		if err != nil {
			return err
		}
		key = k
	}
	if err := l.direct.Apply(containerName, hostname, domains, key); err != nil {
		return err
	}
	if err := l.caddyClient.SetAliases(hostname, domains); err != nil {
		return fmt.Errorf("caddy routes for direct domains: %w", err)
	}
	l.log.Info("direct domains set",
		zap.String("container", containerName), zap.String("hostname", hostname), zap.Strings("domains", domains))
	return nil
}

// directChanged re-stamps a container's leaves after one of its direct
// certificates was obtained or renewed, so OID 7.4 names the current key.
func (l *Launcher) directChanged(containerName string) {
	l.mu.Lock()
	spec, ok := l.specs[containerName]
	if !ok {
		l.mu.Unlock()
		return
	}
	hosts := append([]string{spec.Hostname}, l.directDomains[containerName]...)
	for _, h := range hosts {
		if err := l.writeContainerExtensions(containerName, h, spec.Port); err != nil {
			l.log.Warn("direct key stamp not written", zap.String("host", h), zap.Error(err))
		}
	}
	l.mu.Unlock()
	if err := l.caddyClient.ReloadForce(); err != nil {
		l.log.Warn("caddy reload after a direct certificate change failed; the stamp lands on the next issuance",
			zap.String("container", containerName), zap.Error(err))
	}
}

// removeDirect drops a container's direct domains at unload.
//
// Must be called with l.mu held.
func (l *Launcher) removeDirect(containerName, hostname string) {
	if !l.DirectSupported() {
		return
	}
	domains := l.directDomains[containerName]
	delete(l.directDomains, containerName)
	delete(l.directBranches, containerName)
	l.directView.Delete(containerName)
	if len(domains) == 0 {
		return
	}
	l.direct.Remove(containerName)
	for _, d := range domains {
		_ = extensions.Remove(l.cfg.ExtensionsDir, d)
	}
	if err := l.caddyClient.SetAliases(hostname, nil); err != nil {
		l.log.Warn("direct routes not removed", zap.String("hostname", hostname), zap.Error(err))
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
