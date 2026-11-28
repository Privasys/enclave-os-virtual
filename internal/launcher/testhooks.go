//go:build testhooks

package launcher

// Test-only entry points, compiled only with -tags testhooks (CI's test
// step): never part of a production binary. They let another package's
// tests reproduce the launcher's real boot order and its real load lock.

import (
	"encoding/hex"

	"github.com/Privasys/enclave-os-virtual/internal/apifees"
	"github.com/Privasys/enclave-os-virtual/internal/container"
	"github.com/Privasys/enclave-os-virtual/internal/manifest"
)

// AttachContainerManagerForTest does what Run does when it has created the
// container manager.
func AttachContainerManagerForTest(l *Launcher, m *container.Manager) {
	l.attachContainerManager(m)
}

// HoldLoadLockForTest takes the lock a load holds while it creates a task
// (the pre-start hooks run under it) and returns its release.
func HoldLoadLockForTest(l *Launcher) (release func()) {
	l.mu.Lock()
	return l.mu.Unlock
}

// RegisterAppForTest makes name a loaded app on hostname, in the state st
// with the fee table prices, as a load leaves it (no task runs).
func RegisterAppForTest(l *Launcher, name, hostname string, st FreezeState, prices apifees.Table) {
	l.mu.Lock()
	l.specs[name] = manifest.Container{Name: name, Hostname: hostname}
	if id, err := hex.DecodeString(st.AppID); err == nil && len(id) == 16 {
		l.appIDs[name] = id
	}
	if st.BillingFrozen {
		l.billingFrozen[name] = st.BillingReason
	}
	l.mu.Unlock()
	l.freezeMu.Lock()
	l.configAPI[name] = st.ConfigAPI
	l.configured[name] = st.Configured
	l.configOwners[name] = st.Owners
	l.routeAuth[name] = st.RouteAuth
	l.prices[name] = prices
	l.freezeMu.Unlock()
}

// SetHolderFoldersForTest gives name the resource declarations decls and the
// holder wrap key wrap, as a load of a vault-backed volume leaves them.
func SetHolderFoldersForTest(l *Launcher, name string, decls []ResourceDecl, wrap []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.resourceDecls[name] = decls
	l.holderWrapKeys[name] = wrap
}
