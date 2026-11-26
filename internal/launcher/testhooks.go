//go:build testhooks

package launcher

// Test-only entry points, compiled only with -tags testhooks (CI's test
// step): never part of a production binary. They let another package's
// tests reproduce the launcher's real boot order and its real load lock.

import "github.com/Privasys/enclave-os-virtual/internal/container"

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
