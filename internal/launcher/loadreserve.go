package launcher

import (
	"fmt"
	"time"
)

// vaultCallTimeout bounds each vault round-trip a load makes (the private
// registry credential, the volume key). A vault that never answers must fail
// the load, not hold it, and with it l.mu, for good.
const vaultCallTimeout = 5 * time.Minute

// loadReservation is what a load holds while its image downloads without l.mu:
// the name, hostname and port it will take, and the image the prune must keep.
type loadReservation struct {
	image    string
	hostname string
	port     int
}

// reserveLoadLocked checks a load against the containers loaded and the loads
// on their way, and reserves what it will take. l.mu must be held.
func (l *Launcher) reserveLoadLocked(name string, r loadReservation) error {
	if _, exists := l.specs[name]; exists {
		return fmt.Errorf("launcher: container %q already loaded", name)
	}
	if _, exists := l.reserved[name]; exists {
		return fmt.Errorf("launcher: container %q is already being loaded", name)
	}
	// Check for duplicate hostname (should not happen with deterministic
	// derivation, but guard against name collisions).
	if r.hostname != "" {
		for _, s := range l.specs {
			if s.Hostname == r.hostname {
				return fmt.Errorf("launcher: hostname %q already in use by %q", r.hostname, s.Name)
			}
		}
		for other, o := range l.reserved {
			if o.hostname == r.hostname {
				return fmt.Errorf("launcher: hostname %q already in use by %q", r.hostname, other)
			}
		}
	}
	// Check for duplicate host port. Containers share the host network
	// namespace, so two apps cannot both bind the same TCP port — if we
	// let a second Load through, the container would crash on bind and
	// the manager would be left with a STOPPED task and a dangling
	// in-memory spec. This bit us after an unattended VM restart where
	// the registry had two GPU apps both pinned to 8080.
	if r.port > 0 {
		for _, s := range l.specs {
			if s.Port == r.port {
				return fmt.Errorf("launcher: host port %d already in use by %q", r.port, s.Name)
			}
		}
		for other, o := range l.reserved {
			if o.port == r.port {
				return fmt.Errorf("launcher: host port %d already in use by %q", r.port, other)
			}
		}
	}
	l.reserved[name] = r
	return nil
}

// releaseLoad drops a load's reservation once it has finished, either way.
func (l *Launcher) releaseLoad(name string) {
	l.mu.Lock()
	delete(l.reserved, name)
	l.mu.Unlock()
}

// AbandonLoad forgets the "pulling" entry of a load that was cancelled, so the
// stopped container does not stay listed.
func (l *Launcher) AbandonLoad(name string) {
	if l.mgr != nil {
		l.mgr.Forget(name)
	}
}
