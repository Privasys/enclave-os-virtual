package manager

import (
	"os"
	"testing"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
)

// Security checks read trusted time, which the manager installs at startup.
// These tests exercise the checks, not the clock, so they trust the host.
func TestMain(m *testing.M) {
	trustedtime.Install(trustedtime.HostClock{})
	os.Exit(m.Run())
}

type fixedClock struct {
	t   time.Time
	err error
}

func (c fixedClock) Now() (time.Time, error) { return c.t, c.err }

// The peer verdict window must hold in trusted time as well as on the
// monotonic clock: a verdict trusted time says is too old is not current,
// and nothing is current without trusted time.
func TestVerdictWindowUsesTrustedTime(t *testing.T) {
	defer trustedtime.Install(trustedtime.HostClock{})
	now := time.Now().UTC()
	pv := &peerVerdict{at: now, mono: time.Now()}
	if !pv.current() {
		t.Fatal("a fresh verdict is not current")
	}
	trustedtime.Install(fixedClock{t: now.Add(verdictTTL + time.Minute)})
	if pv.current() {
		t.Fatal("a verdict past its window in trusted time is still current")
	}
	trustedtime.Install(fixedClock{err: trustedtime.ErrUnavailable})
	if pv.current() {
		t.Fatal("a verdict is current without trusted time")
	}
}
