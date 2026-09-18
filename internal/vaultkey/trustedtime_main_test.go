package vaultkey

import (
	"os"
	"testing"

	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
)

// Security checks read trusted time, which the manager installs at startup.
// These tests exercise the checks, not the clock, so they trust the host.
func TestMain(m *testing.M) {
	trustedtime.Install(trustedtime.HostClock{})
	os.Exit(m.Run())
}
