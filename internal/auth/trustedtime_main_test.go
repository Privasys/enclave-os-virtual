package auth

import (
	"os"
	"testing"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
)

// The verifiers read trusted time, which the manager installs at startup.
// These tests exercise token logic, not the clock, so they trust the host.
func TestMain(m *testing.M) {
	trustedtime.Install(trustedtime.HostClock{})
	os.Exit(m.Run())
}

type rolledBack struct{ now time.Time }

func (r rolledBack) Now() (time.Time, error) { return r.now, nil }

type noClock struct{}

func (noClock) Now() (time.Time, error) { return time.Time{}, trustedtime.ErrUnavailable }

// Expiry is judged by trusted time, not the host clock: a voucher the host
// clock says is valid is refused once trusted time is past its exp, and
// nothing is accepted when there is no trusted time at all.
func TestVoucherExpiryUsesTrustedTime(t *testing.T) {
	defer trustedtime.Install(trustedtime.HostClock{})
	f := newVoucherFixture(t)
	tok := f.sign(t, voucherType, f.validClaims()) // exp = host now + 10 min

	trustedtime.Install(rolledBack{time.Now().Add(time.Hour)})
	if _, err := f.verifier.VerifyVoucher(tok); err == nil {
		t.Fatal("a voucher past its exp in trusted time was accepted")
	}
	trustedtime.Install(noClock{})
	if _, err := f.verifier.VerifyVoucher(tok); err == nil {
		t.Fatal("a voucher was accepted without trusted time")
	}
}
