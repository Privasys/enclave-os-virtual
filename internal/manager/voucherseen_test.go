package manager

import (
	"testing"
	"time"
)

// A voucher this enclave has served is spent here, whatever anyone else says.
// A voucher it has not served is not its business to refuse.
func TestDeliveredVouchers(t *testing.T) {
	d := newDeliveredVouchers()
	now := time.Now()

	if d.Seen("jti-1", now) {
		t.Fatal("an unseen voucher was reported as delivered")
	}
	d.Record("jti-1", now)
	if !d.Seen("jti-1", now) {
		t.Fatal("a delivered voucher was forgotten immediately")
	}
	if d.Seen("jti-2", now) {
		t.Error("another voucher was caught by the first one's record")
	}

	// A disclosure that failed after all releases the voucher, so this
	// enclave must not refuse the retry.
	d.Forget("jti-1")
	if d.Seen("jti-1", now) {
		t.Error("a released voucher stayed spent")
	}

	// Past the window a voucher cannot be presented anyway, and the entry is
	// dropped rather than growing without bound.
	d.Record("jti-3", now)
	later := now.Add(deliveredTTL + time.Minute)
	if d.Seen("jti-3", later) {
		t.Error("an expired record still refused a voucher")
	}
	if len(d.seen) != 0 {
		t.Errorf("expired entries were kept: %d", len(d.seen))
	}
}

// The zero value and an empty jti must not panic: the path runs on every
// voucher-bearing request.
func TestDeliveredVouchersDegradesQuietly(t *testing.T) {
	var d *deliveredVouchers
	if d.Seen("jti", time.Now()) {
		t.Error("a nil record reported a delivery")
	}
	d.Record("jti", time.Now())
	d.Forget("jti")

	real := newDeliveredVouchers()
	if real.Seen("", time.Now()) {
		t.Error("an empty jti was treated as delivered")
	}
	real.Record("", time.Now())
	if len(real.seen) != 0 {
		t.Error("an empty jti was recorded")
	}
}
