package manager

// What this enclave has already disclosed.
//
// A disclosure voucher buys one delivery. The record of which vouchers have
// been spent is the platform's, and it stays there: settlement is commercial
// business, not runtime business. But an enclave asking that record about a
// voucher it has itself already served is asking a question it can answer.
//
// So each manager remembers the vouchers it delivered under, and refuses a
// repeat without asking anyone. It is a narrowing, not a replacement: an
// enclave that restarts forgets, and an app running on several enclaves has
// several memories, so the platform's record remains the one that spans them.
// What this removes is the common case, where the same enclave is asked to
// serve the same voucher twice.

import (
	"sync"
	"time"
)

// deliveredTTL bounds how long a spent voucher is remembered. A voucher lives
// minutes, so past this it cannot be presented again anyway and the entry is
// only occupying memory.
const deliveredTTL = time.Hour

// deliveredVouchers remembers the jti of every voucher this manager has
// delivered under, with the time it did.
type deliveredVouchers struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newDeliveredVouchers() *deliveredVouchers {
	return &deliveredVouchers{seen: make(map[string]time.Time)}
}

// Seen reports whether this manager has already delivered under this voucher,
// forgetting entries past their usefulness as it goes.
func (d *deliveredVouchers) Seen(jti string, now time.Time) bool {
	if d == nil || jti == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.seen {
		if now.Sub(t) > deliveredTTL {
			delete(d.seen, k)
		}
	}
	at, ok := d.seen[jti]
	return ok && now.Sub(at) <= deliveredTTL
}

// Record marks a voucher as delivered. It is called only once the disclosure
// has actually been served, mirroring the platform's own rule that a failed
// attempt releases the voucher rather than spending it.
func (d *deliveredVouchers) Record(jti string, now time.Time) {
	if d == nil || jti == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen[jti] = now
}

// Forget drops a voucher, for a disclosure that failed after all.
func (d *deliveredVouchers) Forget(jti string) {
	if d == nil || jti == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.seen, jti)
}
