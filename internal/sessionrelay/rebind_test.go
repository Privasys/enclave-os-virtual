package sessionrelay

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func rebindManager() (*Manager, *time.Time) {
	m := NewManager()
	clock := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return clock }
	return m, &clock
}

func TestRebindBudgetPerSID(t *testing.T) {
	m, clock := rebindManager()
	for i := 0; i < rebindRateLimit; i++ {
		if !m.allowRebind("sid") {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if m.allowRebind("sid") {
		t.Fatal("the attempt past the budget was allowed")
	}
	*clock = clock.Add(rebindRateWindow + time.Second)
	if !m.allowRebind("sid") {
		t.Fatal("the next window was refused")
	}
}

// The sid is read before any signature check, so a long one must cost nothing.
func TestRebindRefusesAnOversizedSID(t *testing.T) {
	m, _ := rebindManager()
	if m.allowRebind(strings.Repeat("a", maxRebindSIDLen+1)) {
		t.Fatal("an oversized sid was allowed")
	}
	if n := len(m.rebinds); n != 0 {
		t.Fatalf("%d entries, want 0", n)
	}
}

// Forged sids fill the table, and a real sid arriving then is still allowed.
func TestRebindTableIsBounded(t *testing.T) {
	m, _ := rebindManager()
	for i := 0; i < maxRebindEntries+500; i++ {
		if !m.allowRebind(fmt.Sprintf("forged-%d", i)) {
			t.Fatalf("new sid %d refused", i)
		}
	}
	if n := len(m.rebinds); n != maxRebindEntries {
		t.Fatalf("%d entries, want %d", n, maxRebindEntries)
	}
	if !m.allowRebind("real") {
		t.Fatal("a real sid was refused while the table was full")
	}
}

// A sid already counted keeps its budget while the table is full.
func TestRebindFullTableKeepsCountedBudgets(t *testing.T) {
	m, _ := rebindManager()
	for i := 0; i < rebindRateLimit; i++ {
		m.allowRebind("counted")
	}
	for i := 0; i < maxRebindEntries; i++ {
		m.allowRebind(fmt.Sprintf("forged-%d", i))
	}
	if m.allowRebind("counted") {
		t.Fatal("a sid past its budget was allowed")
	}
}

func TestRebindFullTableIsReclaimedAfterTheWindow(t *testing.T) {
	m, clock := rebindManager()
	for i := 0; i < maxRebindEntries; i++ {
		m.allowRebind(fmt.Sprintf("forged-%d", i))
	}
	*clock = clock.Add(rebindRateWindow + time.Second)
	m.allowRebind("after")
	if n := len(m.rebinds); n != 1 {
		t.Fatalf("%d entries after the window, want 1", n)
	}
}

// While the table is full of live entries it is swept at most once per interval.
func TestRebindSweepIsThrottled(t *testing.T) {
	m, clock := rebindManager()
	for i := 0; i < maxRebindEntries; i++ {
		m.allowRebind(fmt.Sprintf("forged-%d", i))
	}
	m.allowRebind("first")
	swept := m.rebindSwept
	*clock = clock.Add(rebindSweepEvery / 2)
	m.allowRebind("second")
	if !m.rebindSwept.Equal(swept) {
		t.Fatal("the table was swept again inside the interval")
	}
	*clock = clock.Add(rebindSweepEvery)
	m.allowRebind("third")
	if m.rebindSwept.Equal(swept) {
		t.Fatal("the table was not swept after the interval")
	}
}
