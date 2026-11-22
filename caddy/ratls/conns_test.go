package ratls

import (
	"fmt"
	"testing"
	"time"
)

func resetConns() {
	conns.mu.Lock()
	conns.m = map[string]*connInfo{}
	conns.lastSweep = time.Time{}
	conns.mu.Unlock()
}

func TestConnTableIsBounded(t *testing.T) {
	resetConns()
	t.Cleanup(resetConns)
	for i := 0; i < maxConns+100; i++ {
		connFor(fmt.Sprintf("192.0.2.1:%d", i), true)
	}
	conns.mu.Lock()
	n := len(conns.m)
	conns.mu.Unlock()
	if n != maxConns {
		t.Fatalf("table holds %d records, want %d", n, maxConns)
	}
	// A connection without a record claims nothing.
	if c := connFor("198.51.100.1:1", true); c != nil {
		t.Fatal("a full table recorded a new connection")
	}
	if tag := connTag("198.51.100.1:1"); tag != "none" {
		t.Fatalf("tag %q, want none", tag)
	}
	if leg := connLeg("198.51.100.1:1"); leg != "" {
		t.Fatalf("leg %q, want none", leg)
	}
}

func TestConnTableSweepsExpiredRecordsAtMostOncePerSecond(t *testing.T) {
	resetConns()
	t.Cleanup(resetConns)
	stale := time.Now().Add(-connRetention - time.Minute)
	conns.mu.Lock()
	for i := 0; i < maxConns; i++ {
		conns.m[fmt.Sprintf("192.0.2.2:%d", i)] = &connInfo{tag: "none", touched: stale}
	}
	conns.lastSweep = time.Now()
	conns.mu.Unlock()
	// Swept less than a second ago: no room yet.
	if c := connFor("198.51.100.2:1", true); c != nil {
		t.Fatal("swept again within a second")
	}
	conns.mu.Lock()
	conns.lastSweep = time.Now().Add(-2 * connSweepEvery)
	conns.mu.Unlock()
	if c := connFor("198.51.100.2:2", true); c == nil {
		t.Fatal("expired records were not swept")
	}
	conns.mu.Lock()
	n := len(conns.m)
	conns.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d records after the sweep, want 1", n)
	}
}

func TestRequestOnAKnownConnectionDoesNotSweep(t *testing.T) {
	resetConns()
	t.Cleanup(resetConns)
	stale := time.Now().Add(-connRetention - time.Minute)
	conns.mu.Lock()
	for i := 0; i < connSweepAbove*2; i++ {
		conns.m[fmt.Sprintf("192.0.2.3:%d", i)] = &connInfo{tag: "none", touched: stale}
	}
	conns.m["198.51.100.3:1"] = &connInfo{tag: "challenge", touched: time.Now()}
	conns.mu.Unlock()
	if tag := connTag("198.51.100.3:1"); tag != "challenge" {
		t.Fatalf("tag %q, want challenge", tag)
	}
	conns.mu.Lock()
	n := len(conns.m)
	conns.mu.Unlock()
	if n != connSweepAbove*2+1 {
		t.Fatalf("a lookup swept the table (%d records left)", n)
	}
}
