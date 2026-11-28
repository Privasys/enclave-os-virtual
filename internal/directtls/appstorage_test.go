package directtls

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// A stopped app writes, deletes and locks nothing in the shared storage, so
// a name purged after its release is not written again by the app that held
// it; reads still work.
func TestAStoppedAppWritesNothing(t *testing.T) {
	ctx := context.Background()
	a := newAppStorage(&certmagic.FileStorage{Path: t.TempDir()})
	if err := a.Store(ctx, "certificates/x/name.crt", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	a.stop()
	for name, err := range map[string]error{
		"store":  a.Store(ctx, "certificates/x/name.crt", []byte("late")),
		"delete": a.Delete(ctx, "certificates/x/name.crt"),
		"lock":   a.Lock(ctx, "issue_cert_name"),
		"unlock": a.Unlock(ctx, "issue_cert_name"),
	} {
		if !errors.Is(err, errAppStopped) {
			t.Errorf("%s after stop: %v", name, err)
		}
	}
	if v, err := a.Load(ctx, "certificates/x/name.crt"); err != nil || string(v) != "v1" {
		t.Fatalf("load after stop: %q %v", v, err)
	}
}

// stop returns only once a write under way has finished.
func TestStopWaitsForAWriteUnderWay(t *testing.T) {
	a := newAppStorage(&certmagic.FileStorage{Path: t.TempDir()})
	a.mu.RLock() // a write in progress
	done := make(chan struct{})
	go func() {
		a.stop()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("stop returned while a write was under way")
	case <-time.After(50 * time.Millisecond):
	}
	a.mu.RUnlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not return after the write finished")
	}
}
