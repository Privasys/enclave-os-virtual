package launcher

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/manifest"
)

func newLoadQueueLauncher() *Launcher {
	return &Launcher{
		log:       zap.NewNop(),
		failures:  make(map[string]string),
		loading:   make(map[string]*pendingLoad),
		loadTurns: make(map[string]*sync.Mutex),
		specs:     make(map[string]manifest.Container),
		reserved:  make(map[string]loadReservation),
	}
}

func statusOf(l *Launcher, name string) (ContainerStatus, bool) {
	for _, s := range l.StatusReport() {
		if s.Name == name {
			return s, true
		}
	}
	return ContainerStatus{}, false
}

// An announced load is listed before containerd is even connected: the control
// plane repairs an absent container by redeploying it.
func TestAnnouncedLoadIsListedAsPulling(t *testing.T) {
	l := newLoadQueueLauncher()
	_, done := l.AnnounceLoad("app", "img@sha256:aa")

	s, ok := statusOf(l, "app")
	if !ok || s.Status != "pulling" || s.Image != "img@sha256:aa" {
		t.Fatalf("status = %+v (listed %v), want pulling", s, ok)
	}
	done()
	if _, ok := statusOf(l, "app"); ok {
		t.Fatal("a finished load must not stay listed")
	}
}

func TestLoadStaysListedUntilTheLastAnnouncementEnds(t *testing.T) {
	l := newLoadQueueLauncher()
	_, first := l.AnnounceLoad("app", "img")
	_, second := l.AnnounceLoad("app", "img")

	first()
	first() // ending one twice must not end the other
	if _, ok := statusOf(l, "app"); !ok {
		t.Fatal("the second load is still on its way")
	}
	second()
	if _, ok := statusOf(l, "app"); ok {
		t.Fatal("no load is left")
	}
}

// A load that is on its way outranks the failure of the attempt before it.
func TestAnnouncedLoadHidesAnEarlierFailure(t *testing.T) {
	l := newLoadQueueLauncher()
	l.MarkFailed("app", "pull failed")
	_, done := l.AnnounceLoad("app", "img")

	if s, _ := statusOf(l, "app"); s.Status != "pulling" {
		t.Fatalf("status = %q, want pulling", s.Status)
	}
	done()
	if s, _ := statusOf(l, "app"); s.Status != "failed" || s.Error != "pull failed" {
		t.Fatalf("status = %+v, want the recorded failure back", s)
	}
}

func TestLoadTurnsRunOneAtATimePerContainer(t *testing.T) {
	l := newLoadQueueLauncher()
	release := l.TakeLoadTurn("app")

	// Another container is not held up.
	l.TakeLoadTurn("other")()

	got := make(chan struct{})
	go func() {
		l.TakeLoadTurn("app")()
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("the second load of a container must wait for the first")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the second load never got its turn")
	}
}

// A stop ends the load that is running and the ones queued behind it, and a
// load announced after the stop is not affected.
func TestCancelLoadsEndsEveryAnnouncedLoad(t *testing.T) {
	l := newLoadQueueLauncher()
	running, doneRunning := l.AnnounceLoad("app", "img")
	queued, doneQueued := l.AnnounceLoad("app", "img")
	other, doneOther := l.AnnounceLoad("other", "img")
	defer doneOther()

	if n := l.CancelLoads("app"); n != 2 {
		t.Fatalf("cancelled %d loads, want 2", n)
	}
	for _, ctx := range []context.Context{running, queued} {
		if !errors.Is(context.Cause(ctx), ErrLoadCancelled) {
			t.Fatalf("cause = %v, want ErrLoadCancelled", context.Cause(ctx))
		}
	}
	if other.Err() != nil {
		t.Fatal("another container's load must not be cancelled")
	}
	doneRunning()
	doneQueued()

	later, doneLater := l.AnnounceLoad("app", "img")
	defer doneLater()
	if later.Err() != nil {
		t.Fatal("a load announced after the stop must run")
	}
	if n := l.CancelLoads("nothing"); n != 0 {
		t.Fatalf("cancelled %d loads of a container with none, want 0", n)
	}
}

// Finishing a load ends its context, but not with ErrLoadCancelled: only a
// stop must read as one.
func TestFinishedLoadIsNotACancel(t *testing.T) {
	l := newLoadQueueLauncher()
	ctx, done := l.AnnounceLoad("app", "img")
	done()
	if errors.Is(context.Cause(ctx), ErrLoadCancelled) {
		t.Fatal("a finished load must not read as cancelled")
	}
}

func TestCommitLoadSkipsACancelledLoad(t *testing.T) {
	l := newLoadQueueLauncher()
	ctx, done := l.AnnounceLoad("app", "img")
	defer done()

	ran := false
	if !l.CommitLoad(ctx, func() { ran = true }) || !ran {
		t.Fatal("a live load must be committed")
	}
	l.CancelLoads("app")
	ran = false
	if l.CommitLoad(ctx, func() { ran = true }) || ran {
		t.Fatal("a stopped load must not be committed: it would replay at boot")
	}
}

// A load on its way holds its name, hostname and port without l.mu, so a
// second load cannot take them while the first one's image downloads.
func TestReservationHoldsNameHostnameAndPort(t *testing.T) {
	l := newLoadQueueLauncher()
	if err := l.reserveLoadLocked("app", loadReservation{image: "img", hostname: "app.example", port: 8000}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		r    loadReservation
	}{
		{"app", loadReservation{image: "img"}},
		{"b", loadReservation{hostname: "app.example"}},
		{"c", loadReservation{port: 8000}},
	} {
		if err := l.reserveLoadLocked(tc.name, tc.r); err == nil {
			t.Fatalf("%s %+v must be refused while app is on its way", tc.name, tc.r)
		}
	}
	if err := l.reserveLoadLocked("d", loadReservation{hostname: "d.example", port: 8001}); err != nil {
		t.Fatalf("an unrelated load must reserve: %v", err)
	}
	l.releaseLoad("app")
	if err := l.reserveLoadLocked("app", loadReservation{hostname: "app.example", port: 8000}); err != nil {
		t.Fatalf("released names must be free again: %v", err)
	}
}

func TestReservationRefusesALoadedContainer(t *testing.T) {
	l := newLoadQueueLauncher()
	l.specs["app"] = manifest.Container{Name: "app", Hostname: "app.example", Port: 8000}
	if err := l.reserveLoadLocked("app", loadReservation{}); err == nil {
		t.Fatal("a loaded container must refuse a second load")
	}
	if err := l.reserveLoadLocked("b", loadReservation{port: 8000}); err == nil {
		t.Fatal("a loaded container's port must be refused")
	}
}
