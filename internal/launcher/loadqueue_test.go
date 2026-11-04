package launcher

import (
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newLoadQueueLauncher() *Launcher {
	return &Launcher{
		log:       zap.NewNop(),
		failures:  make(map[string]string),
		loading:   make(map[string]*pendingLoad),
		loadTurns: make(map[string]*sync.Mutex),
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
	done := l.AnnounceLoad("app", "img@sha256:aa")

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
	first := l.AnnounceLoad("app", "img")
	second := l.AnnounceLoad("app", "img")

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
	done := l.AnnounceLoad("app", "img")

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
