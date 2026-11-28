//go:build testhooks

package manager

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/container"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// bootAsMainDoes builds the launcher and the manager in cmd/manager's order
// (launcher.New, then manager.New, then Run attaches the container manager).
func bootAsMainDoes(t *testing.T) (*Server, *launcher.Launcher, *container.Manager) {
	t.Helper()
	log := zap.NewNop()
	l := launcher.New(launcher.Config{}, log)
	s := New(Config{}, log, l, nil)
	mgr := &container.Manager{}
	launcher.AttachContainerManagerForTest(l, mgr)
	return s, l, mgr
}

// In the real boot order, every check the manager registers to run before a
// new task starts is installed on the container manager. On 146-dev the
// read-only re-check was registered before the container manager existed
// and silently dropped.
func TestBootOrderInstallsTheTaskChecks(t *testing.T) {
	_, _, mgr := bootAsMainDoes(t)
	ran, err := mgr.RunPreStart("no-such-app", 1)
	if !ran {
		t.Fatal("after a boot in main's order, no pre-start check is installed")
	}
	if err != nil {
		t.Fatalf("the pre-start check refused an app with no folders: %v", err)
	}
}

// The pre-start checks run inside a load, under the launcher's lock. Run
// them while that very lock is held: they must finish (here within 2 s),
// whatever path they take. On 147-dev the re-check asked the launcher for
// the folder's paths and deadlocked the host's launcher.
func TestTaskChecksFinishUnderTheLoadLock(t *testing.T) {
	for _, writableView := range []bool{false, true} {
		s, l, mgr := bootAsMainDoes(t)
		s.holdersOpen.set("ro", holderOpenState{KeyID: "k1", ReadOnly: true, Container: "app", HolderKey: "h1"})
		s.folderOps = &fakeFolders{viewWritable: writableView}

		release := launcher.HoldLoadLockForTest(l)
		done := make(chan error, 1)
		go func() {
			_, err := mgr.RunPreStart("app", 4242)
			done <- err
		}()
		select {
		case err := <-done:
			release()
			if err != nil {
				t.Fatalf("writable view %v: %v", writableView, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("writable view %v: the pre-start check blocked under the launcher's load lock (a deadlock on a real host)", writableView)
		}
	}
}
