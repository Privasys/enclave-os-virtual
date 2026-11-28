package manager

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/holders"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

func TestHolderPermissionsDecideTheMode(t *testing.T) {
	for _, c := range []struct {
		perms []string
		ro    bool
		ok    bool
	}{
		{[]string{"read"}, true, true},
		{[]string{" Read "}, true, true},
		{[]string{"read", "write"}, false, true},
		{[]string{"write", "read"}, false, true},
		{[]string{"write"}, false, false},
		{nil, false, false},
		{[]string{"read", "write", "admin"}, false, false},
		{[]string{"read", "read"}, false, false},
	} {
		ro, err := holderReadOnly(c.perms)
		if (err == nil) != c.ok || (c.ok && ro != c.ro) {
			t.Errorf("%v: ro %v err %v", c.perms, ro, err)
		}
	}
}

// fakeFolders records the folder operations, in order. The folder exists
// unless missing is set, and the container's task is pid 4242.
type fakeFolders struct {
	steps   []string
	missing bool
	loadErr error
	// viewWritable makes the container's view of the folder writable even
	// after the bind (the failure the self-check exists for).
	viewWritable bool
	// viewWait, when set, blocks the view check until it is closed.
	viewWait chan struct{}
	noTask   bool
}

func (f *fakeFolders) add(s string) { f.steps = append(f.steps, s) }

func (f *fakeFolders) MakeFolder(mount, holderKey string) (bool, error) {
	if !f.missing {
		return false, nil
	}
	f.add("make " + mount)
	return true, nil
}
func (f *fakeFolders) Seal(mount, holderKey string, raw []byte) (string, error) {
	f.add("seal " + mount)
	return "kid", f.loadErr
}
func (f *fakeFolders) RemoveFolder(mount, holderKey string) error {
	f.add("remove " + mount)
	return nil
}
func (f *fakeFolders) Open(mount, holderKey string, raw []byte) (string, error) {
	f.add("open " + mount)
	return "kid", f.loadErr
}
func (f *fakeFolders) Close(mount, holderKey, keyID string) (holders.Status, []int, error) {
	f.add("close-key " + keyID + " " + mount)
	return holders.Absent, nil, nil
}
func (f *fakeFolders) KeyStatus(mount, keyID string) (holders.Status, error) {
	return holders.Present, nil
}
func (f *fakeFolders) Chown(mount, holderKey string, hostUID int) error { return nil }
func (f *fakeFolders) Usage(mount, holderKey string) (int64, error)     { return 0, nil }
func (f *fakeFolders) BindReadOnly(dir string) error {
	f.add("bind-ro " + dir)
	return nil
}
func (f *fakeFolders) Unbind(dir string) error {
	f.add("unbind " + dir)
	return nil
}
func (f *fakeFolders) TaskPID(container string) (int, bool) { return 4242, !f.noTask }
func (f *fakeFolders) ViewReadOnly(pid int, inContainer string) (bool, error) {
	if f.viewWait != nil {
		<-f.viewWait
	}
	f.add(fmt.Sprintf("check-view %d %s", pid, inContainer))
	return !f.viewWritable, nil
}

func (f *fakeFolders) server() *Server {
	return &Server{log: zap.NewNop(), folderOps: f}
}

func (f *fakeFolders) check(t *testing.T, name string, want ...string) {
	t.Helper()
	if strings.Join(f.steps, "|") != strings.Join(want, "|") {
		t.Fatalf("%s: steps %v, want %v", name, f.steps, want)
	}
	f.steps = nil
}

// The order Security set, for EVERY unlock (mint and open alike): for a
// read-only grant the read-only bind exists, and the container's own view
// confirms it, BEFORE the key is loaded (no writable window); both are
// undone if the key then fails to load. A writable grant removes any
// earlier read-only bind. An unknown permission set touches nothing. A new
// folder that is not sealed is removed again.
func TestUnlockBindsReadOnlyBeforeTheKey(t *testing.T) {
	hf := launcher.HolderFolders{Mount: "/view", Exposed: "/vol"}
	key := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	folder := "/vol/holders/" + key
	view := "check-view 4242 /data/holders/" + key

	for _, c := range []struct {
		name          string
		create, isNew bool
	}{{"open", false, false}, {"mint, existing folder", true, false}, {"mint, new folder", true, true}} {
		f := &fakeFolders{missing: c.isNew}
		s := f.server()
		var made, load, removed []string
		if c.isNew {
			made, load, removed = []string{"make /view"}, []string{"seal /view"}, []string{"remove /view"}
		} else {
			load = []string{"open /view"}
		}
		steps := func(parts ...[]string) []string {
			var out []string
			for _, p := range parts {
				out = append(out, p...)
			}
			return out
		}

		_, ro, err := s.unlockHolderFolder("app", hf, key, []string{"read"}, nil, c.create)
		if err != nil || !ro {
			t.Fatalf("%s read-only: ro %v err %v", c.name, ro, err)
		}
		f.check(t, c.name+" read-only", steps(made, []string{"bind-ro " + folder, view}, load)...)

		f.loadErr = errors.New("no key")
		if _, _, err := s.unlockHolderFolder("app", hf, key, []string{"read"}, nil, c.create); err == nil {
			t.Fatalf("%s: a failed key load reported success", c.name)
		}
		f.check(t, c.name+" failed read-only", steps(made, []string{"bind-ro " + folder, view}, load, []string{"unbind " + folder}, removed)...)
		f.loadErr = nil

		// The bind looked fine but the container still sees the folder
		// writable (what 145-dev showed live): refused before the key loads.
		f.viewWritable = true
		if _, _, err := s.unlockHolderFolder("app", hf, key, []string{"read"}, nil, c.create); err == nil {
			t.Fatalf("%s: a writable container view was accepted", c.name)
		}
		f.check(t, c.name+" writable view", steps(made, []string{"bind-ro " + folder, view, "unbind " + folder}, removed)...)
		f.viewWritable = false

		// No running task to check against: nothing is unlocked.
		f.noTask = true
		if _, _, err := s.unlockHolderFolder("app", hf, key, []string{"read"}, nil, c.create); err == nil {
			t.Fatalf("%s: a read-only unlock with no task was accepted", c.name)
		}
		f.check(t, c.name+" no task", steps(made, []string{"bind-ro " + folder, "unbind " + folder}, removed)...)
		f.noTask = false

		if _, ro, err := s.unlockHolderFolder("app", hf, key, []string{"read", "write"}, nil, c.create); err != nil || ro {
			t.Fatalf("%s writable: ro %v err %v", c.name, ro, err)
		}
		f.check(t, c.name+" writable", steps(made, []string{"unbind " + folder}, load)...)

		if _, _, err := s.unlockHolderFolder("app", hf, key, []string{"write"}, nil, c.create); !errors.Is(err, errHolderAccess) {
			t.Fatalf("%s unknown permissions: %v", c.name, err)
		}
		f.check(t, c.name+" unknown permissions")
	}
}

// Every new task re-proves the container's open read-only folders against
// its own mount view before it starts: a folder it would see writable is
// closed (key removed, bind released, state dropped); a read-only one stays
// open; writable grants and other containers are not touched.
func TestNewTaskClosesAReadOnlyFolderItWouldSeeWritable(t *testing.T) {
	for _, writableView := range []bool{false, true} {
		f := &fakeFolders{viewWritable: writableView}
		s := f.server()
		s.holdersOpen = newHolderState()
		s.events = newEventHub()
		// The paths are the container's (launcher.HolderPaths), never asked of
		// the launcher (the Server here has none: calling it would panic).
		mount, exposed := launcher.HolderPaths("app")
		s.holdersOpen.set("ro", holderOpenState{KeyID: "k1", ReadOnly: true, Container: "app", HolderKey: "h1"})
		s.holdersOpen.set("rw", holderOpenState{KeyID: "k2", ReadOnly: false, Container: "app", HolderKey: "h2"})
		s.holdersOpen.set("other", holderOpenState{KeyID: "k3", ReadOnly: true, Container: "other", HolderKey: "h3"})

		if err := s.recheckReadOnlyFolders("app", 4242); err != nil {
			t.Fatalf("writable view %v: %v", writableView, err)
		}

		_, roOpen := s.holdersOpen.get("ro")
		_, rwOpen := s.holdersOpen.get("rw")
		_, otherOpen := s.holdersOpen.get("other")
		if !rwOpen || !otherOpen {
			t.Fatalf("writable view %v: a writable grant or another container was touched", writableView)
		}
		if writableView {
			if roOpen {
				t.Fatal("a read-only folder the new task would see writable stayed open")
			}
			f.check(t, "writable view", "check-view 4242 /data/holders/h1", "close-key k1 "+mount, "unbind "+exposed+"/holders/h1")
		} else {
			if !roOpen {
				t.Fatal("a read-only folder the new task sees read-only was closed")
			}
			f.check(t, "read-only view", "check-view 4242 /data/holders/h1")
		}
	}
}

// The re-check runs under the launcher's lock, so it is bounded: a check
// that hangs refuses the new task (an error, so it never starts) instead of
// holding the lock.
func TestNewTaskRecheckIsBounded(t *testing.T) {
	old := preStartBound
	preStartBound = 50 * time.Millisecond
	t.Cleanup(func() { preStartBound = old })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	s := (&fakeFolders{viewWait: release}).server()
	s.holdersOpen = newHolderState()
	s.holdersOpen.set("ro", holderOpenState{KeyID: "k1", ReadOnly: true, Container: "app", HolderKey: "h1"})

	start := time.Now()
	if err := s.recheckReadOnlyFolders("app", 4242); err == nil {
		t.Fatal("a hung re-check let the task start")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("the re-check held its caller for %s", waited)
	}
	if err := s.recheckReadOnlyFolders("none", 1); err != nil {
		t.Fatalf("a container with no read-only folder was refused: %v", err)
	}
}

// The pre-start re-check runs inside the launcher's load, under its lock:
// nothing it calls in this package may reference s.launcher (147-dev
// deadlocked when it asked the launcher for the folder's paths).
func TestPreStartRecheckNeverCallsTheLauncher(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]*ast.BlockStmt{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil && fn.Recv != nil {
				bodies[fn.Name.Name] = fn.Body
			}
		}
	}
	// Walk the Server methods reachable from the hook.
	seen := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if seen[name] || bodies[name] == nil {
			return
		}
		seen[name] = true
		ast.Inspect(bodies[name], func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "s" {
				if sel.Sel.Name == "launcher" {
					t.Errorf("%s (reached from the pre-start hook) uses s.launcher", name)
				}
				walk(sel.Sel.Name)
			}
			return true
		})
	}
	walk("recheckReadOnlyFolders")
	if !seen["closeFoldersNotReadOnly"] || !seen["folders"] {
		t.Fatalf("the walk did not reach the hook's helpers: %v", seen)
	}
}

// unlockHolderFolder is the only way a holder folder becomes unlocked: no
// non-test file of this package loads a holder's key (MakeFolder, Seal,
// Open) on the folder backend except unlockHolderFolder, and the kernel's
// own calls appear only in the kernel backend's methods of the same name.
// The mint was once the exception that opened a read-only grant writable.
func TestOnlyUnlockHolderFolderLoadsAHolderKey(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	loads := map[string]bool{"MakeFolder": true, "Seal": true, "Open": true}
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			inKernel := false
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				if id, ok := fn.Recv.List[0].Type.(*ast.Ident); ok && id.Name == "kernelFolders" {
					inKernel = true
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !loads[sel.Sel.Name] {
					return true
				}
				switch x := sel.X.(type) {
				case *ast.Ident:
					switch x.Name {
					case "holders":
						if !inKernel || fn.Name.Name != sel.Sel.Name {
							t.Errorf("%s: %s calls holders.%s; only kernelFolders.%s may", name, fn.Name.Name, sel.Sel.Name, sel.Sel.Name)
						}
					case "fs":
						found++
						if fn.Name.Name != "unlockHolderFolder" {
							t.Errorf("%s: %s calls the folder backend\x27s %s; only unlockHolderFolder may", name, fn.Name.Name, sel.Sel.Name)
						}
					}
				case *ast.CallExpr: // s.folders().Open(...)
					if inner, ok := x.Fun.(*ast.SelectorExpr); ok && inner.Sel.Name == "folders" {
						t.Errorf("%s: %s calls s.folders().%s; only unlockHolderFolder may load a key", name, fn.Name.Name, sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	if found == 0 {
		t.Error("no backend load found: the source test no longer sees the unlock path")
	}
}
