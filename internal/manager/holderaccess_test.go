package manager

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

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

// unlockRecorder records the mount and key steps of unlockHolderFolder. The
// fake loader behaves like holders.Create/Open: the folder exists, guard
// runs, then the key loads.
type unlockRecorder struct {
	steps     []string
	loadErr   error
	skipGuard bool
	// viewWritable makes the container's view of the folder writable even
	// after the bind (the failure the self-check exists for).
	viewWritable bool
}

func (u *unlockRecorder) server() *Server {
	s := &Server{log: zap.NewNop()}
	s.holderBind = func(dir string, ro bool) error {
		if ro {
			u.steps = append(u.steps, "bind-ro "+dir)
		} else {
			u.steps = append(u.steps, "unbind "+dir)
		}
		return nil
	}
	s.holderLoadFn = func(mount, holderKey string, raw []byte, uid int, create bool, guard func() error) (string, error) {
		op := "open"
		if create {
			op = "create"
		}
		if !u.skipGuard {
			if err := guard(); err != nil {
				return "", err
			}
		}
		u.steps = append(u.steps, "load-key "+op+" "+mount)
		return "kid", u.loadErr
	}
	s.holderCloseFn = func(mount, holderKey, keyID string) {
		u.steps = append(u.steps, "close-key "+keyID+" "+mount)
	}
	s.holderViewFn = func(container, inContainer string) (bool, error) {
		u.steps = append(u.steps, "check-view "+container+" "+inContainer)
		return !u.viewWritable, nil
	}
	return s
}

func (u *unlockRecorder) check(t *testing.T, name string, want ...string) {
	t.Helper()
	if strings.Join(u.steps, "|") != strings.Join(want, "|") {
		t.Fatalf("%s: steps %v, want %v", name, u.steps, want)
	}
	u.steps = nil
}

// The order Security set, for EVERY unlock (mint and open alike): for a
// read-only grant the read-only bind exists BEFORE the key is loaded (no
// writable window), and is undone if the key then fails to load. A
// writable grant removes any earlier read-only bind. An unknown permission
// set binds and loads nothing.
func TestUnlockBindsReadOnlyBeforeTheKey(t *testing.T) {
	hf := launcher.HolderFolders{Mount: "/view", Exposed: "/vol"}
	key := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	folder := "/vol/holders/" + key
	view := "check-view app /data/holders/" + key

	for _, create := range []bool{true, false} {
		op := "open"
		if create {
			op = "create"
		}
		u := &unlockRecorder{}
		s := u.server()

		_, ro, err := s.unlockHolderFolder("app", hf, key, []string{"read"}, nil, -1, create)
		if err != nil || !ro {
			t.Fatalf("%s read-only: ro %v err %v", op, ro, err)
		}
		u.check(t, op+" read-only", "bind-ro "+folder, view, "load-key "+op+" /view")

		u.loadErr = errors.New("no key")
		if _, _, err := s.unlockHolderFolder("app", hf, key, []string{"read"}, nil, -1, create); err == nil {
			t.Fatalf("%s: a failed key load reported success", op)
		}
		u.check(t, op+" failed read-only", "bind-ro "+folder, view, "load-key "+op+" /view", "unbind "+folder)
		u.loadErr = nil

		// The bind looked fine but the container still sees the folder
		// writable (what 145-dev showed live): refused before the key loads.
		u.viewWritable = true
		if _, _, err := s.unlockHolderFolder("app", hf, key, []string{"read"}, nil, -1, create); err == nil {
			t.Fatalf("%s: a writable container view was accepted", op)
		}
		u.check(t, op+" writable view", "bind-ro "+folder, view, "unbind "+folder)
		u.viewWritable = false

		if _, ro, err := s.unlockHolderFolder("app", hf, key, []string{"read", "write"}, nil, -1, create); err != nil || ro {
			t.Fatalf("%s writable: ro %v err %v", op, ro, err)
		}
		u.check(t, op+" writable", "unbind "+folder, "load-key "+op+" /view")

		if _, _, err := s.unlockHolderFolder("app", hf, key, []string{"write"}, nil, -1, create); !errors.Is(err, errHolderAccess) {
			t.Fatalf("%s unknown permissions: %v", op, err)
		}
		u.check(t, op+" unknown permissions")
	}
}

// Every new task re-proves the container's open read-only folders against
// its own mount view before it starts: a folder it would see writable is
// closed (key removed, bind released, state dropped); a read-only one stays
// open; writable grants and other containers are not touched.
func TestNewTaskClosesAReadOnlyFolderItWouldSeeWritable(t *testing.T) {
	for _, writableView := range []bool{false, true} {
		u := &unlockRecorder{viewWritable: writableView}
		s := u.server()
		s.holdersOpen = newHolderState()
		s.events = newEventHub()
		// The paths come from the open state, never from the launcher (the
		// Server here has none: calling it would panic).
		s.holdersOpen.set("ro", holderOpenState{KeyID: "k1", ReadOnly: true, Container: "app", HolderKey: "h1", Mount: "/view", Exposed: "/vol"})
		s.holdersOpen.set("rw", holderOpenState{KeyID: "k2", ReadOnly: false, Container: "app", HolderKey: "h2", Mount: "/view", Exposed: "/vol"})
		s.holdersOpen.set("other", holderOpenState{KeyID: "k3", ReadOnly: true, Container: "other", HolderKey: "h3", Mount: "/view", Exposed: "/vol"})

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
			u.check(t, "writable view", "check-view app /data/holders/h1", "close-key k1 /view", "unbind /vol/holders/h1")
		} else {
			if !roOpen {
				t.Fatal("a read-only folder the new task sees read-only was closed")
			}
			u.check(t, "read-only view", "check-view app /data/holders/h1")
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

	s := &Server{log: zap.NewNop(), holdersOpen: newHolderState()}
	s.holderViewFn = func(string, string) (bool, error) { <-release; return true, nil }
	s.holdersOpen.set("ro", holderOpenState{KeyID: "k1", ReadOnly: true, Container: "app", HolderKey: "h1", Mount: "/view", Exposed: "/vol"})

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
	if !seen["closeFoldersNotReadOnly"] || !seen["holderClose"] || !seen["releaseHolderBind"] {
		t.Fatalf("the walk did not reach the hook's helpers: %v", seen)
	}
}

// A loader that unlocks without running the access guard is refused, and
// the folder ends CLOSED: the key it loaded is removed and any bind
// released, so it never stays open in a mode nobody checked.
func TestUnlockRefusesALoadThatSkippedTheGuard(t *testing.T) {
	hf := launcher.HolderFolders{Mount: "/view", Exposed: "/vol"}
	key := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	folder := "/vol/holders/" + key
	for _, perms := range [][]string{{"read"}, {"read", "write"}} {
		u := &unlockRecorder{skipGuard: true}
		s := u.server()
		if _, _, err := s.unlockHolderFolder("app", hf, key, perms, nil, -1, true); err == nil {
			t.Fatalf("%v: an unguarded unlock was accepted", perms)
		}
		u.check(t, strings.Join(perms, ","), "load-key create /view", "close-key kid /view", "unbind "+folder)
	}
}

// unlockHolderFolder is the only way a holder folder becomes unlocked: no
// non-test file of this package calls holders.Create or holders.Open except
// holderLoad (the loader unlockHolderFolder drives), and nothing outside
// unlockHolderFolder calls holderLoad. The mint was once the exception that
// opened a read-only grant writable.
func TestOnlyUnlockHolderFolderLoadsAHolderKey(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]string{
		"holders.Create": "holderLoad",
		"holders.Open":   "holderLoad",
		"holderLoad":     "unlockHolderFolder",
	}
	found := map[string]int{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				callee := sel.Sel.Name
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "holders" {
					callee = "holders." + callee
				}
				want, watched := allowed[callee]
				if !watched {
					return true
				}
				found[callee]++
				if fn.Name.Name != want {
					t.Errorf("%s: %s calls %s; only %s may", name, fn.Name.Name, callee, want)
				}
				return true
			})
		}
	}
	for callee := range allowed {
		if found[callee] == 0 {
			t.Errorf("no call to %s found: the source test no longer sees the unlock path", callee)
		}
	}
}

// The wallet's mint creates the folder through unlockHolderFolder, in the
// mode of the permission set the holder approved, and records that mode.
func TestMintUnlocksInTheApprovedMode(t *testing.T) {
	src, err := os.ReadFile("holderfolders.go")
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "holderfolders.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mint *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "mintHolderCapability" {
			mint = fn
		}
	}
	if mint == nil {
		t.Fatal("mintHolderCapability not found")
	}
	body := string(src[mint.Body.Pos()-1 : mint.Body.End()-1])
	for _, want := range []string{
		"s.unlockHolderFolder(container, hf, holderKey, p.Capability.Permissions, raw, -1, true)",
		"ReadOnly: readOnly",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("mintHolderCapability no longer contains %q", want)
		}
	}
}
