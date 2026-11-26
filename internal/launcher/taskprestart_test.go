package launcher

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/container"
)

// The manager installs the task pre-start hook BEFORE Run creates the
// container manager (manager.New runs first). On 146-dev the hook was set
// only on an existing container manager, found none, and was silently
// dropped: a new task never re-checked its read-only folders. The hook is
// kept and handed over when the container manager is attached; one set
// afterwards reaches the attached manager directly.
func TestTaskPreStartSurvivesBeingSetBeforeRun(t *testing.T) {
	l := &Launcher{log: zap.NewNop()}
	var got []string
	l.SetTaskPreStart(func(name string, pid int) { got = append(got, name) })

	mgr := &container.Manager{}
	l.attachContainerManager(mgr)
	if !mgr.RunPreStart("app", 1) || len(got) != 1 || got[0] != "app" {
		t.Fatalf("a hook set before the container manager existed was lost (ran %v)", got)
	}

	l.SetTaskPreStart(func(name string, pid int) { got = append(got, "late:"+name) })
	if !mgr.RunPreStart("app", 1) || got[len(got)-1] != "late:app" {
		t.Fatalf("a hook set after the attach did not reach the container manager (ran %v)", got)
	}
}

// Only attachContainerManager assigns the launcher's container manager, so
// no other path can install one without the hook.
func TestOnlyAttachSetsTheContainerManager(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
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
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range as.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "mgr" && fn.Name.Name != "attachContainerManager" {
						t.Errorf("%s: %s assigns the container manager; only attachContainerManager may", name, fn.Name.Name)
					}
				}
				return true
			})
		}
	}
}
