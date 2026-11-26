package launcher

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The manager installs its hooks on the launcher (SetTaskPreStart,
// SetSignedPolicy, SetDesiredImages, ...) in manager.New, BEFORE the
// launcher's Run creates the parts that use them. A setter that only
// forwards its hook to such a part (l.mgr, l.caddyClient) finds nothing and
// drops it without a word: that is how the task pre-start re-check was never
// switched on in 146-dev. So every Set* method that takes a hook (a func, or
// an interface or func type declared in this package) must store it on a
// field of the Launcher itself, where Run can pick it up.
func TestHookSettersStoreTheHookOnTheLauncher(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var parsed []*ast.File
	hookTypes := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, f)
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts := sp.(*ast.TypeSpec)
				switch ts.Type.(type) {
				case *ast.InterfaceType, *ast.FuncType:
					hookTypes[ts.Name.Name] = true
				}
			}
		}
	}

	isHook := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.FuncType:
			return true
		case *ast.Ident:
			return hookTypes[x.Name]
		}
		return false
	}

	checked := 0
	for _, f := range parsed {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Set") {
				continue
			}
			var hooks []string
			for _, p := range fn.Type.Params.List {
				if isHook(p.Type) {
					for _, n := range p.Names {
						hooks = append(hooks, n.Name)
					}
				}
			}
			if len(hooks) == 0 {
				continue
			}
			checked++
			for _, h := range hooks {
				if !storesOnLauncher(fn.Body, h) {
					t.Errorf("%s: the hook %q is not stored on a Launcher field (l.<field> = %s); a hook set before Run would be lost",
						fn.Name.Name, h, h)
				}
			}
		}
	}
	if checked < 8 {
		t.Fatalf("only %d hook setters found; the test no longer sees them", checked)
	}
}

// storesOnLauncher reports whether body assigns param to a field of l.
func storesOnLauncher(body *ast.BlockStmt, param string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, lhs := range as.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if recv, ok := sel.X.(*ast.Ident); !ok || recv.Name != "l" {
				continue
			}
			if rhs, ok := as.Rhs[i].(*ast.Ident); ok && rhs.Name == param {
				found = true
			}
		}
		return true
	})
	return found
}
