package container

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// An app container never holds CAP_NET_RAW, in any capability set, while the
// other defaults stay.
func TestAppHardeningDropsNetRaw(t *testing.T) {
	defaults := []string{"CAP_CHOWN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_KILL"}
	s := &specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{
		Bounding:  slices.Clone(defaults),
		Effective: slices.Clone(defaults),
		Permitted: slices.Clone(defaults),
	}}}
	for _, opt := range appHardening() {
		if err := opt(context.Background(), nil, nil, s); err != nil {
			t.Fatal(err)
		}
	}
	c := s.Process.Capabilities
	for name, set := range map[string][]string{"bounding": c.Bounding, "effective": c.Effective, "permitted": c.Permitted} {
		if slices.Contains(set, "CAP_NET_RAW") {
			t.Errorf("%s set keeps CAP_NET_RAW: %v", name, set)
		}
		if !slices.Contains(set, "CAP_NET_BIND_SERVICE") {
			t.Errorf("%s set lost an unrelated capability: %v", name, set)
		}
	}
}

// Manager.Create must apply appHardening: a container spec built without it
// keeps CAP_NET_RAW (0f85595 shipped the options unapplied). Building the real
// spec needs a containerd image, so this checks the call in Create's body.
func TestCreateAppliesAppHardening(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "container.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Create" || fn.Recv == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "appHardening" {
					found = true
				}
			}
			return !found
		})
		if !found {
			t.Fatal("Manager.Create does not apply appHardening()")
		}
		return
	}
	t.Fatal("Manager.Create not found in container.go")
}
