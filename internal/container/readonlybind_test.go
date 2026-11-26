package container

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
)

// A holder folder the runtime binds read-only cannot be undone from inside
// the container: the app's spec (containerd's default plus our hardening)
// holds no CAP_SYS_ADMIN in any set, /proc/sys is read-only, and the usual
// kernel interfaces are masked, so no remount, umount or new mount is open
// to the container's root.
func TestContainerCannotUndoAReadOnlyBind(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "enclave-os")
	s, err := oci.GenerateSpec(ctx, nil, &containers.Container{ID: "app"}, appHardening()...)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Process.Capabilities
	for name, set := range map[string][]string{"bounding": c.Bounding, "effective": c.Effective, "permitted": c.Permitted} {
		if slices.Contains(set, "CAP_SYS_ADMIN") {
			t.Errorf("%s set holds CAP_SYS_ADMIN", name)
		}
	}
	if !slices.Contains(s.Linux.ReadonlyPaths, "/proc/sys") {
		t.Errorf("/proc/sys is not read-only: %v", s.Linux.ReadonlyPaths)
	}
	if len(s.Linux.MaskedPaths) == 0 {
		t.Error("no kernel interface is masked")
	}
	if s.Linux.Devices != nil {
		for _, d := range s.Linux.Devices {
			if strings.HasPrefix(d.Path, "/dev/loop") || strings.HasPrefix(d.Path, "/dev/mapper") {
				t.Errorf("a mount-capable device is in the spec: %s", d.Path)
			}
		}
	}
}

// The app's volumes are bound rslave, so the runtime's read-only bind of a
// holder folder on the host reaches the running container (and nothing the
// container mounts reaches the host). A wiring check on the source: the
// volume mount must carry "rslave".
func TestVolumeMountsAreSlave(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "container.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || len(lit.Elts) != 3 {
			return true
		}
		vals := make([]string, 0, 3)
		for _, e := range lit.Elts {
			switch v := e.(type) {
			case *ast.BasicLit:
				vals = append(vals, strings.Trim(v.Value, `"`))
			case *ast.Ident:
				vals = append(vals, v.Name)
			}
		}
		if len(vals) == 3 && vals[0] == "rbind" && vals[1] == "rslave" && vals[2] == "mountOpts" {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal(`container.go: the volume mount must use []string{"rbind", "rslave", mountOpts}`)
	}
}
