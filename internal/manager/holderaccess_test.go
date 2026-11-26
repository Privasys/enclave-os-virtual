package manager

import (
	"errors"
	"testing"

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

// The order Security set: for a read-only grant the read-only bind exists
// BEFORE the key is loaded (no writable window), and is undone if the key
// then fails to load. A writable grant removes any earlier read-only bind.
// An unknown permission set binds and opens nothing.
func TestReadOnlyHolderOpenBindsFirst(t *testing.T) {
	var steps []string
	openErr := error(nil)
	s := &Server{log: zap.NewNop()}
	s.holderBind = func(dir string, ro bool) error {
		if ro {
			steps = append(steps, "bind-ro "+dir)
		} else {
			steps = append(steps, "unbind "+dir)
		}
		return nil
	}
	s.holderOpenFn = func(mount, holderKey string, raw []byte, uid int) (string, error) {
		steps = append(steps, "open "+mount)
		return "kid", openErr
	}
	hf := launcher.HolderFolders{Mount: "/view", Exposed: "/vol"}
	key := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	folder := "/vol/holders/" + key

	check := func(name string, want ...string) {
		t.Helper()
		if len(steps) != len(want) {
			t.Fatalf("%s: steps %v, want %v", name, steps, want)
		}
		for i := range want {
			if steps[i] != want[i] {
				t.Fatalf("%s: steps %v, want %v", name, steps, want)
			}
		}
		steps = nil
	}

	_, ro, err := s.openHolderFolder(hf, &capabilityGrant{HolderKey: key, Permissions: []string{"read"}}, nil, -1)
	if err != nil || !ro {
		t.Fatalf("read-only open: ro %v err %v", ro, err)
	}
	check("read-only", "bind-ro "+folder, "open /view")

	openErr = errors.New("no key")
	if _, _, err := s.openHolderFolder(hf, &capabilityGrant{HolderKey: key, Permissions: []string{"read"}}, nil, -1); err == nil {
		t.Fatal("a failed key load reported success")
	}
	check("failed read-only", "bind-ro "+folder, "open /view", "unbind "+folder)
	openErr = nil

	if _, ro, err := s.openHolderFolder(hf, &capabilityGrant{HolderKey: key, Permissions: []string{"read", "write"}}, nil, -1); err != nil || ro {
		t.Fatalf("writable open: ro %v err %v", ro, err)
	}
	check("writable", "unbind "+folder, "open /view")

	if _, _, err := s.openHolderFolder(hf, &capabilityGrant{HolderKey: key, Permissions: []string{"write"}}, nil, -1); !errors.Is(err, errHolderAccess) {
		t.Fatalf("unknown permissions: %v", err)
	}
	check("unknown permissions")
}
