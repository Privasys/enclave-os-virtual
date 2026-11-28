package launcher

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/merkle"
)

func extensionOIDs(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f struct {
		Extensions []struct {
			OID string `json:"oid"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, e := range f.Extensions {
		out = append(out, e.OID)
	}
	sort.Strings(out)
	return out
}

// The control plane reaches the manager at <enclave>-mgr.<app domain>, and
// clients (the CLI's `apps logs`) refuse a certificate there without the
// platform extensions, 1.3 above all: on 148 that name had no extensions
// file, so its leaf carried the quote only and every owner log read on m1
// was refused. The platform set is now written under that exact name too,
// and no other name gets it.
func TestManagerHostnameCarriesThePlatformExtensions(t *testing.T) {
	dir := t.TempDir()
	l := New(Config{
		ExtensionsDir:    dir,
		PlatformHostname: "m6-dev.privasys.org",
		ManagerHostname:  "m6-dev-mgr.apps.test.privasys.org",
		AppDomain:        "apps.test.privasys.org",
		EnclaveID:        "dfe7de7b-ec36-4fda-a4e4-5b8422f851a3",
	}, zap.NewNop())
	l.platformTree = merkle.New([]merkle.Leaf{{Name: "test", Data: []byte("x")}})

	if err := l.writePlatformExtensions(); err != nil {
		t.Fatal(err)
	}
	platform := extensionOIDs(t, filepath.Join(dir, "m6-dev.privasys.org.json"))
	mgr := extensionOIDs(t, filepath.Join(dir, "m6-dev-mgr.apps.test.privasys.org.json"))
	if strings.Join(platform, ",") != strings.Join(mgr, ",") {
		t.Fatalf("the manager name carries %v, the platform hostname %v", mgr, platform)
	}
	has13 := false
	for _, o := range mgr {
		if o == "1.3.6.1.4.1.65230.1.3" {
			has13 = true
		}
	}
	if !has13 {
		t.Fatalf("the manager name's extensions lack 1.3: %v", mgr)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 2 {
		t.Fatalf("expected exactly the platform and manager files, got %v", files)
	}
}

// Without a manager hostname nothing beyond the platform hostname is written.
func TestNoManagerNameNoExtraExtensions(t *testing.T) {
	dir := t.TempDir()
	l := New(Config{ExtensionsDir: dir, PlatformHostname: "m6-dev.privasys.org"}, zap.NewNop())
	l.platformTree = merkle.New([]merkle.Leaf{{Name: "test", Data: []byte("x")}})
	if err := l.writePlatformExtensions(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("expected only the platform file, got %v", files)
	}
}

// No app may take the manager's hostname: its certificate would show the
// platform's identity, and the app's own extensions file would be replaced.
func TestLoadRefusesTheManagerHostname(t *testing.T) {
	l := New(Config{ManagerHostname: "m6-dev-mgr.apps.test.privasys.org", AppDomain: "apps.test.privasys.org"}, zap.NewNop())
	for _, h := range []string{"m6-dev-mgr.apps.test.privasys.org", "M6-DEV-MGR.apps.test.privasys.org"} {
		_, err := l.Load(context.Background(), LoadRequest{Name: "evil", Image: "example.invalid/x@sha256:" + strings.Repeat("0", 64), Hostname: h, Port: 8081})
		if err == nil || !strings.Contains(err.Error(), "manager hostname") {
			t.Fatalf("%s: a load taking the manager's hostname was not refused: %v", h, err)
		}
	}
}
