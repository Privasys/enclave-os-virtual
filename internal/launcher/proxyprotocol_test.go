package launcher

import (
	"os"
	"path/filepath"
	"testing"
)

// The list the control plane pushes survives a restart: it is kept on /data
// and read back before Caddy is configured.
func TestProxyProtocolListPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manager-proxy-protocol.json")
	if _, ok := loadProxyProtocolFrom(path); ok {
		t.Fatal("nothing pushed yet: the bootstrap flag must apply")
	}
	if err := os.WriteFile(path, []byte(`{"from":["203.0.113.10/32"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok := loadProxyProtocolFrom(path)
	if !ok || len(got) != 1 || got[0] != "203.0.113.10/32" {
		t.Fatalf("loaded %v %v", got, ok)
	}
	if err := os.WriteFile(path, []byte(`{"from":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := loadProxyProtocolFrom(path); !ok || len(got) != 0 {
		t.Fatalf("a pushed empty list must win over the flag (turned off), got %v %v", got, ok)
	}
}
