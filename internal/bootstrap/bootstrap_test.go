package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Run must short-circuit when /data/ca.crt already exists — image
// upgrades and reboots of registered enclaves never re-enroll.
func TestRun_Idempotent(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "ca.crt"), []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), Config{
		DataDir:        dataDir,
		ManagerEnvPath: filepath.Join(dataDir, "manager.env"),
	})
	if err != nil {
		t.Fatalf("Run with existing ca.crt: %v", err)
	}
}

func TestMergeManagerEnvPreservesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manager.env")
	if err := os.WriteFile(path, []byte("MGMT_URL=https://keep-me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mergeManagerEnv(path, map[string]string{
		"MGMT_URL":      "https://do-not-overwrite",
		"ENCLAVE_TOKEN": "tok",
	}); err != nil {
		t.Fatal(err)
	}
	env, err := readEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if env["MGMT_URL"] != "https://keep-me" {
		t.Fatalf("existing key overwritten: %q", env["MGMT_URL"])
	}
	if env["ENCLAVE_TOKEN"] != "tok" {
		t.Fatalf("missing key not appended: %+v", env)
	}
}
