//go:build linux

package holders

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// What a CONTAINER sees decides, not the host: BindReadOnly on a shared
// mount must reach a slave mount namespace (a container's rslave /data)
// read-only. Binding then remounting read-only gave the slave a writable
// copy on 145-dev. Needs root and unshare; skipped elsewhere.
func TestReadOnlyBindReachesASlaveReadOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("needs unshare")
	}
	base := t.TempDir()
	if err := unix.Mount("holders-test", base, "tmpfs", 0, ""); err != nil {
		t.Skipf("cannot mount tmpfs: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(base, unix.MNT_DETACH) })
	if err := unix.Mount("", base, "", unix.MS_SHARED, ""); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(base, "folder")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	slave := exec.Command("unshare", "-m", "--propagation", "slave", "sleep", "30")
	if err := slave.Start(); err != nil {
		t.Skipf("unshare: %v", err)
	}
	t.Cleanup(func() { _ = slave.Process.Kill(); _ = slave.Wait() })
	time.Sleep(200 * time.Millisecond)

	if err := BindReadOnly(folder); err != nil {
		t.Fatal(err)
	}
	ro, err := ContainerViewReadOnly(slave.Process.Pid, folder)
	if err != nil || !ro {
		t.Fatalf("the slave namespace sees the folder read-only = %v (err %v)", ro, err)
	}
	if err := Unbind(folder); err != nil {
		t.Fatal(err)
	}
}
