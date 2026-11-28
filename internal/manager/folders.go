package manager

import (
	"github.com/Privasys/enclave-os-virtual/internal/holders"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// folderBackend is every operation the manager makes on holder folders: the
// kernel's (internal/holders) on an enclave, a recording fake in tests. Paths
// are the volume's (launcher.HolderFolders): key, file and ownership work on
// Mount, the runtime's private view; binds on Exposed, which the container
// sees.
type folderBackend interface {
	// MakeFolder, Seal and RemoveFolder make a new folder (holders.Seal);
	// Open loads the key of one that exists.
	MakeFolder(mount, holderKey string) (created bool, err error)
	Seal(mount, holderKey string, raw []byte) (keyID string, err error)
	RemoveFolder(mount, holderKey string) error
	Open(mount, holderKey string, raw []byte) (keyID string, err error)
	Close(mount, holderKey, keyID string) (holders.Status, []int, error)
	KeyStatus(mount, keyID string) (holders.Status, error)
	Chown(mount, holderKey string, hostUID int) error
	Usage(mount, holderKey string) (int64, error)

	BindReadOnly(dir string) error
	Unbind(dir string) error
	// TaskPID is the init pid of the container's running task.
	TaskPID(container string) (int, bool)
	// ViewReadOnly reads whether the task whose init is pid sees
	// inContainer as a read-only mount.
	ViewReadOnly(pid int, inContainer string) (bool, error)
}

// kernelFolders is the real backend.
type kernelFolders struct{ launcher *launcher.Launcher }

func (kernelFolders) MakeFolder(mount, holderKey string) (bool, error) {
	return holders.MakeFolder(mount, holderKey)
}
func (kernelFolders) Seal(mount, holderKey string, raw []byte) (string, error) {
	return holders.Seal(mount, holderKey, raw)
}
func (kernelFolders) RemoveFolder(mount, holderKey string) error {
	return holders.RemoveFolder(mount, holderKey)
}
func (kernelFolders) Open(mount, holderKey string, raw []byte) (string, error) {
	return holders.Open(mount, holderKey, raw)
}
func (kernelFolders) Close(mount, holderKey, keyID string) (holders.Status, []int, error) {
	return holders.Close(mount, holderKey, keyID)
}
func (kernelFolders) KeyStatus(mount, keyID string) (holders.Status, error) {
	return holders.KeyStatus(mount, keyID)
}
func (kernelFolders) Chown(mount, holderKey string, hostUID int) error {
	return holders.Chown(mount, holderKey, hostUID)
}
func (kernelFolders) Usage(mount, holderKey string) (int64, error) {
	return holders.Usage(mount, holderKey)
}
func (kernelFolders) BindReadOnly(dir string) error { return holders.BindReadOnly(dir) }
func (kernelFolders) Unbind(dir string) error       { return holders.Unbind(dir) }
func (k kernelFolders) TaskPID(container string) (int, bool) {
	if k.launcher == nil {
		return 0, false
	}
	return k.launcher.ContainerTaskPID(container)
}
func (kernelFolders) ViewReadOnly(pid int, inContainer string) (bool, error) {
	return holders.ContainerViewReadOnly(pid, inContainer)
}

// folders is the backend this server uses: the one New installed, or the
// kernel with no tasks to read for a Server built without it (tests).
func (s *Server) folders() folderBackend {
	if s.folderOps != nil {
		return s.folderOps
	}
	return kernelFolders{}
}
