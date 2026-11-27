package manager

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/holders"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// What a holder approved decides how the app sees the folder: exactly
// {read} is read-only, exactly {read, write} is writable, and anything else
// opens nothing. Read-only is a read-only MOUNT (the container's root ignores
// file modes): the folder is bound onto itself read-only on the volume's
// exposed path, which reaches the container through its rslave /data, BEFORE
// the key is loaded, so there is never a writable window. The runtime's own
// work goes through its private writable view (HolderFolders.Mount).

var errHolderAccess = errors.New("the approved permissions are neither [read] nor [read, write]")

// holderReadOnly maps a grant's permission set to the folder's mode.
func holderReadOnly(perms []string) (bool, error) {
	set := make([]string, 0, len(perms))
	for _, p := range perms {
		set = append(set, strings.ToLower(strings.TrimSpace(p)))
	}
	sort.Strings(set)
	switch strings.Join(set, ",") {
	case "read":
		return true, nil
	case "read,write":
		return false, nil
	}
	return false, errHolderAccess
}

// recheckReadOnlyFolders runs for every new task of container, after its
// namespaces exist and before it starts (container.Manager's pre-start
// hook): each folder open read-only for that container must be a read-only
// mount in the new task's own view. One that is not (or cannot be checked)
// is CLOSED: its key is removed, so the new task finds it locked.
//
// It runs INSIDE the launcher's load, which holds the launcher's lock: it
// must never call the launcher (a source test enforces it), and it is
// bounded by preStartBound. The folder's paths come from the open state,
// recorded when the folder was opened. If the checks do not finish in time
// the task is refused (it never starts); the checks still close what they
// reach.
func (s *Server) recheckReadOnlyFolders(container string, pid int) error {
	open := s.holdersOpen.readOnlyOf(container)
	if len(open) == 0 {
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.closeFoldersNotReadOnly(container, pid, open)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(preStartBound):
		s.log.Error("holder read-only re-check did not finish in time: the new task is refused",
			zap.String("container", container), zap.Duration("bound", preStartBound))
		return fmt.Errorf("the read-only folder check for %s did not finish in %s", container, preStartBound)
	}
}

// preStartBound caps the pre-start re-check (a variable for tests).
var preStartBound = 10 * time.Second

// closeFoldersNotReadOnly closes every folder in open that the task whose
// init is pid does not see read-only.
func (s *Server) closeFoldersNotReadOnly(container string, pid int, open map[string]holderOpenState) {
	for key, st := range open {
		inContainer := path.Join(holderContainerMount, holders.Dir, st.HolderKey)
		ro, err := s.viewReadOnlyAt(container, pid, inContainer)
		if err == nil && ro {
			continue
		}
		s.log.Error("holder read-only folder not read-only in a new task: closing it",
			zap.String("container", container), zap.String("holder", st.HolderKey),
			zap.Bool("read_only_view", ro), zap.Error(err))
		if st.Mount != "" {
			s.holderClose(st.Mount, st.HolderKey, st.KeyID)
		}
		s.releaseHolderBind(launcher.HolderFolders{Mount: st.Mount, Exposed: st.Exposed}, st.HolderKey)
		s.holdersOpen.drop(key)
	}
}

// viewReadOnlyAt reads the mount view of the task whose init is pid.
func (s *Server) viewReadOnlyAt(container string, pid int, inContainer string) (bool, error) {
	if s.holderViewFn != nil {
		return s.holderViewFn(container, inContainer)
	}
	return holders.ContainerViewReadOnly(pid, inContainer)
}

// containerSeesReadOnly reads the container's own mount view (tests replace
// it). No running task means nothing to check against: not confirmed.
func (s *Server) containerSeesReadOnly(container, inContainer string) (bool, error) {
	if s.holderViewFn != nil {
		return s.holderViewFn(container, inContainer)
	}
	pid, ok := s.launcher.ContainerTaskPID(container)
	if !ok {
		return false, errors.New("the container has no running task to check against")
	}
	return holders.ContainerViewReadOnly(pid, inContainer)
}

// bindReadOnly and unbind are the mount operations (tests replace them).
func (s *Server) bindReadOnly(dir string) error {
	if s.holderBind != nil {
		return s.holderBind(dir, true)
	}
	return holders.BindReadOnly(dir)
}

func (s *Server) unbindHolder(dir string) error {
	if s.holderBind != nil {
		return s.holderBind(dir, false)
	}
	return holders.Unbind(dir)
}

// unlockHolderFolder is the ONLY way a holder folder becomes unlocked: the
// wallet's mint (create), the app's open, the runtime's own file access and
// any reopen after a restart all come here (a source test enforces it). It
// decides the mode from what the holder approved; for read-only it makes the
// container's view of the folder read-only BEFORE the key is loaded, and
// undoes the bind if the key then fails to load (fail closed: no folder).
// A writable grant removes any earlier read-only bind first.
//
// For read-only, the bind alone is not trusted: before the key loads, the
// manager reads the CONTAINER's own mount view and requires the folder to be
// a read-only mount there. With no running task to check against, or a view
// that is not read-only, nothing is unlocked.
func (s *Server) unlockHolderFolder(container string, hf launcher.HolderFolders, holderKey string, perms []string, raw []byte, hostUID int, create bool) (keyID string, readOnly bool, err error) {
	readOnly, err = holderReadOnly(perms)
	if err != nil {
		return "", false, err
	}
	exposed := holders.FolderPath(hf.Exposed, holderKey)
	inContainer := path.Join(holderContainerMount, holders.Dir, holderKey)
	guarded := false
	guard := func() error {
		guarded = true
		if !readOnly {
			return s.unbindHolder(exposed)
		}
		if err := s.bindReadOnly(exposed); err != nil {
			return err
		}
		ro, err := s.containerSeesReadOnly(container, inContainer)
		if err == nil && !ro {
			err = fmt.Errorf("the container sees %s writable", inContainer)
		}
		if err != nil {
			s.log.Error("holder read-only check failed: the folder stays locked",
				zap.String("container", container), zap.String("holder", holderKey), zap.Error(err))
			return fmt.Errorf("holders: read-only view not confirmed: %w", err)
		}
		return nil
	}
	keyID, err = s.holderLoad(hf.Mount, holderKey, raw, hostUID, create, guard)
	if err == nil && !guarded {
		// A loader that never ran the guard must not leave a folder open in
		// a mode nobody checked: the key it loaded is removed again, and any
		// bind released, before the refusal.
		s.holderClose(hf.Mount, holderKey, keyID)
		_ = s.unbindHolder(exposed)
		return "", readOnly, errors.New("holders: the folder was unlocked without its access guard")
	}
	if err != nil {
		if readOnly && guarded {
			_ = s.unbindHolder(exposed)
		}
		return "", readOnly, err
	}
	return keyID, readOnly, nil
}

// holderClose removes a holder's key (tests replace it).
func (s *Server) holderClose(mount, holderKey, keyID string) {
	if s.holderCloseFn != nil {
		s.holderCloseFn(mount, holderKey, keyID)
		return
	}
	_, _, _ = holders.Close(mount, holderKey, keyID)
}

// holderLoad creates (mint) or opens the folder, running guard after the
// folder exists and before its key is loaded. Tests replace it.
func (s *Server) holderLoad(mount, holderKey string, raw []byte, hostUID int, create bool, guard func() error) (string, error) {
	if s.holderLoadFn != nil {
		return s.holderLoadFn(mount, holderKey, raw, hostUID, create, guard)
	}
	if create {
		return holders.Create(mount, holderKey, raw, guard)
	}
	if err := guard(); err != nil {
		return "", err
	}
	return holders.Open(mount, holderKey, raw, hostUID)
}

// releaseHolderBind drops a read-only bind once the folder is closed.
func (s *Server) releaseHolderBind(hf launcher.HolderFolders, holderKey string) {
	if hf.Exposed == "" {
		return
	}
	_ = s.unbindHolder(holders.FolderPath(hf.Exposed, holderKey))
}
