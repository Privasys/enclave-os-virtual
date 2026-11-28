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
// init is pid does not see read-only. The paths are the container's
// (launcher.HolderPaths): a pure function, so nothing here asks the
// launcher, whose lock the caller holds.
func (s *Server) closeFoldersNotReadOnly(container string, pid int, open map[string]holderOpenState) {
	fs := s.folders()
	mount, exposed := launcher.HolderPaths(container)
	for key, st := range open {
		inContainer := path.Join(holderContainerMount, holders.Dir, st.HolderKey)
		ro, err := fs.ViewReadOnly(pid, inContainer)
		if err == nil && ro {
			continue
		}
		s.log.Error("holder read-only folder not read-only in a new task: closing it",
			zap.String("container", container), zap.String("holder", st.HolderKey),
			zap.Bool("read_only_view", ro), zap.Error(err))
		_, _, _ = fs.Close(mount, st.HolderKey, st.KeyID)
		_ = fs.Unbind(holders.FolderPath(exposed, st.HolderKey))
		s.holdersOpen.drop(key)
	}
}

// unlockHolderFolder is the ONLY way a holder folder becomes unlocked: the
// wallet's mint (create), the app's open, the runtime's own file access and
// any reopen after a restart all come here (a source test enforces it). It
// decides the mode from what the holder approved, makes the container's
// view of the folder match it, and only then loads the key:
//
//  1. a mint makes the folder, empty and unkeyed, when it does not exist;
//  2. read-only: the folder is bound read-only, and the container's own
//     mount view must confirm it (no running task, or a view that is not
//     read-only, unlocks nothing); writable: any earlier read-only bind is
//     removed;
//  3. the key loads: a new folder is sealed to it, an existing one must
//     already be bound to it.
//
// Any failure undoes the steps before it: no folder is left open in a mode
// nobody checked, and a new folder that was not sealed is removed.
func (s *Server) unlockHolderFolder(container string, hf launcher.HolderFolders, holderKey string, perms []string, raw []byte, create bool) (keyID string, readOnly bool, err error) {
	readOnly, err = holderReadOnly(perms)
	if err != nil {
		return "", false, err
	}
	fs := s.folders()
	created := false
	if create {
		if created, err = fs.MakeFolder(hf.Mount, holderKey); err != nil {
			return "", readOnly, err
		}
	}
	removeNew := func() {
		if created {
			_ = fs.RemoveFolder(hf.Mount, holderKey)
		}
	}
	exposed := holders.FolderPath(hf.Exposed, holderKey)
	if err := s.exposeInMode(fs, container, holderKey, exposed, readOnly); err != nil {
		removeNew()
		return "", readOnly, err
	}
	if created {
		keyID, err = fs.Seal(hf.Mount, holderKey, raw)
	} else {
		keyID, err = fs.Open(hf.Mount, holderKey, raw)
	}
	if err != nil {
		if readOnly {
			_ = fs.Unbind(exposed)
		}
		removeNew()
		return "", readOnly, err
	}
	return keyID, readOnly, nil
}

// exposeInMode makes the container's view of the folder at exposed the
// grant's mode, before any key loads. For read-only the bind alone is not
// trusted: the container's own mount view must show a read-only mount, or
// the bind is undone and the unlock refused.
func (s *Server) exposeInMode(fs folderBackend, container, holderKey, exposed string, readOnly bool) error {
	if !readOnly {
		return fs.Unbind(exposed)
	}
	if err := fs.BindReadOnly(exposed); err != nil {
		return err
	}
	inContainer := path.Join(holderContainerMount, holders.Dir, holderKey)
	var ro bool
	pid, ok := fs.TaskPID(container)
	err := errors.New("the container has no running task to check against")
	if ok {
		ro, err = fs.ViewReadOnly(pid, inContainer)
	}
	if err == nil && !ro {
		err = fmt.Errorf("the container sees %s writable", inContainer)
	}
	if err != nil {
		_ = fs.Unbind(exposed)
		s.log.Error("holder read-only check failed: the folder stays locked",
			zap.String("container", container), zap.String("holder", holderKey), zap.Error(err))
		return fmt.Errorf("holders: read-only view not confirmed: %w", err)
	}
	return nil
}

// releaseHolderBind drops a read-only bind once the folder is closed.
func (s *Server) releaseHolderBind(hf launcher.HolderFolders, holderKey string) {
	if hf.Exposed == "" {
		return
	}
	_ = s.folders().Unbind(holders.FolderPath(hf.Exposed, holderKey))
}
