package manager

import (
	"errors"
	"sort"
	"strings"

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
func (s *Server) unlockHolderFolder(hf launcher.HolderFolders, holderKey string, perms []string, raw []byte, hostUID int, create bool) (keyID string, readOnly bool, err error) {
	readOnly, err = holderReadOnly(perms)
	if err != nil {
		return "", false, err
	}
	exposed := holders.FolderPath(hf.Exposed, holderKey)
	guarded := false
	guard := func() error {
		guarded = true
		if readOnly {
			return s.bindReadOnly(exposed)
		}
		return s.unbindHolder(exposed)
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
