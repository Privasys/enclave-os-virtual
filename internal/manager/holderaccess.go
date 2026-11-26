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

// openHolderFolder loads g's key with the folder in the mode its grant
// allows: for read-only, the read-only bind first, undone if the key then
// fails to load (fail closed: no folder).
func (s *Server) openHolderFolder(hf launcher.HolderFolders, g *capabilityGrant, raw []byte, hostUID int) (keyID string, readOnly bool, err error) {
	readOnly, err = holderReadOnly(g.Permissions)
	if err != nil {
		return "", false, err
	}
	exposed := holders.FolderPath(hf.Exposed, g.HolderKey)
	if readOnly {
		if err := s.bindReadOnly(exposed); err != nil {
			return "", true, err
		}
	} else if err := s.unbindHolder(exposed); err != nil {
		return "", false, err
	}
	keyID, err = s.holderOpen(hf.Mount, g.HolderKey, raw, hostUID)
	if err != nil {
		if readOnly {
			_ = s.unbindHolder(exposed)
		}
		return "", readOnly, err
	}
	return keyID, readOnly, nil
}

// holderOpen is holders.Open (tests replace it).
func (s *Server) holderOpen(mount, holderKey string, raw []byte, hostUID int) (string, error) {
	if s.holderOpenFn != nil {
		return s.holderOpenFn(mount, holderKey, raw, hostUID)
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
