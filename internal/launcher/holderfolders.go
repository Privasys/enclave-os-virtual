// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"crypto/hkdf"

	"github.com/Privasys/enclave-os-virtual/internal/container"
	"github.com/Privasys/enclave-os-virtual/internal/holders"
	"github.com/Privasys/enclave-os-virtual/internal/volume"
)

// Holder folders: one directory per holder inside the app's own encrypted
// volume, each under the holder's key, opened and closed by the manager on
// the app's behalf (internal/holders). The launcher's part is small:
//
//   - a one-way branch of the app's vault-backed volume DEK, derived while
//     the DEK is in hand exactly like the sovereign-seal branch, from which
//     the manager derives the key that WRAPS each holder's key beside the
//     approval record. Only the measured enclave OS of this app ever holds
//     the DEK, so only it can unwrap; a redeploy, a constellation move and
//     the owner's promote on an upgrade all follow the DEK as they do today,
//     and nothing exists per holder in the vault;
//   - enabling the layout at load (the ext4 feature, holders/, the immutable
//     flags) for an app whose manifest declares an app_storage resource.
//
// Only a vault-backed volume gets a branch: a throwaway DEK dies with the VM
// and a wrapped key under it would be lost with it, silently.

// holderFolderInfo is the HKDF label of the wrapping branch.
const holderFolderInfo = "privasys-holder-folders/v1"

// AppStorageKind is the resource kind the enclave OS serves itself.
const AppStorageKind = "app_storage"

func deriveHolderBranch(keyHex string) []byte {
	if keyHex == "" {
		return nil
	}
	secret, err := hex.DecodeString(keyHex)
	if err != nil || len(secret) == 0 {
		secret = []byte(keyHex)
	}
	branch, err := hkdf.Key(sha256.New, secret, []byte(holderFolderInfo), "branch", 32)
	if err != nil {
		return nil
	}
	return branch
}

// HolderFolders describes what the manager needs to serve holder folders
// for a loaded container.
type HolderFolders struct {
	// Mount is the volume's host mount point; folders live under
	// Mount/holders. Device is the decrypted block device (for the ext4
	// feature check).
	Mount, Device string
	// WrapKey is the key that wraps holder keys for this app (32 bytes),
	// derived from the DEK branch. Never the DEK.
	WrapKey []byte
	// AppID is the platform app id (hex).
	AppID string
}

// declaresAppStorage reports whether a manifest declares holder folders.
func declaresAppStorage(decls []ResourceDecl) bool {
	for _, d := range decls {
		if d.Kind == AppStorageKind {
			return true
		}
	}
	return false
}

// HolderFolders returns the holder-folder context of a loaded container, or
// an error saying why the container cannot have any: no encrypted volume,
// no vault-backed key, or no declaration.
func (l *Launcher) HolderFolders(name string) (HolderFolders, error) {
	l.mu.RLock()
	branch := l.holderBranches[name]
	decls := l.resourceDecls[name]
	appID := hex.EncodeToString(l.appIDs[name])
	l.mu.RUnlock()
	if !declaresAppStorage(decls) {
		return HolderFolders{}, fmt.Errorf("launcher: container %q declares no %s resource", name, AppStorageKind)
	}
	if len(branch) == 0 {
		return HolderFolders{}, fmt.Errorf("launcher: container %q has no vault-backed encrypted volume; holder folders require one", name)
	}
	wrap, err := hkdf.Key(sha256.New, branch, nil, holderFolderInfo+"|wrap|"+appID, 32)
	if err != nil {
		return HolderFolders{}, fmt.Errorf("launcher: derive wrap key: %w", err)
	}
	return HolderFolders{
		Mount:   volume.MountBase + "/" + name,
		Device:  "/dev/mapper/container-" + name,
		WrapKey: wrap,
		AppID:   appID,
	}, nil
}

// HostUID maps a uid inside the container to the host uid that owns its
// files: the id map under user-namespace remap, identity otherwise.
func (l *Launcher) HostUID(containerUID int) int {
	if l.cfg.IsolationUserns {
		return container.HostUIDFor(containerUID)
	}
	return containerUID
}

// enableHolderFolders prepares the volume layout at load for an app that
// declares app_storage. A failure fails the load: an app that declared
// holder folders and got a plain volume would keep holder data unkeyed.
func (l *Launcher) enableHolderFolders(name string, decls []ResourceDecl, branch []byte) error {
	if !declaresAppStorage(decls) {
		return nil
	}
	if len(branch) == 0 {
		return fmt.Errorf("launcher: %s declares %s but has no vault-backed encrypted volume", name, AppStorageKind)
	}
	return holders.Enable(volume.MountBase+"/"+name, "/dev/mapper/container-"+name)
}

// storageFact is the value of oids.WorkloadStorage for a container: empty
// for a plain volume or none (so certificates of existing apps do not
// change), otherwise what was attached.
func storageFact(volume, holderFolders bool) string {
	if !holderFolders {
		return ""
	}
	fact := "holder-folders,immutable-root"
	if volume {
		fact = "volume," + fact
	}
	return fact
}
