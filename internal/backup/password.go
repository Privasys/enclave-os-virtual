package backup

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// RepositoryInfo is the HKDF info string that turns an app's key into its
// backup repository password. Part of the recovery contract: an owner who
// holds their key material can derive the password and open the repository
// with stock kopia, without any Privasys component. Never change it.
const RepositoryInfo = "privasys/backup-repository/v1"

// RepositoryPassword derives an app's backup repository password from its
// volume key (the hex the vaults reconstruct, i.e. the owner's BYOK material):
//
//	hex( HKDF-SHA256( ikm = key bytes, salt = none, info = RepositoryInfo, 32 bytes ) )
//
// One key per app protects both its volume and its backups, while the
// repository password stays distinct from the volume's LUKS passphrase.
func RepositoryPassword(volumeKeyHex string) (string, error) {
	key, err := hex.DecodeString(volumeKeyHex)
	if err != nil {
		return "", fmt.Errorf("backup: volume key is not hex: %w", err)
	}
	if len(key) < 32 {
		return "", errors.New("backup: volume key shorter than 32 bytes")
	}
	pw, err := hkdf.Key(sha256.New, key, nil, RepositoryInfo, 32)
	if err != nil {
		return "", fmt.Errorf("backup: derive repository password: %w", err)
	}
	return hex.EncodeToString(pw), nil
}
