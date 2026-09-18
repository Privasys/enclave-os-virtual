//go:build !linux

// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package holders

import (
	"crypto/rand"
	"errors"
	"path/filepath"
)

// The runtime only ever runs on Linux; this file keeps the package, and
// everything that imports it, compiling on a developer's workstation.

const (
	Dir        = "holders"
	RawKeySize = 64
)

type Status int

const (
	Absent Status = iota + 1
	Present
	IncompletelyRemoved
)

func (s Status) String() string {
	switch s {
	case Absent:
		return "absent"
	case Present:
		return "present"
	case IncompletelyRemoved:
		return "incompletely_removed"
	}
	return "unknown"
}

var ErrBusy = errors.New("holders: files in use, key incompletely removed")

var errUnsupported = errors.New("holders: holder folders need Linux")

func FolderPath(mount, holderKey string) string { return filepath.Join(mount, Dir, holderKey) }

func ValidHolderKey(k string) bool {
	if len(k) != 32 {
		return false
	}
	for _, c := range k {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func Enable(mount, device string) error                             { return errUnsupported }
func Create(mount, holderKey string, rawKey []byte) (string, error) { return "", errUnsupported }
func Open(mount, holderKey string, rawKey []byte, hostUID int) (string, error) {
	return "", errUnsupported
}
func Close(mount, holderKey, keyID string) (Status, []int, error) { return 0, nil, errUnsupported }
func KeyStatus(mount, keyID string) (Status, error)               { return 0, errUnsupported }
func Delete(mount, holderKey string) error                        { return errUnsupported }
func Usage(mount, holderKey string) (int64, error)                { return 0, errUnsupported }
func Chown(mount, holderKey string, hostUID int) error            { return errUnsupported }
func AddKey(mount string, rawKey []byte) (string, error)          { return "", errUnsupported }

func NewRawKey() ([]byte, error) {
	k := make([]byte, RawKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}
