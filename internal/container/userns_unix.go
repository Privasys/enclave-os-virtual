// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package container

import (
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/snapshots"
)

// remapperSnapshotOpts returns the snapshot options that id-map the overlay
// rootfs to the userns host range, so container-root can read its own
// (host-root-owned) image layers under the remap. Nil when remapping is off.
// The remapper-label helper is unix-only (see the _windows stub), which is why
// this lives in a build-tagged file.
func remapperSnapshotOpts(active bool) []snapshots.Opt {
	if !active {
		return nil
	}
	return []snapshots.Opt{
		client.WithRemapperLabels(0, usernsHostBaseUID, 0, usernsHostBaseGID, usernsMapSize),
	}
}
