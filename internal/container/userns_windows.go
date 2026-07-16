// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package container

import "github.com/containerd/containerd/v2/core/snapshots"

// remapperSnapshotOpts is a no-op on Windows — the enclave OS only ever runs on
// linux; this stub exists solely so the package stays buildable on a Windows
// dev box (client.WithRemapperLabels is unix-only). userns remap is never
// active off-unix.
func remapperSnapshotOpts(active bool) []snapshots.Opt { return nil }
