// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package container

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestIdmapMountsInactiveIsNoop(t *testing.T) {
	in := []specs.Mount{{Destination: "/data", Source: "/host/vol", Type: "bind"}}
	out := idmapMounts(in, false)
	if len(out) != 1 || out[0].UIDMappings != nil || out[0].GIDMappings != nil {
		t.Fatalf("inactive idmapMounts must not stamp mappings, got %+v", out[0])
	}
}

func TestIdmapMountsActiveStampsRange(t *testing.T) {
	in := []specs.Mount{
		{Destination: "/data", Source: "/host/vol"},
		{Destination: "/etc/hosts", Source: "/run/containers-dns/hosts"},
	}
	out := idmapMounts(in, true)
	for i, m := range out {
		if len(m.UIDMappings) != 1 || len(m.GIDMappings) != 1 {
			t.Fatalf("mount %d: expected one uid+gid mapping, got uid=%v gid=%v", i, m.UIDMappings, m.GIDMappings)
		}
		got := m.UIDMappings[0]
		if got.ContainerID != 0 || got.HostID != usernsHostBaseUID || got.Size != usernsMapSize {
			t.Fatalf("mount %d: uid map = %+v, want {0, %d, %d}", i, got, usernsHostBaseUID, usernsMapSize)
		}
	}
}

// The spec's user namespace and the bind maps must describe the SAME host
// range, or the container sees inconsistent ownership. Guard that invariant.
func TestUsernsIDMapMatchesConstants(t *testing.T) {
	m := usernsIDMap()
	if len(m) != 1 {
		t.Fatalf("usernsIDMap must be a single range, got %d", len(m))
	}
	if m[0].ContainerID != 0 || m[0].HostID != usernsHostBaseUID || m[0].Size != usernsMapSize {
		t.Fatalf("usernsIDMap = %+v, want {0, %d, %d}", m[0], usernsHostBaseUID, usernsMapSize)
	}
}
