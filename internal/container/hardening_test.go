package container

import (
	"context"
	"slices"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// An app container never holds CAP_NET_RAW, in any capability set, while the
// other defaults stay.
func TestAppHardeningDropsNetRaw(t *testing.T) {
	defaults := []string{"CAP_CHOWN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_KILL"}
	s := &specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{
		Bounding:  slices.Clone(defaults),
		Effective: slices.Clone(defaults),
		Permitted: slices.Clone(defaults),
	}}}
	for _, opt := range appHardening() {
		if err := opt(context.Background(), nil, nil, s); err != nil {
			t.Fatal(err)
		}
	}
	c := s.Process.Capabilities
	for name, set := range map[string][]string{"bounding": c.Bounding, "effective": c.Effective, "permitted": c.Permitted} {
		if slices.Contains(set, "CAP_NET_RAW") {
			t.Errorf("%s set keeps CAP_NET_RAW: %v", name, set)
		}
		if !slices.Contains(set, "CAP_NET_BIND_SERVICE") {
			t.Errorf("%s set lost an unrelated capability: %v", name, set)
		}
	}
}
