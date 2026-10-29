package bootstrap

import "testing"

func TestNextGeneration(t *testing.T) {
	for in, want := range map[string]string{
		"apps.privasys.org/abc/manager/data/v1": "apps.privasys.org/abc/manager/data/v2",
		"apps.privasys.org/abc/manager/data/v9": "apps.privasys.org/abc/manager/data/v10",
	} {
		if got, err := nextGeneration(in); err != nil || got != want {
			t.Errorf("nextGeneration(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"apps.privasys.org/abc/manager/data", "x/v0", "x/vx", ""} {
		if _, err := nextGeneration(bad); err == nil {
			t.Errorf("nextGeneration(%q) accepted", bad)
		}
	}
}
