package main

import "testing"

func TestAppAudience(t *testing.T) {
	for in, want := range map[string]string{
		"privasys-platform":      "privasys-platform",
		"privasys-platform-test": "privasys-platform-test",
		defaultOIDCAudience:      "",
		"":                       "",
		" privasys-platform ":    "privasys-platform",
	} {
		if got := appAudience(in); got != want {
			t.Errorf("appAudience(%q) = %q, want %q", in, got, want)
		}
	}
}
