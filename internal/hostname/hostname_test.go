// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package hostname

import "testing"

func TestValid(t *testing.T) {
	for _, h := range []string{"a.b", "app.apps.privasys.org", "x-1.example.com"} {
		if !Valid(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{"", "localhost", "*.apps.privasys.org", "App.example.com", "a.b.", "-a.b", "a-.b", "a..b", "a b.c", "a_b.c",
		"34.155.1.2", "127.0.0.1", "10.0.0.9", "a.123"} {
		if Valid(h) {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestUnder(t *testing.T) {
	if !Under("x.apps.privasys.org", "apps.privasys.org") || !Under("a.x.apps.privasys.org", "apps.privasys.org") {
		t.Fatal("a name below the domain is not under it")
	}
	if Under("apps.privasys.org", "apps.privasys.org") || Under("xapps.privasys.org", "apps.privasys.org") || Under("x.apps.privasys.org", "") {
		t.Fatal("a name outside the domain is under it")
	}
}
