// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package network

import (
	"strings"
	"testing"
)

func nameserversOf(body []byte) []string {
	var ns []string
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			ns = append(ns, f[1])
		}
	}
	return ns
}

func TestResolvConfFrom(t *testing.T) {
	cases := []struct {
		name     string
		upstream string
		want     []string
	}{
		{
			// The GCE case: the only DHCP-issued upstream is the metadata IP.
			// It MUST be stripped and replaced with public DNS, or every
			// container's DNS black-holes against Setup's FORWARD drop.
			name:     "gce metadata-only upstream falls back to public",
			upstream: "nameserver 169.254.169.254\n",
			want:     []string{fallbackNameserverPrimary, fallbackNameserverSecondary},
		},
		{
			name:     "real upstreams pass through untouched",
			upstream: "nameserver 10.0.0.53\nnameserver 10.0.0.54\n",
			want:     []string{"10.0.0.53", "10.0.0.54"},
		},
		{
			name:     "metadata stripped, real upstream kept",
			upstream: "nameserver 169.254.169.254\nnameserver 10.0.0.53\n",
			want:     []string{"10.0.0.53"},
		},
		{
			name:     "empty upstream falls back to public",
			upstream: "",
			want:     []string{fallbackNameserverPrimary, fallbackNameserverSecondary},
		},
		{
			// search/options lines are dropped; only nameservers propagate.
			name:     "search and options ignored",
			upstream: "search c.example.internal\noptions ndots:5\nnameserver 10.0.0.53\n",
			want:     []string{"10.0.0.53"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nameserversOf(resolvConfFrom([]byte(tc.upstream)))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("resolvConfFrom(%q) nameservers = %v, want %v", tc.upstream, got, tc.want)
			}
		})
	}
}
