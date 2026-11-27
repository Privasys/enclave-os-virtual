// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package hostname holds the one shape check every hostname the runtime
// serves must pass: a concrete, lowercase, fully qualified name. No wildcard,
// no trailing dot, no upper case, so that two spellings can never name the
// same host and a Caddy host matcher never becomes a pattern.
package hostname

import "strings"

// Valid reports whether h is a lowercase fully qualified hostname of at least
// two labels, each 1 to 63 letters, digits or hyphens, not starting or ending
// with a hyphen, whose last label is not all digits. That last rule keeps an
// IP address out: no top-level domain is numeric, and the control plane
// reaches an enclave by its IP address, so an app holding the IP as a name
// would receive the platform's calls.
func Valid(h string) bool {
	if len(h) == 0 || len(h) > 253 || strings.HasSuffix(h, ".") {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Under reports whether h is a name strictly below domain (one or more labels
// deep), compared exactly: both are expected to be lowercase.
func Under(h, domain string) bool {
	return domain != "" && strings.HasSuffix(h, "."+domain)
}
