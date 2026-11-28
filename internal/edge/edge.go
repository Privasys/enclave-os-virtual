// Package edge names the headers that say who a request is from and which
// leg it came on, which only the runtime sets: the session relay strips
// every inbound copy, and the manager asserts them after verifying the
// caller.
package edge

import (
	"net/http"
	"strings"
)

const (
	// Header is the edge marker Caddy sets from the connection (and
	// overwrites a client's): "terminate" on the gateway-terminated leg,
	// "direct" on a direct name with the publicly trusted certificate.
	Header = "X-Privasys-Edge"
	// SubHeader is the subject the runtime asserts to the app: a sealed
	// session's, a verified direct-leg or inner bearer's, or a tool token's.
	SubHeader = "X-Privasys-Sub"
	// SubViaHeader names the tool through which SubHeader was asserted (the
	// tool token's act.client_id). Absent when the person signed in to the
	// app itself.
	SubViaHeader = "X-Privasys-Sub-Via"
)

// Says reports whether any copy of the edge marker carries one of values, in
// any letter case: a marker a client duplicated or re-cased still counts,
// and only ever makes the request stricter.
func Says(h http.Header, values ...string) bool {
	for _, line := range h.Values(Header) {
		for _, v := range strings.Split(line, ",") {
			v = strings.TrimSpace(v)
			for _, want := range values {
				if strings.EqualFold(v, want) {
					return true
				}
			}
		}
	}
	return false
}
