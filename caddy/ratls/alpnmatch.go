package ratls

import (
	"crypto/tls"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(MatchALPN{})
}

// RATLSALPN is the ALPN protocol an RA-TLS-aware client advertises. It is the
// protocol's own signal that the peer speaks RA-TLS end-to-end, and the
// platform gateway already switches on exactly this value: a ClientHello
// carrying it is SPLICED through at L4 (so the caller's client certificate and
// channel binder reach this enclave untouched), while everything else — the
// browsers — is TERMINATED at the gateway with the public wildcard certificate
// and re-dialled inward as a plain server-auth RA-TLS connection.
const RATLSALPN = "privasys-ratls/1"

// MatchALPN matches a ClientHello by advertised ALPN protocol.
//
// Why this exists: ingress mutual RA-TLS needs `client_authentication` mode
// "require" on the callee's hostname, but Caddy 2.9 only ships SNI and IP
// connection matchers, so the policy could only be keyed on SNI. An app that
// serves BOTH attested app-to-app callers and browsers does so on ONE hostname
// (same SNI), so an SNI-only policy demands a client certificate from the
// gateway's terminated browser connections too — which present none, because a
// browser cannot produce a TEE-bound client cert. The handshake then fails and
// the app is unreachable from the web the moment mutual auth is enabled.
//
// Keying the policy on the RA-TLS ALPN instead splits the two populations at
// exactly the point the protocol already distinguishes them:
//
//	privasys-ratls/1  -> spliced attested caller  -> require + verify client cert
//	h2 / http/1.1     -> gateway-terminated browser -> server-auth catch-all
//
// This is not a relaxation: a caller that wants the mutual path must speak
// RA-TLS, and on that path the certificate is still REQUIRED at TLS and then
// verified (quote, measurements, OIDs, channel binder) by the manager. A client
// that simply omits the ALPN does not gain access — it lands on the server-auth
// policy, where the app's own authentication applies and no peer identity is
// asserted, so anything gated on X-Privasys-Peer-* still fails closed.
type MatchALPN []string

// CaddyModule returns the Caddy module information.
func (MatchALPN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.privasys_alpn",
		New: func() caddy.Module { return new(MatchALPN) },
	}
}

// Match returns true when the ClientHello advertises one of the configured
// protocols. An empty matcher matches nothing: a policy that fails to name a
// protocol must not silently widen to every connection.
func (m MatchALPN) Match(hello *tls.ClientHelloInfo) bool {
	if hello == nil {
		return false
	}
	for _, want := range m {
		for _, got := range hello.SupportedProtos {
			if got == want {
				return true
			}
		}
	}
	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchALPN) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		*m = append(*m, d.RemainingArgs()...)
	}
	return nil
}

// Interface guards. The ConnectionMatcher guard matters: this module is loaded
// by ID from the generated JSON, so a signature drift would otherwise surface
// only as Caddy refusing the config on a live enclave.
var (
	_ caddy.Module               = (*MatchALPN)(nil)
	_ caddyfile.Unmarshaler      = (*MatchALPN)(nil)
	_ caddytls.ConnectionMatcher = (*MatchALPN)(nil)
)
