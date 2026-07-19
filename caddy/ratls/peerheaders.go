package ratls

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(PeerHeaders{})
}

// peerHeaderPrefix is the reserved header namespace for attested-caller
// identity. Everything under it is manager-owned: the ingress must scrub any
// inbound value a remote client set before populating its own, so a caller can
// never spoof its attested identity by sending these headers itself.
const peerHeaderPrefix = "X-Privasys-Peer-"

const (
	// hdrPeerCertDER carries the base64 DER of the verified-at-TLS client leaf
	// certificate, handed to the manager (same TDX TCB) which performs the full
	// RA-TLS quote/measurement/OID verification with its live attestation token.
	hdrPeerCertDER = "X-Privasys-Peer-Cert-Der"
	// hdrPeerChannelBinder carries the base64 32-byte RA-TLS channel binder for
	// this TLS session (fork field ConnectionState.RATLSChannelBinder, populated
	// server-side). The manager recomputes the caller cert's report_data against
	// it so a relayed client cert from another session fails closed.
	hdrPeerChannelBinder = "X-Privasys-Peer-Channel-Binder"
)

// PeerHeaders is a Caddy HTTP handler that runs on mutual-RA-TLS ingress routes.
// It (1) strips every inbound X-Privasys-Peer-* header so a remote client cannot
// forge its attested identity, and (2) re-publishes the TLS-verified client leaf
// certificate and this session's channel binder as headers for the trusted
// manager hop to verify. Caddy has already required a client certificate at the
// TLS layer (connection policy client_authentication mode "require"); this
// handler exposes the raw material the manager needs to turn that certificate
// into an attested caller identity.
//
// Trust model: Caddy, the manager and the container share one TDX-measured TCB
// (dm-verity rootfs + measured boot), so passing the cert and binder across the
// in-TCB plaintext hop is no weaker than terminating TLS at the container. The
// only external actor is the caller, whose forged headers are removed here.
type PeerHeaders struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (PeerHeaders) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.privasys_peer_headers",
		New: func() caddy.Module { return new(PeerHeaders) },
	}
}

// Provision sets up the handler.
func (h *PeerHeaders) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	return nil
}

// ServeHTTP scrubs inbound peer headers and republishes the verified client
// cert + channel binder for the manager.
func (h *PeerHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 1. Anti-spoof: drop every X-Privasys-Peer-* the client may have sent.
	for name := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), peerHeaderPrefix) {
			r.Header.Del(name)
		}
	}

	// 2. Publish the TLS-verified client leaf + channel binder for the manager.
	// mode "require" guarantees a peer certificate is present on these routes;
	// if somehow absent, we leave the headers unset and let the manager reject.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf := r.TLS.PeerCertificates[0]
		r.Header.Set(hdrPeerCertDER, base64.StdEncoding.EncodeToString(leaf.Raw))
		if len(r.TLS.RATLSChannelBinder) > 0 {
			r.Header.Set(hdrPeerChannelBinder,
				base64.StdEncoding.EncodeToString(r.TLS.RATLSChannelBinder))
		} else {
			// No binder means the caller did not drive the RA-TLS challenge that
			// makes the server derive one; without it the manager cannot prove
			// the cert is bound to this session, so it will fail closed.
			h.logger.Warn("mutual-RA-TLS ingress request has no channel binder; "+
				"caller must send the RA-TLS ClientHello challenge",
				zap.String("host", r.Host))
		}
	}

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile is a no-op parser so the directive can appear bare in a
// Caddyfile. The manager drives configuration via the JSON admin API, so there
// are no sub-directives.
func (h *PeerHeaders) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// Interface guards.
var (
	_ caddy.Module                = (*PeerHeaders)(nil)
	_ caddy.Provisioner           = (*PeerHeaders)(nil)
	_ caddyhttp.MiddlewareHandler = (*PeerHeaders)(nil)
	_ caddyfile.Unmarshaler       = (*PeerHeaders)(nil)
)
