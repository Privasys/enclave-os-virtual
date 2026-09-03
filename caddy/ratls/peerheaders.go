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
// identity. Everything under it is manager-owned: the ingress scrubs any
// inbound value a remote client set before populating its own, so a caller can
// never spoof its attested identity by sending these headers itself.
const peerHeaderPrefix = "X-Privasys-Peer-"

const (
	// hdrPeerCertDER carries the base64 DER of the TLS-verified client leaf
	// certificate. The manager (same TDX TCB) matches it against the verdict it
	// recorded for the connection when the caller presented its evidence.
	hdrPeerCertDER = "X-Privasys-Peer-Cert-Der"
	// hdrPeerConn carries the connection identifier (the remote address, unique
	// per TCP connection) under which the attest handler forwarded the caller's
	// evidence to the manager, so the manager can look up the verdict.
	hdrPeerConn = "X-Privasys-Peer-Conn"
)

// PeerHeaders runs on mutual-RA-TLS ingress routes. It (1) strips every
// inbound X-Privasys-Peer-* header so a remote client cannot forge its attested
// identity, and (2) republishes the TLS-verified client leaf certificate and the
// connection identifier for the trusted manager hop. Caddy asked for a client
// certificate at the TLS layer (connection policy mode "request"); the
// caller's evidence for that certificate arrives through the attest handler
// (present) and is verified by the manager, which records a per-connection
// verdict that this header lets it find.
//
// Trust model: Caddy, the manager and the container share one TDX-measured TCB
// (dm-verity rootfs + measured boot), so passing the certificate across the
// in-TCB plaintext hop is no weaker than terminating TLS at the container.
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
// certificate and the connection identifier for the manager.
func (h *PeerHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	for name := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), peerHeaderPrefix) {
			r.Header.Del(name)
		}
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf := r.TLS.PeerCertificates[0]
		r.Header.Set(hdrPeerCertDER, base64.StdEncoding.EncodeToString(leaf.Raw))
		r.Header.Set(hdrPeerConn, r.RemoteAddr)
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile is a no-op parser so the directive can appear bare.
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
