// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Attest{})
}

const (
	// attestPath is the reserved evidence endpoint (ra-tls-clients/docs/ratls-v2.md).
	attestPath      = "/__privasys/attest"
	protocolVersion = 2
	// exporter labels of the server and client evidence.
	exporterLabelServer = "EXPORTER-privasys-ratls-attest-v2"
	exporterLabelClient = "EXPORTER-privasys-ratls-attest-v2-client"
	contextLen          = 32
	hctxLen             = 32
	quoteTimeLayout     = "2006-01-02T15:04Z"
	maxAttestBody       = 64 * 1024

	// hdrAttestation is the connection tag every request carries to the
	// workload: "none" | "deterministic" | "challenge". Set here, never by
	// the caller.
	hdrAttestation = "X-Privasys-Attestation"

	// clientContextTTL bounds the time between an attest response that
	// requires client evidence and the present message.
	clientContextTTL = 2 * time.Minute
	// connRetention drops connection records not touched for this long.
	connRetention = 30 * time.Minute
)

// Attest is the Caddy HTTP handler that serves POST /__privasys/attest and
// stamps the attestation tag on every other request of a connection.
type Attest struct {
	// ManagerURL is the in-VM manager (plain HTTP on loopback) that verifies
	// client evidence on mutual hosts (POST /api/v1/peer-evidence).
	ManagerURL string `json:"manager_url,omitempty"`

	logger *zap.Logger
	http   *http.Client
}

// connInfo is what the handler remembers per TLS connection (keyed by the
// remote address, unique per TCP connection).
type connInfo struct {
	tag           string
	touched       time.Time
	clientContext []byte
	clientCtxAt   time.Time
}

var conns = struct {
	mu sync.Mutex
	m  map[string]*connInfo
}{m: map[string]*connInfo{}}

func connFor(remote string, create bool) *connInfo {
	conns.mu.Lock()
	defer conns.mu.Unlock()
	now := time.Now()
	if len(conns.m) > 4096 {
		for k, c := range conns.m {
			if now.Sub(c.touched) > connRetention {
				delete(conns.m, k)
			}
		}
	}
	c := conns.m[remote]
	if c == nil && create {
		c = &connInfo{tag: "none"}
		conns.m[remote] = c
	}
	if c != nil {
		c.touched = now
	}
	return c
}

// CaddyModule returns the Caddy module information.
func (Attest) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.privasys_attest",
		New: func() caddy.Module { return new(Attest) },
	}
}

// Provision sets up the handler.
func (h *Attest) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	h.http = &http.Client{Timeout: 15 * time.Second}
	return nil
}

// ServeHTTP answers the evidence endpoint and tags every other request.
func (h *Attest) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	r.Header.Del(hdrAttestation)
	if r.URL.Path == attestPath {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return nil
		}
		h.handle(w, r)
		return nil
	}
	tag := "none"
	if c := connFor(r.RemoteAddr, false); c != nil {
		tag = c.tag
	}
	r.Header.Set(hdrAttestation, tag)
	return next.ServeHTTP(w, r)
}

type attestRequest struct {
	V       int    `json:"v"`
	Mode    string `json:"mode"`
	Leaf    string `json:"leaf"`
	Context string `json:"context"`
	// present
	TEE         string  `json:"tee"`
	Quote       string  `json:"quote"`
	GPUEvidence *string `json:"gpu_evidence"`
	QuoteTime   string  `json:"quote_time"`
}

type attestResponse struct {
	V              int     `json:"v"`
	Mode           string  `json:"mode"`
	TEE            string  `json:"tee"`
	Quote          string  `json:"quote"`
	GPUEvidence    *string `json:"gpu_evidence"`
	QuoteTime      string  `json:"quote_time"`
	ClientEvidence string  `json:"client_evidence"`
	ClientContext  *string `json:"client_context"`
}

var b64 = base64.RawURLEncoding

func b64Decode(s string) ([]byte, error) {
	return b64.DecodeString(strings.TrimRight(s, "="))
}

func (h *Attest) fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"v": protocolVersion, "error": msg})
}

func (h *Attest) handle(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
		h.fail(w, http.StatusBadRequest, "RA-TLS v2 needs a TLS 1.3 connection")
		return
	}
	// The gateway's terminate path serves the public certificate and re-dials
	// inward; it marks itself, and evidence cannot be bound to the outer leg.
	if r.Header.Get("X-Privasys-Edge") == "terminate" {
		h.fail(w, http.StatusNotFound, "no evidence on the gateway terminate path")
		return
	}
	g := current.Load()
	if g == nil {
		h.fail(w, http.StatusServiceUnavailable, "attestation not provisioned")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAttestBody))
	if err != nil {
		h.fail(w, http.StatusBadRequest, "unreadable body")
		return
	}
	var req attestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.fail(w, http.StatusBadRequest, "malformed JSON")
		return
	}
	if req.V != protocolVersion {
		h.fail(w, http.StatusBadRequest, fmt.Sprintf("unsupported protocol version %d", req.V))
		return
	}
	switch req.Mode {
	case "deterministic", "challenge":
		h.serveEvidence(w, r, g, &req)
	case "present":
		h.acceptClientEvidence(w, r, &req)
	default:
		h.fail(w, http.StatusBadRequest, "unknown mode")
	}
}

// serveEvidence answers a deterministic or challenge request for the leaf the
// client received.
func (h *Attest) serveEvidence(w http.ResponseWriter, r *http.Request, g *RATLSCertGetter, req *attestRequest) {
	leafHash, err := b64Decode(req.Leaf)
	if err != nil || len(leafHash) != 32 {
		h.fail(w, http.StatusBadRequest, "leaf must be the base64url SHA-256 of the leaf SPKI")
		return
	}
	var h32 [32]byte
	copy(h32[:], leafHash)
	lk := leafBySPKI(h32)
	if lk == nil {
		h.fail(w, http.StatusNotFound, "unknown leaf")
		return
	}

	resp := attestResponse{V: protocolVersion, Mode: req.Mode, TEE: g.attester.Name(), ClientEvidence: "none"}
	var gpu []byte
	switch req.Mode {
	case "deterministic":
		cq, err := lk.deterministicQuote(g)
		if err != nil {
			h.logger.Error("deterministic quote failed", zap.Error(err))
			h.fail(w, http.StatusServiceUnavailable, "quote provider unavailable")
			return
		}
		resp.Quote = b64.EncodeToString(cq.quote)
		resp.QuoteTime = cq.quoteTime
		gpu = cq.gpu
	case "challenge":
		ctx, err := b64Decode(req.Context)
		if err != nil || len(ctx) != contextLen {
			h.fail(w, http.StatusBadRequest, "context must be 32 bytes, base64url")
			return
		}
		hctx, err := r.TLS.ExportKeyingMaterial(exporterLabelServer, ctx, hctxLen)
		if err != nil {
			h.fail(w, http.StatusBadRequest, "exporter unavailable on this connection")
			return
		}
		var gpuSum [32]byte
		var gpuOK bool
		gpu, gpuSum, gpuOK = loadGPUEvidence(g.GPUEvidenceDir)
		binding := append(append([]byte(nil), ctx...), hctx...)
		rd := reportData(lk.spkiHash, gpuBinding(binding, gpuSum, gpuOK))
		quote, err := g.attester.Quote(rd)
		if err != nil {
			h.logger.Error("challenge quote failed", zap.Error(err))
			h.fail(w, http.StatusServiceUnavailable, "quote provider unavailable")
			return
		}
		resp.Quote = b64.EncodeToString(quote)
		resp.QuoteTime = time.Now().UTC().Format(quoteTimeLayout)
	}
	if len(gpu) > 0 {
		s := b64.EncodeToString(gpu)
		resp.GPUEvidence = &s
		resp.TEE = g.attester.Name() + "-gpu"
	}

	c := connFor(r.RemoteAddr, true)
	c.tag = req.Mode
	// A caller that presented a client certificate must prove it: a mutual
	// leg. The context is remembered for the present message.
	if len(r.TLS.PeerCertificates) > 0 {
		cc := make([]byte, contextLen)
		if _, err := rand.Read(cc); err != nil {
			h.fail(w, http.StatusInternalServerError, "rng")
			return
		}
		conns.mu.Lock()
		c.clientContext, c.clientCtxAt = cc, time.Now()
		conns.mu.Unlock()
		s := b64.EncodeToString(cc)
		resp.ClientEvidence = "required"
		resp.ClientContext = &s
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
	h.logger.Debug("evidence served",
		zap.String("mode", req.Mode),
		zap.String("remote", r.RemoteAddr),
		zap.Bool("client_evidence_required", resp.ClientEvidence == "required"))
}

// acceptClientEvidence forwards a present message, with this connection's
// client exporter value and the TLS-verified client leaf, to the manager,
// which verifies it against the host's allowed-caller policy and records the
// verdict for the connection.
func (h *Attest) acceptClientEvidence(w http.ResponseWriter, r *http.Request, req *attestRequest) {
	if len(r.TLS.PeerCertificates) == 0 {
		h.fail(w, http.StatusBadRequest, "no client certificate on this connection")
		return
	}
	c := connFor(r.RemoteAddr, false)
	conns.mu.Lock()
	var cc []byte
	var at time.Time
	if c != nil {
		cc, at = c.clientContext, c.clientCtxAt
		c.clientContext = nil
	}
	conns.mu.Unlock()
	if len(cc) == 0 || time.Since(at) > clientContextTTL {
		h.fail(w, http.StatusBadRequest, "no pending client_context for this connection")
		return
	}
	ctx, err := b64Decode(req.Context)
	if err != nil || !bytes.Equal(ctx, cc) {
		h.fail(w, http.StatusBadRequest, "context does not match the client_context issued")
		return
	}
	hctx, err := r.TLS.ExportKeyingMaterial(exporterLabelClient, cc, hctxLen)
	if err != nil {
		h.fail(w, http.StatusBadRequest, "exporter unavailable on this connection")
		return
	}
	if h.ManagerURL == "" {
		h.fail(w, http.StatusNotImplemented, "client evidence is not verified on this host")
		return
	}
	leaf := r.TLS.PeerCertificates[0]
	fwd := map[string]any{
		"v":            protocolVersion,
		"conn":         r.RemoteAddr,
		"host":         r.Host,
		"sni":          r.TLS.ServerName,
		"cert_der":     b64.EncodeToString(leaf.Raw),
		"context":      b64.EncodeToString(cc),
		"hctx":         b64.EncodeToString(hctx),
		"tee":          req.TEE,
		"quote":        req.Quote,
		"gpu_evidence": req.GPUEvidence,
		"quote_time":   req.QuoteTime,
	}
	payload, _ := json.Marshal(fwd)
	mreq, err := http.NewRequest(http.MethodPost, strings.TrimRight(h.ManagerURL, "/")+"/api/v1/peer-evidence", bytes.NewReader(payload))
	if err != nil {
		h.fail(w, http.StatusInternalServerError, "manager request")
		return
	}
	mreq.Header.Set("Content-Type", "application/json")
	resp, err := h.http.Do(mreq)
	if err != nil {
		h.logger.Error("peer-evidence forward failed", zap.Error(err))
		h.fail(w, http.StatusBadGateway, "manager unreachable")
		return
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		h.logger.Warn("client evidence rejected",
			zap.String("remote", r.RemoteAddr),
			zap.String("host", r.Host),
			zap.Int("status", resp.StatusCode))
		h.fail(w, http.StatusForbidden, strings.TrimSpace(string(rb)))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UnmarshalCaddyfile parses `privasys_attest { manager_url <url> }`.
func (h *Attest) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "manager_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.ManagerURL = d.Val()
		default:
			return d.Errf("unrecognised sub-directive: %s", d.Val())
		}
	}
	return nil
}

// leafIDOf is the "leaf" value of a certificate: base64url SHA-256 of its SPKI.
func leafIDOf(spkiDER []byte) string {
	h := sha256.Sum256(spkiDER)
	return b64.EncodeToString(h[:])
}

// Interface guards.
var (
	_ caddy.Module                = (*Attest)(nil)
	_ caddy.Provisioner           = (*Attest)(nil)
	_ caddyhttp.MiddlewareHandler = (*Attest)(nil)
	_ caddyfile.Unmarshaler       = (*Attest)(nil)
)
