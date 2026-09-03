package manager

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-os-virtual/internal/tdx"
	"go.uber.org/zap"
)

// Ingress mutual RA-TLS v2. Caddy's privasys_peer_headers handler sets the
// first two headers (inside the TDX TCB): the TLS-verified caller leaf and the
// connection identifier. The caller's evidence for that leaf arrives through
// Caddy's privasys_attest handler as a "present" message, forwarded here as
// POST /api/v1/peer-evidence together with the connection's client exporter
// value; the verdict is recorded per connection and consulted on every request
// of that connection. The remaining headers are what the manager sets for the
// container after a successful verification. Every X-Privasys-Peer-* header is
// stripped from a request that fails or is not a mutual-auth host, so a caller
// can never inject its own attested identity.
const (
	hdrPeerCertDER = "X-Privasys-Peer-Cert-Der"
	hdrPeerConn    = "X-Privasys-Peer-Conn"

	hdrPeerAppID       = "X-Privasys-Peer-App-Id"
	hdrPeerImageDigest = "X-Privasys-Peer-Image-Digest"
	hdrPeerMeasurement = "X-Privasys-Peer-Measurement"
	hdrPeerVerified    = "X-Privasys-Peer-Verified"

	peerHeaderPrefix = "X-Privasys-Peer-"

	// verdictTTL is how long a verified caller stays verified on one
	// connection. SDK clients re-attest every 5 minutes; a minute of slack.
	verdictTTL = 6 * time.Minute
)

// peerVerdict is the recorded verification of one caller on one connection.
type peerVerdict struct {
	certFP [32]byte
	host   string
	info   ratls.CertInfo
	at     time.Time
}

// ingressVerifier holds the per-host allowed-caller policies and the
// per-connection verdicts.
type ingressVerifier struct {
	log *zap.Logger

	// attServer resolves the attestation server URL + bearer token used to
	// verify a caller's TDX quote signature (the Intel DCAP check). Without it,
	// verification fails closed.
	attServer func() (url, token string)

	// allowDebugImages permits callers running a non-production ("dev") image
	// profile. Enabled on dev platforms; false on production.
	allowDebugImages bool

	mu       sync.RWMutex
	policies map[string]*ratls.DependencySet // lowercase host → allowed callers
	verdicts map[string]*peerVerdict         // connection id → verdict
}

func newIngressVerifier(log *zap.Logger, attServer func() (string, string), allowDebugImages bool) *ingressVerifier {
	return &ingressVerifier{
		log:              log.Named("ingress-verify"),
		attServer:        attServer,
		allowDebugImages: allowDebugImages,
		policies:         make(map[string]*ratls.DependencySet),
		verdicts:         make(map[string]*peerVerdict),
	}
}

// setPolicy installs (or, with a nil policy, removes) the allowed-caller set for
// a host. Called by the launcher via the manager's RegisterIngressPolicy.
func (v *ingressVerifier) setPolicy(host string, policy *ratls.DependencySet) {
	h := strings.ToLower(host)
	v.mu.Lock()
	defer v.mu.Unlock()
	if policy == nil || len(policy.Entries) == 0 {
		delete(v.policies, h)
		return
	}
	v.policies[h] = policy
}

// policyFor returns the allowed-caller set for a host, if it is a mutual-auth host.
func (v *ingressVerifier) policyFor(host string) (*ratls.DependencySet, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	p, ok := v.policies[strings.ToLower(host)]
	return p, ok
}

// enforce is the ingress gate. For a mutual-auth host it looks up the verdict
// recorded for the connection and rewrites the X-Privasys-Peer-* headers to
// the verified identity; a caller that presented a certificate without a
// current verdict is rejected. For a non-mutual host it strips any peer
// headers and returns nil.
func (v *ingressVerifier) enforce(r *http.Request) error {
	host := hostOnly(r.Host)
	_, mutual := v.policyFor(host)
	if !mutual {
		stripPeerHeaders(r)
		return nil
	}

	certB64 := r.Header.Get(hdrPeerCertDER)
	conn := r.Header.Get(hdrPeerConn)
	stripPeerHeaders(r)

	if certB64 == "" {
		// No client certificate: an ANONYMOUS caller, not a failed one. The
		// same hostname serves browsers whose connections the gateway
		// terminates and re-dials inward without a client certificate. Nothing
		// is granted: with no X-Privasys-Peer-* headers, anything the app gates
		// on an attested caller still fails closed.
		return nil
	}
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("undecodable peer certificate: %w", err)
	}
	fp := sha256.Sum256(certDER)

	v.mu.RLock()
	verdict := v.verdicts[conn]
	v.mu.RUnlock()
	if verdict == nil || verdict.certFP != fp || time.Since(verdict.at) > verdictTTL {
		// A caller that presents a certificate must have proven it on this
		// connection (present), and within the re-attestation window.
		return fmt.Errorf("caller presented a certificate without current evidence on this connection (attest with client evidence first)")
	}
	if !strings.EqualFold(verdict.host, host) {
		return fmt.Errorf("caller evidence was verified for host %q, not %q", verdict.host, host)
	}

	info := verdict.info
	r.Header.Set(hdrPeerVerified, "true")
	if id := oidFromInfo(info, ratls.OidWorkloadAppID); id != "" {
		r.Header.Set(hdrPeerAppID, id)
	}
	if dg := oidFromInfo(info, ratls.OidWorkloadCodeHash); dg != "" {
		r.Header.Set(hdrPeerImageDigest, dg)
	}
	if info.Quote != nil && len(info.Quote.Raw) >= ratls.TDXQuoteMRTDEnd {
		r.Header.Set(hdrPeerMeasurement,
			hex.EncodeToString(info.Quote.Raw[ratls.TDXQuoteMRTDOff:ratls.TDXQuoteMRTDEnd]))
	}
	return nil
}

// peerEvidenceRequest is what Caddy's attest handler forwards for a present
// message: the caller's leaf, the connection's client context and exporter
// value, and the caller's evidence.
type peerEvidenceRequest struct {
	V           int     `json:"v"`
	Conn        string  `json:"conn"`
	Host        string  `json:"host"`
	SNI         string  `json:"sni"`
	CertDER     string  `json:"cert_der"`
	Context     string  `json:"context"`
	Hctx        string  `json:"hctx"`
	TEE         string  `json:"tee"`
	Quote       string  `json:"quote"`
	GPUEvidence *string `json:"gpu_evidence"`
	QuoteTime   string  `json:"quote_time"`
}

// verifyPeerEvidence verifies a caller's evidence against the host's
// allowed-caller policy and records the verdict for the connection.
func (v *ingressVerifier) verifyPeerEvidence(req *peerEvidenceRequest) error {
	host := hostOnly(req.Host)
	policy, mutual := v.policyFor(host)
	if !mutual {
		return fmt.Errorf("host %q does not accept attested callers", host)
	}
	certDER, err := b64urlDecode(req.CertDER)
	if err != nil {
		return fmt.Errorf("cert_der: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("unparseable peer certificate: %w", err)
	}
	ctx, err := b64urlDecode(req.Context)
	if err != nil || len(ctx) != ratls.ContextLen {
		return fmt.Errorf("context must be %d bytes", ratls.ContextLen)
	}
	hctx, err := b64urlDecode(req.Hctx)
	if err != nil || len(hctx) != ratls.HctxLen {
		return fmt.Errorf("hctx must be %d bytes", ratls.HctxLen)
	}
	quote, err := b64urlDecode(req.Quote)
	if err != nil || len(quote) == 0 {
		return fmt.Errorf("quote must be base64url")
	}
	ev := &ratls.Evidence{
		Mode:         ratls.AttestationChallenge,
		TEE:          req.TEE,
		Quote:        quote,
		QuoteTimeRaw: req.QuoteTime,
		Context:      ctx,
		Hctx:         hctx,
	}
	if req.GPUEvidence != nil && *req.GPUEvidence != "" {
		if ev.GPUEvidence, err = b64urlDecode(*req.GPUEvidence); err != nil {
			return fmt.Errorf("gpu_evidence must be base64url")
		}
	}

	attURL, attToken := v.attServer()
	if attURL == "" {
		return fmt.Errorf("no attestation server configured; cannot verify caller quote signature")
	}
	// Step 1: quote signature (Intel DCAP, via the attestation server) and the
	// binding of report_data to the caller's leaf key, the client context and
	// this connection's exporter value, with no measurement pinned.
	base := &ratls.VerificationPolicy{
		TEE: ratls.TeeTypeTDX,
		QuoteVerification: &ratls.QuoteVerificationConfig{
			Endpoint: attURL,
			Token:    attToken,
		},
		AllowDebugImages: v.allowDebugImages,
	}
	info, err := ratls.VerifyEvidence(cert, ev, base)
	if err != nil {
		return fmt.Errorf("caller evidence verification failed: %w", err)
	}

	// Step 2: match the (now trusted) evidence and OIDs against an
	// allowed-caller entry whose app-id matches the caller.
	callerAppID := oidFromInfoRaw(info, ratls.OidWorkloadAppID)
	var lastErr error
	matchedEntry := false
	for i := range policy.Entries {
		entry := policy.Entries[i]
		if entry.AppID != "" && !appIDMatches(entry.AppID, callerAppID) {
			continue
		}
		matchedEntry = true
		if err := ratls.MatchDependency(info, ratls.TeeTypeTDX, entry); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
		}
	}
	if !matchedEntry {
		return fmt.Errorf("no allowed-caller entry matches caller app-id %s", hex.EncodeToString(callerAppID))
	}
	if lastErr != nil {
		return fmt.Errorf("caller did not satisfy any allowed-caller entry: %w", lastErr)
	}

	v.mu.Lock()
	if len(v.verdicts) > 4096 {
		now := time.Now()
		for k, vd := range v.verdicts {
			if now.Sub(vd.at) > verdictTTL {
				delete(v.verdicts, k)
			}
		}
	}
	v.verdicts[req.Conn] = &peerVerdict{certFP: sha256.Sum256(certDER), host: host, info: info, at: time.Now()}
	v.mu.Unlock()
	v.log.Debug("ingress caller verified",
		zap.String("host", host),
		zap.String("conn", req.Conn),
		zap.String("caller_app_id", hex.EncodeToString(callerAppID)))
	return nil
}

// handlePeerEvidence is POST /api/v1/peer-evidence: Caddy forwards a caller's
// present message here. Reachable from the host only.
func (s *Server) handlePeerEvidence(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !isLoopbackHost(host) {
		s.jsonError(w, http.StatusForbidden, "this endpoint is reachable only from the host")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	var req peerEvidenceRequest
	if err := json.Unmarshal(body, &req); err != nil || req.V != ratls.ProtocolVersion {
		s.jsonError(w, http.StatusBadRequest, "malformed peer-evidence body")
		return
	}
	if err := s.ingress.verifyPeerEvidence(&req); err != nil {
		s.log.Warn("ingress caller verification failed",
			zap.String("host", req.Host), zap.String("conn", req.Conn), zap.Error(err))
		s.jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// stripPeerHeaders removes every X-Privasys-Peer-* header from the request.
func stripPeerHeaders(r *http.Request) {
	for name := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), peerHeaderPrefix) {
			r.Header.Del(name)
		}
	}
}

func oidFromInfoRaw(info ratls.CertInfo, dotted string) []byte {
	for _, e := range info.CustomOids {
		if e.OID == dotted {
			return e.Value
		}
	}
	return nil
}

// oidFromInfo returns a hex-encoded custom OID value from cert info, or "".
func oidFromInfo(info ratls.CertInfo, dotted string) string {
	if b := oidFromInfoRaw(info, dotted); b != nil {
		return hex.EncodeToString(b)
	}
	return ""
}

// appIDMatches reports whether the allowed-caller entry's app-id (lowercase
// hex of the raw app-id bytes, the OID 4.1 value) equals the caller's.
func appIDMatches(entryAppID string, callerAppID []byte) bool {
	if len(callerAppID) == 0 {
		return false
	}
	return strings.EqualFold(entryAppID, hex.EncodeToString(callerAppID))
}

// RegisterIngressPolicy installs the per-host allowed-caller policy for an
// ingress mutual-RA-TLS app. Passing nil disables verification for the host.
func (s *Server) RegisterIngressPolicy(hostname string, policy *ratls.DependencySet) {
	s.ingress.setPolicy(hostname, policy)
}

// -- container identity and evidence (v2) ------------------------------------

// containerFromRequest authenticates an in-enclave caller by its container
// token and returns the container name.
func (s *Server) containerFromRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !isInEnclaveCaller(host) {
		s.jsonError(w, http.StatusForbidden, "this endpoint is reachable only from inside the enclave")
		return "", false
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		s.jsonError(w, http.StatusUnauthorized, "expected Bearer PRIVASYS_CONTAINER_TOKEN")
		return "", false
	}
	name := s.launcher.LookupContainerByToken(strings.TrimPrefix(authHeader, "Bearer "))
	if name == "" {
		s.jsonError(w, http.StatusUnauthorized, "invalid container token")
		return "", false
	}
	return name, true
}

// handleMintEgressIdentity mints the calling container's RA-TLS v2 client
// identity for app-to-app and vault calls: leaf key, chain, code digest (OID
// 4.2) and app id (OID 4.1), no evidence. The app never mints its own identity,
// so the measured manager stays the sole minter and the stamped app id is
// trustworthy. The identity is valid for an hour; evidence for it is minted per
// connection by handleEgressEvidence. Serves POST /api/v1/egress-identity and
// POST /api/v1/vault-identity.
func (s *Server) handleMintEgressIdentity(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	certPEM, keyPEM, err := s.launcher.MintIdentity(name)
	if err != nil {
		s.log.Warn("mint identity failed", zap.String("container", name), zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, "failed to mint identity")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cert_pem": string(certPEM),
		"key_pem":  string(keyPEM),
	})
}

// handleEgressEvidence mints the calling container's client evidence for one
// connection (POST /api/v1/egress-evidence): a TDX quote whose report_data is
// SHA-512( SHA-256(SPKI) || context || hctx ), where the SPKI must belong to an
// identity this manager minted for the container. Only the container knows its
// connection's exporter value; the manager only quotes keys it issued to it.
func (s *Server) handleEgressEvidence(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		V          int    `json:"v"`
		SPKISHA256 string `json:"spki_sha256"`
		Context    string `json:"context"`
		Hctx       string `json:"hctx"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&body); err != nil || body.V != ratls.ProtocolVersion {
		s.jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	spkiHash, err := b64urlDecode(body.SPKISHA256)
	if err != nil || len(spkiHash) != 32 {
		s.jsonError(w, http.StatusBadRequest, "spki_sha256 must be 32 bytes, base64url")
		return
	}
	ctx, err := b64urlDecode(body.Context)
	if err != nil || len(ctx) != ratls.ContextLen {
		s.jsonError(w, http.StatusBadRequest, "context must be 32 bytes, base64url")
		return
	}
	hctx, err := b64urlDecode(body.Hctx)
	if err != nil || len(hctx) != ratls.HctxLen {
		s.jsonError(w, http.StatusBadRequest, "hctx must be 32 bytes, base64url")
		return
	}
	var h32 [32]byte
	copy(h32[:], spkiHash)
	if !s.launcher.ContainerOwnsIdentity(name, h32) {
		s.jsonError(w, http.StatusForbidden, "spki_sha256 is not an identity minted for this container")
		return
	}
	preimage := make([]byte, 0, 96)
	preimage = append(preimage, spkiHash...)
	preimage = append(preimage, ctx...)
	preimage = append(preimage, hctx...)
	reportData := sha512.Sum512(preimage)
	quote, err := tdx.GetQuote(reportData)
	if err != nil {
		s.log.Warn("egress evidence quote failed", zap.String("container", name), zap.Error(err))
		s.jsonError(w, http.StatusServiceUnavailable, "quote provider unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"v":            ratls.ProtocolVersion,
		"tee":          "tdx",
		"quote":        base64.RawURLEncoding.EncodeToString(quote),
		"gpu_evidence": nil,
		"quote_time":   time.Now().UTC().Format(ratls.QuoteTimeLayout),
	})
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// isDevImageProfile reports whether this VM runs a non-production ("dev") image,
// read from the dm-verity-measured /etc/privasys/image-profile marker.
func isDevImageProfile() bool {
	b, err := os.ReadFile("/etc/privasys/image-profile")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "dev"
}
