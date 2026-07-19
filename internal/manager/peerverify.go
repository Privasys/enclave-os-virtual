package manager

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	ratls "enclave-os-mini/clients/go/ratls"

	"go.uber.org/zap"
)

// Ingress mutual-RA-TLS headers. The first two are set by Caddy's
// privasys_peer_headers handler (inside the TDX TCB) and consumed here; they
// carry the TLS-verified caller leaf and this session's channel binder. The
// remaining headers are what the manager sets for the container AFTER a
// successful verification. Every header in the X-Privasys-Peer-* namespace is
// stripped from a request that fails or is not a mutual-auth host, so a caller
// can never inject its own attested identity.
const (
	hdrPeerCertDER       = "X-Privasys-Peer-Cert-Der"
	hdrPeerChannelBinder = "X-Privasys-Peer-Channel-Binder"

	hdrPeerAppID       = "X-Privasys-Peer-App-Id"
	hdrPeerImageDigest = "X-Privasys-Peer-Image-Digest"
	hdrPeerMeasurement = "X-Privasys-Peer-Measurement"
	hdrPeerVerified    = "X-Privasys-Peer-Verified"

	peerHeaderPrefix = "X-Privasys-Peer-"
)

// ingressVerifier holds the per-host allowed-caller policies and verifies the
// attested caller certificate on the ingress mutual-RA-TLS path. It is the
// callee-side enforcement point that enclave-os-virtual previously lacked: the
// caller's TDX quote, measurement, app identity (OID 3.6), code hash (OID 3.2)
// and channel binding are all checked here before the request reaches the app.
type ingressVerifier struct {
	log *zap.Logger

	// attServer resolves the attestation server URL + bearer token used to
	// verify a caller's TDX quote signature (the Intel DCAP check). Without it,
	// verification fails closed — measurement bytes alone are not trustworthy.
	attServer func() (url, token string)

	// allowDebugImages permits callers running a non-production ("dev") image
	// profile. Enabled on dev platforms (tdx-*-dev) where both peers are dev
	// builds; false on production so a dev caller is rejected.
	allowDebugImages bool

	mu       sync.RWMutex
	policies map[string]*ratls.DependencySet // lowercase host → allowed callers
}

func newIngressVerifier(log *zap.Logger, attServer func() (string, string), allowDebugImages bool) *ingressVerifier {
	return &ingressVerifier{
		log:              log.Named("ingress-verify"),
		attServer:        attServer,
		allowDebugImages: allowDebugImages,
		policies:         make(map[string]*ratls.DependencySet),
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

// enforce is the ingress gate. For a mutual-auth host it verifies the attested
// caller and rewrites the X-Privasys-Peer-* headers to the verified identity;
// on failure it returns an error and the caller must not be proxied. For a
// non-mutual host it strips any peer headers (defence in depth) and returns nil.
//
// The bool result reports whether the request may proceed.
func (v *ingressVerifier) enforce(r *http.Request) error {
	host := hostOnly(r.Host)
	policy, mutual := v.policyFor(host)
	if !mutual {
		// Not an ingress mutual-auth app: no attested caller identity applies,
		// so scrub the whole namespace and continue.
		stripPeerHeaders(r)
		return nil
	}

	// Snapshot the raw material handed over by Caddy, then scrub the namespace
	// so nothing survives to the app except what we re-set after verifying.
	certB64 := r.Header.Get(hdrPeerCertDER)
	binderB64 := r.Header.Get(hdrPeerChannelBinder)
	stripPeerHeaders(r)

	if certB64 == "" {
		return fmt.Errorf("no client certificate presented")
	}
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return fmt.Errorf("undecodable peer certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("unparseable peer certificate: %w", err)
	}
	binder, err := base64.StdEncoding.DecodeString(binderB64)
	if err != nil || len(binder) == 0 {
		// Channel binding is mandatory: without the session binder we cannot
		// prove the caller's quote committed to THIS TLS session, so a relayed
		// client certificate would be accepted. Fail closed.
		return fmt.Errorf("missing or undecodable channel binder (relay protection required)")
	}

	attURL, attToken := v.attServer()
	if attURL == "" {
		return fmt.Errorf("no attestation server configured; cannot verify caller quote signature")
	}

	certInfo, err := v.verifyAgainstPolicy(cert, binder, policy, attURL, attToken)
	if err != nil {
		v.log.Warn("ingress caller verification failed",
			zap.String("host", host),
			zap.Error(err))
		return err
	}

	// Success: publish the verified identity for the container.
	r.Header.Set(hdrPeerVerified, "true")
	if id := oidFromInfo(certInfo, ratls.OidWorkloadAppID); id != "" {
		r.Header.Set(hdrPeerAppID, id)
	}
	if dg := oidFromInfo(certInfo, ratls.OidWorkloadCodeHash); dg != "" {
		r.Header.Set(hdrPeerImageDigest, dg)
	}
	if certInfo.Quote != nil && len(certInfo.Quote.Raw) >= ratls.TDXQuoteMRTDEnd {
		r.Header.Set(hdrPeerMeasurement,
			hex.EncodeToString(certInfo.Quote.Raw[ratls.TDXQuoteMRTDOff:ratls.TDXQuoteMRTDEnd]))
	}
	v.log.Debug("ingress caller verified",
		zap.String("host", host),
		zap.String("caller_app_id", r.Header.Get(hdrPeerAppID)))
	return nil
}

// verifyAgainstPolicy verifies the caller certificate in two steps and returns
// the verified cert info:
//
//  1. Verify the TDX quote signature (Intel DCAP, via the attestation server)
//     and the channel binding (report_data folds this session's binder), with
//     NO measurement pinned. This proves the certificate carries a genuine,
//     session-bound quote from some TDX enclave.
//  2. Match the (now trusted) quote/OIDs against each allowed-caller entry whose
//     app-id matches the caller, using the SDK's MatchDependency — the exact
//     any-of measurement + required-OID check the egress/caller side runs, so a
//     caller is accepted on ingress under identical rules.
func (v *ingressVerifier) verifyAgainstPolicy(
	cert *x509.Certificate, binder []byte, policy *ratls.DependencySet,
	attURL, attToken string,
) (ratls.CertInfo, error) {
	// -- Step 1: quote signature + channel binding (measurement-agnostic) --
	base := &ratls.VerificationPolicy{
		TEE:        ratls.TeeTypeTDX,
		MRTD:       nil, // measurement pinned per-entry in step 2
		ReportData: ratls.ReportDataChallengeResponse,
		Nonce:      nil, // binder-only: report_data folds the session binder
		QuoteVerification: &ratls.QuoteVerificationConfig{
			Endpoint: attURL,
			Token:    attToken,
		},
		AllowDebugImages: v.allowDebugImages,
	}
	info, err := ratls.VerifyRaTlsCertBound(cert, base, binder)
	if err != nil {
		return ratls.CertInfo{}, fmt.Errorf("caller quote/binding verification failed: %w", err)
	}

	// -- Step 2: match against an allowed-caller entry (any-of) --
	callerAppID := oidFromInfoRaw(info, ratls.OidWorkloadAppID)
	var lastErr error
	matchedEntry := false
	for i := range policy.Entries {
		entry := policy.Entries[i]
		// Entry app-id selects which caller this entry describes; it is
		// re-verified as a RequiredOid inside MatchDependency.
		if entry.AppID != "" && !appIDMatches(entry.AppID, callerAppID) {
			continue
		}
		matchedEntry = true
		if err := ratls.MatchDependency(info, ratls.TeeTypeTDX, entry); err == nil {
			return info, nil
		} else {
			lastErr = err
		}
	}
	if !matchedEntry {
		return ratls.CertInfo{}, fmt.Errorf("no allowed-caller entry matches caller app-id %s",
			hex.EncodeToString(callerAppID))
	}
	return ratls.CertInfo{}, fmt.Errorf("caller did not satisfy any allowed-caller entry: %w", lastErr)
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

// appIDMatches reports whether the allowed-caller entry's app-id (which the
// dependency-set encoding stores as a lowercase-hex string of the raw app-id
// bytes, matching the OID 3.6 value) equals the caller's presented app-id.
func appIDMatches(entryAppID string, callerAppID []byte) bool {
	if len(callerAppID) == 0 {
		return false
	}
	return strings.EqualFold(entryAppID, hex.EncodeToString(callerAppID))
}

// RegisterIngressPolicy installs the per-host allowed-caller policy for an
// ingress mutual-RA-TLS app (AppHostRouter). Passing nil disables verification
// for the host.
func (s *Server) RegisterIngressPolicy(hostname string, policy *ratls.DependencySet) {
	s.ingress.setPolicy(hostname, policy)
}

// handleMintEgressIdentity mints the calling container's one-shot RA-TLS client
// identity for an app-to-app (ingress mutual RA-TLS) call, bound to the channel
// binder of the caller's live handshake to the sibling app. It reuses the same
// measured-manager minting as the vault path (quote + image digest OID 3.2 + app
// id OID 3.6), so the callee can trust the stamped app id. Unlike the vault
// path, the server challenge is optional: anti-relay comes from the mandatory
// channel binder alone (report_data folds it, so a relayed cert from another
// session fails closed at the callee). Authenticated by the per-container token
// from inside the enclave; a container can only mint its OWN identity.
func (s *Server) handleMintEgressIdentity(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !isInEnclaveCaller(host) {
		s.jsonError(w, http.StatusForbidden, "this endpoint is reachable only from inside the enclave")
		return
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		s.jsonError(w, http.StatusUnauthorized, "expected Bearer PRIVASYS_CONTAINER_TOKEN")
		return
	}
	name := s.launcher.LookupContainerByToken(strings.TrimPrefix(authHeader, "Bearer "))
	if name == "" {
		s.jsonError(w, http.StatusUnauthorized, "invalid container token")
		return
	}
	var body struct {
		// BinderB64 is the 32-byte RA-TLS channel binder of the caller's live
		// handshake (CertificateRequestInfo.RATLSChannelBinder). Mandatory.
		BinderB64 string `json:"binder_b64"`
		// ChallengeB64 is an optional server-emitted nonce
		// (CertificateRequestInfo.RATLSChallenge); folded before the binder when
		// present, for parity with a callee that also sends a challenge.
		ChallengeB64 string `json:"challenge_b64,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	channelBinder, err := base64.StdEncoding.DecodeString(body.BinderB64)
	if err != nil || len(channelBinder) == 0 {
		s.jsonError(w, http.StatusBadRequest, "binder_b64 must be non-empty base64 (channel binding is required)")
		return
	}
	var challenge []byte
	if body.ChallengeB64 != "" {
		challenge, err = base64.StdEncoding.DecodeString(body.ChallengeB64)
		if err != nil {
			s.jsonError(w, http.StatusBadRequest, "challenge_b64 must be valid base64")
			return
		}
	}
	certPEM, keyPEM, err := s.launcher.MintVaultIdentity(name, challenge, channelBinder)
	if err != nil {
		s.log.Warn("mint egress identity failed", zap.String("container", name), zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, "failed to mint egress identity")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cert_pem": string(certPEM),
		"key_pem":  string(keyPEM),
	})
}

// isDevImageProfile reports whether this VM runs a non-production ("dev") image,
// read from the dm-verity-measured /etc/privasys/image-profile marker. On dev
// platforms ingress verification permits dev-image callers; on production a dev
// caller is rejected. A missing marker (images predating it) is treated as
// production (fail closed toward stricter verification).
func isDevImageProfile() bool {
	b, err := os.ReadFile("/etc/privasys/image-profile")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "dev"
}
