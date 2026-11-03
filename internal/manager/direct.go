package manager

// Direct domains: adopter hostnames whose TLS ends in this enclave with a
// publicly trusted certificate (internal/directtls, launcher/direct.go). The
// owner names them in the signed app policy; the control plane reads this
// status before it lets a gateway splice a name here, and checks the
// adopter's CAA record against the account it reports.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"go.uber.org/zap"
)

// handleDirectStatus handles GET /api/v1/containers/{name}/direct.
func (s *Server) handleDirectStatus(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "container name is required")
		return
	}
	if !s.launcher.DirectSupported() {
		s.jsonError(w, http.StatusNotFound, "direct domains are not configured on this host")
		return
	}
	st, err := s.launcher.DirectStatus(name)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// AttestationLevelHeader tells the app how the user on a direct private
// request signed in: "verified" when it was the wallet (which checked this
// enclave's attestation), "unverified" otherwise (passkey, social). Only the
// runtime sets it; every inbound value is stripped.
const AttestationLevelHeader = "X-Privasys-Attestation-Level"

// directSubHeader is the subject header the sealed leg also carries
// (sessionrelay), so an app reads one identity contract on every leg.
const directSubHeader = "X-Privasys-Sub"

// The person's name and email, as the identity provider put them in the token
// the runtime just verified. Present only on a token from the code exchange,
// right after the sign-in: the identity provider keeps no profile, so a token
// minted by refresh says nothing and the app stores these on first sight. The
// email is only ever an address the token says was proved. The name is
// percent-encoded UTF-8; decode it before use.
const (
	emailHeader = "X-Privasys-Email"
	nameHeader  = "X-Privasys-Name"
)

// stripAssertedProfile removes any inbound profile: only the runtime sets it.
func stripAssertedProfile(h http.Header) {
	h.Del(emailHeader)
	h.Del(nameHeader)
}

// assertProfile sets the profile headers from a verified token. An email a
// header cannot carry as it stands is left out, and the app sees the absence.
func assertProfile(h http.Header, u auth.AppUser) {
	if u.Email != "" && headerSafeASCII(u.Email) {
		h.Set(emailHeader, u.Email)
	}
	if u.Name != "" {
		h.Set(nameHeader, percentEncodeName(u.Name))
	}
}

func headerSafeASCII(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] <= 0x20 || v[i] >= 0x7f {
			return false
		}
	}
	return true
}

// percentEncodeName encodes everything outside RFC 3986's unreserved set, a
// subset of RFC 8187's attr-char, so every URL decoder reads it the same way.
func percentEncodeName(name string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// bearerSubjectKey marks a request whose X-Privasys-Sub came from an inner
// bearer rather than from the session itself.
type bearerSubjectKey struct{}

// assertSealedIdentity adds what the inner bearer of a sealed request says
// about the person, beside the subject the relay asserted from the session.
//
// With a session subject, the bearer must name that same subject, so one
// person's name never sits beside another's subject; on a mismatch only the
// profile is withheld, the session's subject stands. Without one (a session
// from a fresh ceremony), the bearer must be minted for this app, as on a
// direct name, and it supplies the subject too. A bearer that does not verify
// adds nothing.
//
// The bearer stays in place: apps reading it today keep working until they
// have moved to the headers.
func (s *Server) assertSealedIdentity(r *http.Request) *http.Request {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") || s.verifier == nil {
		return r
	}
	token := strings.TrimPrefix(authz, "Bearer ")
	if sub := r.Header.Get(directSubHeader); sub != "" {
		u, err := s.verifier.AuthenticateSubject(token, sub)
		if err != nil {
			s.log.Debug("sealed bearer adds no profile", zap.String("host", hostOnly(r.Host)), zap.Error(err))
			return r
		}
		assertProfile(r.Header, u)
		return r
	}
	u, err := s.verifier.AuthenticateAppUser(token, s.appAudiences(hostOnly(r.Host)))
	if err != nil {
		s.log.Debug("sealed bearer adds no identity", zap.String("host", hostOnly(r.Host)), zap.Error(err))
		return r
	}
	r.Header.Set(directSubHeader, u.Sub)
	assertProfile(r.Header, u)
	// Never a payer: this token is one the app itself may hold, and an app
	// must not be able to bill a person with it (callerIdentity).
	return r.WithContext(context.WithValue(r.Context(), bearerSubjectKey{}, true))
}

// serveDirect prepares a private request on a direct adopter name, for an
// app that opted in (surfaces.direct "private"). An end user's privasys.id
// token in Authorization, minted for this app, is verified here and replaced
// by the subject, the sign-in assurance and any profile the token carries; the
// app never sees the token. No
// token is an anonymous request. ok is false when it was answered here.
func (s *Server) serveDirect(w http.ResponseWriter, r *http.Request) bool {
	r.Header.Del(directSubHeader)
	r.Header.Del(AttestationLevelHeader)
	stripAssertedProfile(r.Header)
	r.Header.Set(TransportHeader, TransportDirect)

	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return true
	}
	if s.verifier == nil {
		s.jsonError(w, http.StatusUnauthorized, "this runtime has no identity provider to check the token")
		return false
	}
	host := hostOnly(r.Host)
	u, err := s.verifier.AuthenticateAppUser(strings.TrimPrefix(authz, "Bearer "), s.appAudiences(host))
	if err != nil {
		s.log.Info("direct bearer refused", zap.String("host", host), zap.Error(err))
		s.jsonError(w, http.StatusUnauthorized, "the token is not valid for this app")
		return false
	}
	r.Header.Del("Authorization")
	r.Header.Set(directSubHeader, u.Sub)
	assertProfile(r.Header, u)
	level := "unverified"
	if u.Wallet {
		level = "verified"
	}
	r.Header.Set(AttestationLevelHeader, level)
	return true
}

// appAudiences are the audiences an end user's token may carry for the app
// behind host: "app:<app id hex>", the app's platform hostname, and each of
// its direct adopter names. Never the platform audience, so a token minted
// for one app is refused by every other.
func (s *Server) appAudiences(host string) []string {
	if s.launcher == nil {
		return []string{host}
	}
	name := s.launcher.AppHostnameToContainer(host)
	if name == "" {
		return nil
	}
	out := []string{host}
	if id := s.launcher.AppIDOf(name); id != "" {
		out = append(out, "app:"+id)
	}
	return append(out, s.launcher.DirectDomainsOf(name)...)
}

// handleSetProxyProtocol handles PUT /api/v1/edge/proxy-protocol
// {"from": ["ip or cidr", ...]}: the platform gateways whose PROXY protocol v2
// header this host honours on direct splices. An empty list turns it off.
// Connections without a header keep working from anywhere either way.
func (s *Server) handleSetProxyProtocol(w http.ResponseWriter, r *http.Request) {
	var body struct {
		From []string `json:"from"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, err := s.launcher.SetProxyProtocolFrom(body.From); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.launcher.ProxyProtocolStatus())
}
