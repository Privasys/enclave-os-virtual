package manager

// Direct domains: adopter hostnames whose TLS ends in this enclave with a
// publicly trusted certificate (internal/directtls, launcher/direct.go). The
// owner names them in the signed app policy; the control plane reads this
// status before it lets a gateway splice a name here, and checks the
// adopter's CAA record against the account it reports.

import (
	"encoding/json"
	"net/http"
	"strings"

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

// serveDirect prepares a private request on a direct adopter name, for an
// app that opted in (surfaces.direct "private"). An end user's privasys.id
// token in Authorization, minted for this app, is verified here and replaced
// by the subject and the sign-in assurance; the app never sees the token. No
// token is an anonymous request. ok is false when it was answered here.
func (s *Server) serveDirect(w http.ResponseWriter, r *http.Request) bool {
	r.Header.Del(directSubHeader)
	r.Header.Del(AttestationLevelHeader)
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
	sub, wallet, err := s.verifier.AuthenticateAppUser(strings.TrimPrefix(authz, "Bearer "), s.appAudiences(host))
	if err != nil {
		s.log.Info("direct bearer refused", zap.String("host", host), zap.Error(err))
		s.jsonError(w, http.StatusUnauthorized, "the token is not valid for this app")
		return false
	}
	r.Header.Del("Authorization")
	r.Header.Set(directSubHeader, sub)
	level := "unverified"
	if wallet {
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
