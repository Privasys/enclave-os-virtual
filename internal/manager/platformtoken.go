package manager

import (
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
)

// A caller's platform bearer is the runtime's to consume (the API-fee payer,
// the configure gate, guarded routes), never the app's: the developer portal
// sends the person's control-plane token with all their roles, and an app
// that received it could act on the platform as that person until it expires.
// So before any request reaches a container, on every leg (sealed, gateway,
// direct), a platform-audience bearer is withheld:
//
//   - always, when it carries a platform-tier role (staff tokens);
//   - otherwise, unless the app is a first-party app still verifying platform
//     tokens itself (platformTokenApps), until those apps verify their own
//     app audience instead.
//
// A token for any other audience (the app's own) passes unchanged. The token
// is read unverified: the result only ever removes a credential.

// platformAudiences are the audiences of the platform's own tokens.
var platformAudiences = map[string]bool{
	"privasys-platform":      true,
	"privasys-platform-test": true,
}

// platformTierRoles are the staff roles, matched exactly (never by substring)
// under each platform audience.
var platformTierRoles = func() map[string]bool {
	m := map[string]bool{}
	for aud := range platformAudiences {
		for _, r := range []string{"admin", "manager", "monitoring"} {
			m[aud+":"+r] = true
		}
	}
	return m
}()

// platformTokenApps are the first-party apps that still verify an ordinary
// platform user token themselves. Platform-controlled: compiled into the
// measured runtime, never set by an app or its owner. Empty once they verify
// app:<id>.
var platformTokenApps = func() map[string]bool {
	m := map[string]bool{}
	for _, id := range []string{
		"cf7a0d58-5468-4168-84c3-41ebe0ce4025", // privasys-drive (prod)
		"02104572-ca2f-41e8-ae2d-24c0294e6f5e", // drive-demo (dev)
		"2425f347-ebdc-4e80-b0b1-328757f34fc8", // globaml-coordinator (dev)
		"c907ba31-0fe6-4e29-8627-51f3a153dd7f", // globaml-bwbagb (dev)
		"dd4dcd8a-c94f-4d9d-8eef-68879a9c5969", // globaml-hcbggb (dev)
	} {
		m[normalizeAppID(id)] = true
	}
	return m
}()

func normalizeAppID(id string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(id), "-", ""))
}

// withholdToken reports whether tok must not reach the container of appID.
func withholdToken(tok, roleClaim, appID string) bool {
	p, ok := auth.Peek(tok, roleClaim)
	if !ok {
		return false
	}
	platform := false
	for _, a := range p.Audiences {
		if platformAudiences[a] {
			platform = true
			break
		}
	}
	if !platform {
		return false
	}
	for _, r := range p.Roles {
		if platformTierRoles[r] {
			return true
		}
	}
	return appID == "" || !platformTokenApps[normalizeAppID(appID)]
}

// stripPlatformTokens removes, from a request about to be proxied to the app
// appID, every bearer withholdToken refuses: Authorization, X-App-Auth and a
// bearer WebSocket subprotocol.
func stripPlatformTokens(h http.Header, roleClaim, appID string) {
	if tok := bearerToken(h.Get("Authorization")); tok != "" && withholdToken(tok, roleClaim, appID) {
		h.Del("Authorization")
	}
	if tok := strings.TrimSpace(h.Get("X-App-Auth")); tok != "" && withholdToken(tok, roleClaim, appID) {
		h.Del("X-App-Auth")
	}
	lines := h.Values(wsProtocolHeader)
	if len(lines) == 0 {
		return
	}
	var keep []string
	dropped := false
	for _, line := range lines {
		for _, p := range strings.Split(line, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if len(p) >= len(wsBearerPrefix) && strings.EqualFold(p[:len(wsBearerPrefix)], wsBearerPrefix) &&
				withholdToken(p[len(wsBearerPrefix):], roleClaim, appID) {
				dropped = true
				continue
			}
			keep = append(keep, p)
		}
	}
	if !dropped {
		return
	}
	h.Del(wsProtocolHeader)
	if len(keep) > 0 {
		h.Set(wsProtocolHeader, strings.Join(keep, ", "))
	}
}

// appIDForHost is the platform app id of the container serving host, or "".
func (s *Server) appIDForHost(host string) string {
	if s.launcher == nil {
		return ""
	}
	name := s.launcher.AppHostnameToContainer(host)
	if name == "" {
		return ""
	}
	return s.launcher.ContainerFreezeState(name).AppID
}

// rewriteAppRequest is the app proxy's Rewrite: every leg (sealed, gateway,
// direct) reaches a container through it.
func (s *Server) rewriteAppRequest(pr *httputil.ProxyRequest) {
	host := hostOnly(pr.In.Host)
	upstream, _ := s.lookupAppHost(host)
	pr.Out.URL.Scheme = "http"
	pr.Out.URL.Host = upstream
	pr.Out.Host = pr.In.Host
	pr.SetXForwarded()
	restoreDirectForwardedHost(pr)
	// A platform bearer is the runtime's, not the app's. The outbound copy
	// only: the runtime's own gates keep reading pr.In.
	appID := ""
	if s.appIDOf != nil {
		appID = s.appIDOf(host)
	} else {
		appID = s.appIDForHost(host)
	}
	stripPlatformTokens(pr.Out.Header, s.verifier.RoleClaim(), appID)
}
