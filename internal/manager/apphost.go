package manager

import (
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// serveAppHost serves a request for a registered app host. The steps run in
// this order, and TestTheAppHostGatesRunInOrder pins it:
//
//  1. the enclave OS's own paths on the app's name (capabilities, holders);
//  2. the ingress mutual RA-TLS gate;
//  3. removing what only the runtime may assert;
//  4. the leg: direct name, clear leg, sealed or attested;
//  5. the tool-subject assertion;
//  6. per container: the spend gate, the billing freeze, the guarded route,
//     the configure gate and its freeze;
//  7. the fee gate, around the app proxy.
func (s *Server) serveAppHost(w http.ResponseWriter, r *http.Request, host string) {
	setRouteLabel(r, "app")
	if s.serveRuntimePaths(w, r, host) {
		return
	}
	// The callee-side enforcement point of mutual RA-TLS (peerverify.go): for
	// a host that declares an allowed-caller set, verify the attested caller
	// certificate Caddy handed over (quote signature, measurement, app-id and
	// code-hash OIDs, channel binding) and rewrite X-Privasys-Peer-* to the
	// verified identity. Other hosts have the peer namespace scrubbed.
	if err := s.ingress.enforce(r); err != nil {
		s.jsonError(w, http.StatusForbidden, "caller attestation failed: "+err.Error())
		return
	}
	stripRuntimeAssertions(r)
	w, r, ok := s.serveLeg(w, r, host)
	if !ok {
		return
	}
	// From here on the credential headers stay as they are, so every step
	// below reads one verification of each (caller.go).
	r = s.withCaller(r)
	s.assertToolSubject(r)

	containerName := s.launcher.AppHostnameToContainer(host)
	if containerName != "" {
		st := s.launcher.ContainerFreezeState(containerName)
		if !s.spendGate(w, r, host, st) || !s.billingFreeze(w, st) {
			return
		}
		if r, ok = s.routeGate(w, r, containerName, st); !ok {
			return
		}
		if r, ok = s.configureGate(w, r, containerName, st); !ok {
			return
		}
	}
	// Per-call API fee (x-privasys.price): consent gate and charge recording
	// around the app proxy, from the measured price table (apifee.go).
	// Unpriced requests pass through.
	s.serveAppBilled(w, r, containerName)
}

// serveRuntimePaths answers the paths the enclave OS serves on an app's name
// itself, and reports whether it did.
func (s *Server) serveRuntimePaths(w http.ResponseWriter, r *http.Request, host string) bool {
	// Wallet-facing capability endpoints, for any app that declares
	// resources, before the ingress gate: the wallet presents no client
	// certificate.
	if isCapabilityWellKnown(r.URL.Path) {
		if name := s.launcher.AppHostnameToContainer(host); name != "" && len(s.launcher.ContainerResourceDecls(name)) > 0 {
			s.serveCapabilityWellKnown(w, r, name)
			return true
		}
	}
	// The holder-facing pair the wallet speaks to every resource service,
	// for the kinds the enclave OS is the service of (app_storage) and for
	// the caller-side revoke of every kind; and the holder's window onto
	// their folder (holderpaths.go).
	return s.serveEnclaveHolderPaths(w, r, host)
}

// stripRuntimeAssertions removes the headers only the runtime may set, so a
// client's copy never reaches the app: the voucher headers (or a caller
// could forge an authorised-claims header past the app's paid gate), the
// sign-in assurance (direct.go) and the profile.
func stripRuntimeAssertions(r *http.Request) {
	r.Header.Del(voucherJTIHeader)
	r.Header.Del(voucherProviderHeader)
	r.Header.Del(voucherClaimsHeader)
	r.Header.Del(voucherRPIDHeader)
	r.Header.Del(AttestationLevelHeader)
	stripAssertedProfile(r.Header)
}

// serveLeg applies the rules of the leg the request came on (surfaces.go).
// The session relay marked a request it unsealed; anything else is RA-TLS
// direct (TLS ended here) or plaintext on the gateway-terminated leg, which
// the require-sealed predicate only let through for a declared surface and
// which is served anonymous by construction. It reports false when it has
// answered the request itself.
func (s *Server) serveLeg(w http.ResponseWriter, r *http.Request, host string) (http.ResponseWriter, *http.Request, bool) {
	switch {
	case r.Header.Get(TransportHeader) == TransportSealed:
		return w, s.assertSealedIdentity(r), true
	case r.Header.Get(TransportHeader) != "":
		return w, r, true
	case isDirectLeg(r) && !s.clearAllowed(r) && s.surfacesOf(host).DirectPrivate():
		r, ok := s.serveDirect(w, r)
		return w, r, ok
	case isClearLeg(r):
		pw, ok := s.servePublic(w, r)
		return pw, r, ok
	default:
		r.Header.Set(TransportHeader, TransportAttested)
		return w, r, true
	}
}

// assertToolSubject names the person a tool token for this app presents, as
// the app knows them; the token itself is withheld from the app
// (platformtoken.go). The session relay stripped any inbound X-Privasys-Sub
// on every path.
func (s *Server) assertToolSubject(r *http.Request) {
	if t := r.Header.Get(TransportHeader); t != TransportAttested && t != TransportSealed {
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Privasys-Sub")) != "" {
		return
	}
	if sub, via := s.toolCaller(r); sub != "" && headerSafeASCII(via) {
		r.Header.Set("X-Privasys-Sub", sub)
		r.Header.Set(SubViaHeader, via)
	}
}

// spendGate names the paying user behind the call (spendgate.go), or
// refuses a bad token (403) or a payer who may not spend (402). It runs
// after the ingress gate scrubbed the peer namespace, so the payer headers
// it asserts are the only ones the app can see.
func (s *Server) spendGate(w http.ResponseWriter, r *http.Request, host string, st launcher.FreezeState) bool {
	code, err := s.spend.enforce(r, host, st.AppID)
	if code == 0 {
		return true
	}
	if code == http.StatusPaymentRequired {
		w.Header().Set("X-Privasys-Payer-Refused", "true")
	}
	s.jsonError(w, code, err.Error())
	return false
}

// billingFreeze refuses every request of an app whose credits are exhausted:
// its task is paused. Attestation is served outside the app host, so the
// chain stays verifiable.
func (s *Server) billingFreeze(w http.ResponseWriter, st launcher.FreezeState) bool {
	if !st.BillingFrozen {
		return true
	}
	w.Header().Set("Retry-After", "30")
	s.jsonError(w, http.StatusServiceUnavailable, "app paused: "+st.BillingReason)
	return false
}

// routeGate checks a guarded route (tools[].x-privasys.auth in the measured
// manifest, Enclave OS Mini's @auth grammar), so the app verifies no
// platform token itself. The configure path is the configure gate's.
func (s *Server) routeGate(w http.ResponseWriter, r *http.Request, containerName string, st launcher.FreezeState) (*http.Request, bool) {
	ra, ok := matchRouteAuth(st.RouteAuth, r)
	if !ok || (st.ConfigAPI != nil && matchesConfigAPI(st.ConfigAPI, r)) {
		return r, true
	}
	sub, role, err := s.routeGrant(r, containerName, st, ra)
	if err != nil {
		s.jsonError(w, http.StatusForbidden, "route "+ra.Path+" requires "+routeAuthLabel(ra)+": "+err.Error())
		return r, false
	}
	// An owner route tells the app who passed, like configure.
	if role != "" {
		r = withConfigureGrant(r, sub, role)
	}
	return r, true
}

// configureGate guards the configure surface, owner or admin only on every
// call (a reconfigure of a running app is equally privileged), and holds
// every other request of an app that declared a configure step and has not
// been configured yet. It reports false when it has answered the request,
// which includes proxying the first configure call itself: the freeze lifts
// on its 2xx.
func (s *Server) configureGate(w http.ResponseWriter, r *http.Request, containerName string, st launcher.FreezeState) (*http.Request, bool) {
	if st.ConfigAPI == nil {
		return r, true
	}
	if !matchesConfigAPI(st.ConfigAPI, r) {
		if !st.ConfigAPI.Optional && !st.Configured {
			w.Header().Set("Retry-After", "5")
			s.jsonError(w, http.StatusServiceUnavailable, "container is awaiting initial configuration")
			return r, false
		}
		return r, true
	}
	sub, role, err := s.configureGrant(r, containerName, st)
	if err != nil {
		s.jsonError(w, http.StatusForbidden, "configure requires the app owner or admin: "+err.Error())
		return r, false
	}
	// The app learns who passed the gate from the runtime (platformtoken.go),
	// never from the platform token.
	r = withConfigureGrant(r, sub, role)
	if st.Configured {
		return r, true
	}
	rw := &statusRecorder{ResponseWriter: w}
	s.appProxy.ServeHTTP(rw, r)
	if rw.status >= 200 && rw.status < 300 {
		s.launcher.MarkConfigured(containerName)
		s.log.Info("container configured (freeze lifted)", zap.String("container", containerName))
	}
	return r, false
}
