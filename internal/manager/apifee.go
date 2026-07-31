// Package manager — per-call API-fee enforcement (x-privasys.price).
//
// The dispatcher routes every priced app request through serveAppBilled,
// which mirrors the wasm runtime's attested billing gate: the price comes
// from the MEASURED image manifest label (launcher.ContainerPrices), the
// caller must consent with a byte-exact X-Billing-Approved header, the
// refusal happens inside the attested runtime before the app sees the
// request, and a successful call stamps X-Billing-Charged and records a
// fee event for the management-service pull path. Because the TLS session
// terminates in this enclave (RA-TLS / sealed relay), no intermediary can
// inject an approval, alter a price, or strip a charge.
package manager

import (
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/apifees"
	"github.com/Privasys/enclave-os-virtual/internal/auth"
)

const (
	billingApprovedHeader = "X-Billing-Approved"
	billingPriceHeader    = "X-Billing-Price"
	billingChargedHeader  = "X-Billing-Charged"
)

// priceForRequest resolves the enforceable price for an app request, if
// any. OPTIONS (CORS preflight cannot carry consent headers), well-known
// metadata, and the session-bootstrap endpoint are never priced.
func (s *Server) priceForRequest(containerName string, r *http.Request) (apifees.PricedTool, bool) {
	if s.apiFees == nil || containerName == "" {
		return apifees.PricedTool{}, false
	}
	if r.Method == http.MethodOptions {
		return apifees.PricedTool{}, false
	}
	if strings.HasPrefix(r.URL.Path, "/.well-known/") || strings.HasPrefix(r.URL.Path, "/__privasys/") {
		return apifees.PricedTool{}, false
	}
	tbl := s.launcher.ContainerPrices(containerName)
	if tbl == nil {
		return apifees.PricedTool{}, false
	}
	pt, ok := tbl[r.URL.Path]
	return pt, ok
}

// callerIdentity resolves who is calling, for charge attribution. A
// verified platform bearer wins: its sub is the platform-pairwise one the
// ledger can map to an account. Fallback is the relay-asserted
// X-Privasys-Sub, set exclusively by the session-relay middleware after an
// EncAuth bootstrap.
//
// Deliberately NOT a source of the wallet exemption. A session that a
// wallet once approved is an ordinary paying caller; only a call the
// wallet app itself makes is exempt, and that is proved per request (see
// walletCall).
func (s *Server) callerIdentity(r *http.Request) string {
	tok := ""
	if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Bearer ") {
		tok = strings.TrimPrefix(authz, "Bearer ")
	} else if x := r.Header.Get("X-App-Auth"); x != "" {
		tok = x
	}
	if tok != "" && s.verifier != nil {
		if sub, _, err := s.verifier.AuthenticateCaller(tok); err == nil && sub != "" {
			return sub
		}
	}
	return r.Header.Get("X-Privasys-Sub")
}

// serveAppBilled applies the API-fee gate around the ordinary app proxy
// path. Unpriced requests pass straight through.
func (s *Server) serveAppBilled(w http.ResponseWriter, r *http.Request, containerName string) {
	pt, priced := s.priceForRequest(containerName, r)
	if !priced {
		stripWalletProof(r)
		s.serveAppWithVoucher(w, r)
		return
	}
	rule := pt.Rule

	// Wallet-originated calls: the wallet app proves per request that it is
	// an attested instance (WIA + holder-key proof bound to this method and
	// path). Exempt callers are neither asked for consent nor charged, and
	// need no account — nobody is billed, and the wallet's app calls are
	// deliberately token-less so the callee never learns the user's
	// account. The proof headers are stripped so the app cannot replay them.
	if rule.FreeForWallet() {
		if instance, ok := s.walletCall.IsWalletCall(r); ok {
			s.log.Info("wallet-originated call exempted",
				zap.String("container", containerName),
				zap.String("tool", pt.Tool),
				zap.String("instance", instance))
			stripWalletProof(r)
			r.Header.Del(billingApprovedHeader)
			s.serveAppWithVoucher(w, r)
			return
		}
	}
	stripWalletProof(r)
	sub := s.callerIdentity(r)

	expected := fmt.Sprintf("%d credits", rule.Credits)

	// A caller-priced call must be attributable to an account, even on an
	// otherwise-public endpoint (the wasm runtime forces auth the same way).
	if sub == "" {
		w.Header().Set(billingPriceHeader, expected)
		s.jsonError(w, http.StatusPaymentRequired, fmt.Sprintf(
			"payment required: this call charges %s and must be attributable to a caller — authenticate with a platform bearer token or a wallet sealed session", expected))
		return
	}

	// Byte-exact consent, after trimming: proof the caller knew THIS price.
	// A mismatch usually means a stale client schema, so the refusal
	// carries the current attested price (both header and message — the
	// message wording is what clients regex for the 402 price).
	approved := strings.TrimSpace(r.Header.Get(billingApprovedHeader))
	if msg := consentRefusal(expected, approved); msg != "" {
		w.Header().Set(billingPriceHeader, expected)
		s.jsonError(w, http.StatusPaymentRequired, msg)
		return
	}

	// The app never sees the consent header; billing is the runtime's job.
	r.Header.Del(billingApprovedHeader)

	bw := &billedResponseWriter{ResponseWriter: w, charged: expected}
	s.serveAppWithVoucher(bw, r)

	// Charge only on delivery: a failed call costs nothing. status 0 means
	// the handler wrote a body with no explicit status — an implicit 200.
	if bw.status == 0 || (bw.status >= 200 && bw.status < 300) {
		ev := s.apiFees.Record(containerName, pt.Tool, sub, rule.Credits)
		s.log.Info("api fee recorded",
			zap.String("container", containerName),
			zap.String("tool", pt.Tool),
			zap.String("call_id", ev.CallID),
			zap.Uint64("credits", rule.Credits),
			zap.Uint64("seq", ev.Seq))
	}
}

// stripWalletProof removes the wallet-call proof headers before the app
// sees the request. They are a billing credential for the runtime, not
// something an app should receive or be able to relay onwards.
func stripWalletProof(r *http.Request) {
	r.Header.Del(auth.WalletAttestationHeader)
	r.Header.Del(auth.WalletProofHeader)
}

// consentRefusal returns the 402 refusal message for a missing or
// mismatched consent value, or "" when consent matches. The wording
// mirrors the wasm runtime's refusals verbatim: clients anchor on
// "charges N credits" to read the current attested price back, and the
// caller's own wrong figure is echoed first so it is never mistaken for
// the price.
func consentRefusal(expected, approved string) string {
	switch approved {
	case expected:
		return ""
	case "":
		return fmt.Sprintf(
			"payment approval required: this call charges %s — retry with X-Billing-Approved: %s", expected, expected)
	default:
		return fmt.Sprintf(
			"payment approval mismatch: approved '%s' but this call charges %s — retry with X-Billing-Approved: %s", approved, expected, expected)
	}
}

// billedResponseWriter stamps X-Billing-Charged on a 2xx response (and
// records the status for the fee decision). Upstream-set billing headers
// are scrubbed for every app response by the proxy's ModifyResponse; this
// writer re-asserts the runtime's own value after that scrub. Unwrap keeps
// http.ResponseController pass-through (Flush for SSE bodies) intact.
type billedResponseWriter struct {
	http.ResponseWriter
	charged string
	status  int
	wrote   bool
}

func (b *billedResponseWriter) WriteHeader(code int) {
	if !b.wrote {
		b.wrote = true
		b.status = code
		if code >= 200 && code < 300 {
			b.Header().Set(billingChargedHeader, b.charged)
		}
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *billedResponseWriter) Write(p []byte) (int, error) {
	if !b.wrote {
		b.WriteHeader(http.StatusOK)
	}
	return b.ResponseWriter.Write(p)
}

func (b *billedResponseWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }

// handleAPIFees serves GET /api/v1/api-fees: the fee-event ring for the
// management-service pull path (monitoring role suffices — the events
// carry no secrets, and the puller advances its own seq cursor). Reading
// persists the ring, mirroring the wasm runtime's save-on-read.
func (s *Server) handleAPIFees(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		s.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}
	events := s.apiFees.Snapshot()
	if events == nil {
		events = []apifees.Event{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"api_fees": events})
}
