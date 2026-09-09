package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"enclave-os-mini/clients/go/spend"

	"go.uber.org/zap"
)

// Spend tokens (acting-subject plan v2): the paying user behind a call.
//
// A caller app attaches X-Privasys-Spend (a token the identity provider
// issued to it for one signed-in user, bound to the app's own key) and
// X-Privasys-Spend-Proof (a signature with that key over this host and this
// minute). This gate, on the callee's ingress path, verifies both against
// the IdP JWKS it already trusts, refuses replays and revoked consents, asks
// the management-service (cached) whether that user may spend through that
// app right now, and asserts the result to the app as X-Privasys-Peer-Payer
// and X-Privasys-Peer-Payer-App. The spend headers never reach the app; the
// payer headers are stripped from every request this gate did not verify.
//
// Nothing here consults the host's allowed-caller set or a platform list:
// who pays is independent of who may connect. A request without spend
// headers passes untouched and the app falls back to its own auth.

const (
	// spendVerdictOK / spendVerdictNo bound how long a billable verdict is
	// reused. A yes is re-checked often enough that a reached cap stops
	// spending within minutes; a no clears as soon as the user tops up or
	// raises the cap.
	spendVerdictOK = 5 * time.Minute
	spendVerdictNo = time.Minute
	// spendRevokedPoll is how often the revoked-session feed is polled.
	spendRevokedPoll = 30 * time.Second
)

// spendVerdict is one cached billable answer.
type spendVerdict struct {
	billable bool
	reason   string
	until    time.Time
}

// spendGate is the ingress verifier plus its caches.
type spendGate struct {
	log      *zap.Logger
	verifier *spend.Verifier
	issuer   string

	mgmtURL string
	token   string
	http    *http.Client

	mu       sync.Mutex
	verdicts map[string]spendVerdict

	revMu   sync.RWMutex
	revoked map[string]struct{}
	revNow  int64

	now func() time.Time
}

// newSpendGate builds the gate. An empty issuer disables verification (the
// gate then only strips): a fleet without an IdP cannot name a payer.
func newSpendGate(log *zap.Logger, issuer, mgmtURL, enclaveToken string) *spendGate {
	g := &spendGate{
		log:      log.Named("spend"),
		issuer:   strings.TrimRight(issuer, "/"),
		mgmtURL:  strings.TrimRight(mgmtURL, "/"),
		token:    enclaveToken,
		http:     &http.Client{Timeout: 10 * time.Second},
		verdicts: map[string]spendVerdict{},
		revoked:  map[string]struct{}{},
		now:      time.Now,
	}
	if g.issuer != "" {
		g.verifier = spend.NewVerifier(g.issuer, g.http)
		g.verifier.Revoked = g.isRevoked
	}
	return g
}

// enabled reports whether tokens can be verified on this runtime.
func (g *spendGate) enabled() bool { return g != nil && g.verifier != nil }

// enforce runs on every app-host request. It always strips the payer
// namespace the app trusts. With spend headers present and verified it
// asserts the payer and returns (0, nil); a bad token or proof returns
// (403, err); a payer who may not spend returns (402, err). Without spend
// headers it returns (0, nil) and the request continues unchanged.
func (g *spendGate) enforce(r *http.Request, host, calleeAppID string) (int, error) {
	spend.StripPayerHeaders(r)
	tok := r.Header.Get(spend.HeaderToken)
	proof := r.Header.Get(spend.HeaderProof)
	// The app never sees the credential, whatever happens next.
	r.Header.Del(spend.HeaderToken)
	r.Header.Del(spend.HeaderProof)
	if tok == "" && proof == "" {
		return 0, nil
	}
	if !g.enabled() {
		return http.StatusForbidden, fmt.Errorf("spend tokens are not accepted on this runtime (no identity provider configured)")
	}
	// Re-attach for the verifier's header reads, then strip again.
	r.Header.Set(spend.HeaderToken, tok)
	r.Header.Set(spend.HeaderProof, proof)
	payer, err := g.verifier.Verify(r, host)
	r.Header.Del(spend.HeaderToken)
	r.Header.Del(spend.HeaderProof)
	if err != nil {
		g.log.Info("spend token refused", zap.String("host", host), zap.Error(err))
		return http.StatusForbidden, fmt.Errorf("spend token refused: %w", err)
	}
	if payer == nil {
		return 0, nil
	}
	if ok, reason := g.billable(r.Context(), payer); !ok {
		g.log.Info("payer may not spend", zap.String("host", host),
			zap.String("app", payer.AppID), zap.String("reason", reason))
		return http.StatusPaymentRequired, fmt.Errorf("%s", spendRefusal(reason))
	}
	r.Header.Set(spend.HeaderPayer, payer.Sub)
	r.Header.Set(spend.HeaderPayerApp, payer.AppID)
	if payer.SID != "" {
		r.Header.Set(spend.HeaderPayerSID, payer.SID)
	}
	_ = calleeAppID // the callee's own id is not part of the decision; logged by callers
	return 0, nil
}

// spendRefusal words the 402 for a caller app to relay to its user.
func spendRefusal(reason string) string {
	switch reason {
	case "no_account":
		return "payment required: the user has no Privasys platform account to debit — open one at https://privasys.id/account"
	case "cap_reached":
		return "payment required: the user's monthly spending cap for this app is reached — raise it at https://privasys.id/account"
	case "no_balance":
		return "payment required: the user's credit balance is exhausted — top up at https://privasys.id/account"
	default:
		return "payment required: the user may not spend through this app right now"
	}
}

// billable answers "may payer.Sub spend through payer.AppID now", from the
// management-service's billable-caller endpoint, cached per (user, app).
// With no management-service configured (dev) every verified payer is
// servable; on an outage the last verdict, even expired, is reused, and
// with nothing cached the call is served (the meter drops an unbillable
// line server-side, as it does for the inference enclave).
func (g *spendGate) billable(ctx context.Context, p *spend.Payer) (bool, string) {
	if g.mgmtURL == "" || g.token == "" {
		return true, ""
	}
	key := p.Sub + "|" + p.AppID
	now := g.now()
	g.mu.Lock()
	v, cached := g.verdicts[key]
	g.mu.Unlock()
	if cached && now.Before(v.until) {
		return v.billable, v.reason
	}
	ok, reason, err := g.askBillable(ctx, p)
	if err != nil {
		g.log.Warn("billable check failed", zap.String("app", p.AppID), zap.Error(err))
		if cached {
			return v.billable, v.reason
		}
		return true, ""
	}
	ttl := spendVerdictOK
	if !ok {
		ttl = spendVerdictNo
	}
	g.mu.Lock()
	g.verdicts[key] = spendVerdict{billable: ok, reason: reason, until: now.Add(ttl)}
	g.mu.Unlock()
	return ok, reason
}

func (g *spendGate) askBillable(ctx context.Context, p *spend.Payer) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	q := url.Values{}
	q.Set("sub", p.Sub)
	q.Set("app", p.AppID)
	if p.Cap > 0 {
		q.Set("cap", strconv.FormatInt(p.Cap, 10))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		g.mgmtURL+"/api/v1/enclave/billable-caller?"+q.Encode(), nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	resp, err := g.http.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("billable-caller status %d", resp.StatusCode)
	}
	var out struct {
		Billable bool   `json:"billable"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(&out); err != nil {
		return false, "", err
	}
	return out.Billable, out.Reason, nil
}

// --- revoked-session feed -----------------------------------------------------

func (g *spendGate) isRevoked(sid string) bool {
	g.revMu.RLock()
	defer g.revMu.RUnlock()
	_, ok := g.revoked[sid]
	return ok
}

// runRevokedPoller polls the identity provider's revoked-sid feed until ctx
// ends. A consent the user withdrew in the wallet is refused here within
// one interval, whatever the token's remaining lifetime.
func (g *spendGate) runRevokedPoller(ctx context.Context) {
	if !g.enabled() {
		return
	}
	g.pollRevoked(ctx)
	t := time.NewTicker(spendRevokedPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.pollRevoked(ctx)
		}
	}
}

func (g *spendGate) pollRevoked(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	g.revMu.RLock()
	since := g.revNow
	g.revMu.RUnlock()
	u := g.issuer + "/sessions/revoked"
	if since > 0 {
		// Overlap the window by a minute so a revoke that landed while the
		// previous poll was in flight is never missed.
		u += "?since=" + strconv.FormatInt(since-60, 10)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	resp, err := g.http.Do(req)
	if err != nil {
		g.log.Debug("revoked feed unreachable", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var out struct {
		Revoked []string `json:"revoked"`
		Now     int64    `json:"now"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return
	}
	g.revMu.Lock()
	for _, sid := range out.Revoked {
		g.revoked[sid] = struct{}{}
	}
	if out.Now > 0 {
		g.revNow = out.Now
	}
	g.revMu.Unlock()
}
