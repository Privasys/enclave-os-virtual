package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"enclave-os-mini/clients/go/spend"

	"go.uber.org/zap"
)

// spendFixture is a fake IdP (JWKS + revoked feed), a fake mgmt
// billable-caller endpoint, and a caller app's signer.
type spendFixture struct {
	idp      *httptest.Server
	mgmt     *httptest.Server
	idpKey   *ecdsa.PrivateKey
	signer   *spend.Signer
	revoked  []string
	verdict  map[string]any
	mgmtHits int
	gate     *spendGate
}

func newSpendFixture(t *testing.T) *spendFixture {
	t.Helper()
	f := &spendFixture{verdict: map[string]any{"billable": true}}
	f.idpKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idpMux := http.NewServeMux()
	idpMux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []spend.JWK{spend.JWKOf(&f.idpKey.PublicKey)}})
	})
	idpMux.HandleFunc("GET /sessions/revoked", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"revoked": f.revoked, "now": time.Now().Unix()})
	})
	idpMux.HandleFunc("POST /spend/token", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Sub string `json:"sub"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var doc struct {
			Keys []spend.JWK `json:"keys"`
		}
		_ = json.Unmarshal(f.signer.JWKS(), &doc)
		now := time.Now()
		tok, _ := spend.SignJWT(f.idpKey, spend.JWKOf(&f.idpKey.PublicKey).Kid, spend.TokenTyp, map[string]any{
			"iss": f.idp.URL, "sub": req.Sub, "azp": f.signer.AppID(), "sid": "sid-" + req.Sub, "cap": 500,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": "t",
			"cnf": map[string]any{"jwk": doc.Keys[0]},
		})
		_ = json.NewEncoder(w).Encode(map[string]any{"spend_token": tok, "expires_in": 3600, "cap": 500, "sid": "sid-" + req.Sub})
	})
	f.idp = httptest.NewServer(idpMux)
	t.Cleanup(f.idp.Close)

	f.mgmt = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mgmtHits++
		if r.Header.Get("Authorization") != "Bearer enclave-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/enclave/billable-caller" || r.URL.Query().Get("cap") != "500" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(f.verdict)
	}))
	t.Cleanup(f.mgmt.Close)

	// The Signer insists on https; the gate's verifier does not, so point
	// the signer at an https alias of the same fake IdP.
	tlsIdp := httptest.NewTLSServer(idpMux)
	t.Cleanup(tlsIdp.Close)
	var err error
	f.signer, err = spend.NewSigner("0123456789abcdef0123456789abcdef", tlsIdp.URL, spend.WithHTTPClient(tlsIdp.Client()))
	if err != nil {
		t.Fatal(err)
	}
	// Tokens name the plain-HTTP issuer (what the gate is configured with).
	f.gate = newSpendGate(zap.NewNop(), f.idp.URL, f.mgmt.URL, "enclave-token")
	return f
}

func (f *spendFixture) request(t *testing.T, host, sub string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://"+host+"/v1/chat", nil)
	r.Host = host
	// Inject what a caller could try to spoof: all must be scrubbed.
	r.Header.Set(spend.HeaderPayer, "mallory")
	r.Header.Set(spend.HeaderPayerApp, "evil")
	if sub != "" {
		if err := f.signer.Decorate(context.Background(), r, sub); err != nil {
			t.Fatalf("decorate: %v", err)
		}
	}
	return r
}

func TestSpendGateAssertsPayer(t *testing.T) {
	f := newSpendFixture(t)
	r := f.request(t, "cai.apps.test", "alice")
	code, err := f.gate.enforce(r, "cai.apps.test", "callee")
	if code != 0 || err != nil {
		t.Fatalf("enforce: %d %v", code, err)
	}
	if r.Header.Get(spend.HeaderPayer) != "alice" || r.Header.Get(spend.HeaderPayerApp) != "0123456789abcdef0123456789abcdef" ||
		r.Header.Get(spend.HeaderPayerSID) != "sid-alice" {
		t.Fatalf("payer headers: %v", r.Header)
	}
	if r.Header.Get(spend.HeaderToken) != "" || r.Header.Get(spend.HeaderProof) != "" {
		t.Fatal("spend credential reached the app")
	}
	// Second call: verdict cached, mgmt asked once.
	r2 := f.request(t, "cai.apps.test", "alice")
	if code, _ := f.gate.enforce(r2, "cai.apps.test", ""); code != 0 {
		t.Fatal(code)
	}
	if f.mgmtHits != 1 {
		t.Fatalf("mgmt asked %d times", f.mgmtHits)
	}
}

func TestSpendGateStripsWithoutToken(t *testing.T) {
	f := newSpendFixture(t)
	r := f.request(t, "cai.apps.test", "")
	if code, err := f.gate.enforce(r, "cai.apps.test", ""); code != 0 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
	if r.Header.Get(spend.HeaderPayer) != "" || r.Header.Get(spend.HeaderPayerApp) != "" {
		t.Fatal("spoofed payer headers survived")
	}
	// A disabled gate (no issuer) still scrubs, and refuses a token it
	// cannot verify.
	off := newSpendGate(zap.NewNop(), "", "", "")
	r2 := f.request(t, "cai.apps.test", "alice")
	if code, _ := off.enforce(r2, "cai.apps.test", ""); code != http.StatusForbidden {
		t.Fatalf("disabled gate: %d", code)
	}
	if r2.Header.Get(spend.HeaderToken) != "" || r2.Header.Get(spend.HeaderPayer) != "" {
		t.Fatal("disabled gate leaked headers")
	}
}

func TestSpendGateRefusals(t *testing.T) {
	f := newSpendFixture(t)
	// Wrong host: the proof was minted for another callee.
	r := f.request(t, "cai.apps.test", "alice")
	if code, err := f.gate.enforce(r, "drive.apps.test", ""); code != http.StatusForbidden || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("audience: %d %v", code, err)
	}
	// Replay.
	r2 := f.request(t, "cai.apps.test", "alice")
	tok, proof := r2.Header.Get(spend.HeaderToken), r2.Header.Get(spend.HeaderProof)
	if code, _ := f.gate.enforce(r2, "cai.apps.test", ""); code != 0 {
		t.Fatal("first use refused")
	}
	r3 := httptest.NewRequest(http.MethodPost, "https://cai.apps.test/v1/chat", nil)
	r3.Host = "cai.apps.test"
	r3.Header.Set(spend.HeaderToken, tok)
	r3.Header.Set(spend.HeaderProof, proof)
	if code, err := f.gate.enforce(r3, "cai.apps.test", ""); code != http.StatusForbidden || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replay: %d %v", code, err)
	}
	// Payer may not spend: 402 with the reason's wording.
	f.verdict = map[string]any{"billable": false, "reason": "cap_reached"}
	r4 := f.request(t, "cai.apps.test", "bob")
	if code, err := f.gate.enforce(r4, "cai.apps.test", ""); code != http.StatusPaymentRequired || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("cap: %d %v", code, err)
	}
	if r4.Header.Get(spend.HeaderPayer) != "" {
		t.Fatal("refused payer asserted")
	}
	// Revocation lands through the feed.
	f.revoked = []string{"sid-alice"}
	f.gate.pollRevoked(context.Background())
	r5 := f.request(t, "cai.apps.test", "alice")
	if code, err := f.gate.enforce(r5, "cai.apps.test", ""); code != http.StatusForbidden || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked: %d %v", code, err)
	}
}

func TestSpendGateMgmtOutageFailsOpenWithCache(t *testing.T) {
	f := newSpendFixture(t)
	r := f.request(t, "cai.apps.test", "alice")
	if code, _ := f.gate.enforce(r, "cai.apps.test", ""); code != 0 {
		t.Fatal(code)
	}
	f.mgmt.Close()
	f.gate.verdicts = map[string]spendVerdict{} // force a re-ask
	r2 := f.request(t, "cai.apps.test", "alice")
	if code, _ := f.gate.enforce(r2, "cai.apps.test", ""); code != 0 || r2.Header.Get(spend.HeaderPayer) != "alice" {
		t.Fatalf("outage with nothing cached must serve: %d", code)
	}
}
