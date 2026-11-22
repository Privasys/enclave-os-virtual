// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// signJWT builds a compact JWS with a raw-64-byte ES256 signature (JOSE
// form), the same shape the wallet produces from its hardware key.
func signJWT(t *testing.T, k *ecdsa.PrivateKey, typ string, claims map[string]interface{}) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": typ, "kid": "test-key"})
	body, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwkOf(k *ecdsa.PrivateKey) map[string]interface{} {
	x := make([]byte, 32)
	y := make([]byte, 32)
	k.PublicKey.X.FillBytes(x)
	k.PublicKey.Y.FillBytes(y)
	return map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}

// newWalletTestVerifier serves a JWKS containing the provider key and
// returns a verifier pointed at it.
func newWalletTestVerifier(t *testing.T, provider *ecdsa.PrivateKey) *WalletCallVerifier {
	t.Helper()
	j := jwkOf(provider)
	j["kid"] = "test-key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{j}})
	}))
	t.Cleanup(srv.Close)
	return NewWalletCallVerifier(srv.URL, zap.NewNop())
}

// walletRequest builds a request carrying a WIA for holder and a proof
// bound to method+path, both mintable with deliberate faults for the
// negative cases.
func walletRequest(t *testing.T, provider, holder *ecdsa.PrivateKey, method, path string,
	proofMethod, proofPath string, iat time.Time, wiaExp time.Time) *http.Request {
	t.Helper()
	wia := signJWT(t, provider, "wia+jwt", map[string]interface{}{
		"cnf": map[string]interface{}{"jwk": jwkOf(holder)},
		"exp": wiaExp.Unix(),
	})
	proof := signJWT(t, holder, "wallet-pop+jwt", map[string]interface{}{
		"htm": proofMethod, "htu": proofPath, "iat": iat.Unix(),
	})
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set(WalletAttestationHeader, wia)
	r.Header.Set(WalletProofHeader, proof)
	return r
}

func TestWalletCallAccepted(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)

	r := walletRequest(t, provider, holder, "POST", "/verify-identity",
		"POST", "/verify-identity", time.Now(), time.Now().Add(time.Hour))
	inst, ok := v.IsWalletCall(r)
	if !ok {
		t.Fatal("a well-formed wallet call must be accepted")
	}
	if inst == "" {
		t.Fatal("expected an instance thumbprint")
	}
}

func TestWalletCallNoHeadersIsNotWallet(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)
	if _, ok := v.IsWalletCall(httptest.NewRequest("POST", "/x", nil)); ok {
		t.Fatal("a bare request must not be wallet-class")
	}
}

func TestWalletCallNilVerifierNeverExempts(t *testing.T) {
	var v *WalletCallVerifier
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := walletRequest(t, provider, holder, "POST", "/x", "POST", "/x",
		time.Now(), time.Now().Add(time.Hour))
	if _, ok := v.IsWalletCall(r); ok {
		t.Fatal("an unconfigured verifier must never exempt")
	}
}

// The proof is bound to the request: a proof captured from one call must
// not free a different one. This is what stops an app (or anything that
// saw the headers) replaying them elsewhere.
func TestWalletCallProofIsRequestBound(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)

	wrongPath := walletRequest(t, provider, holder, "POST", "/expensive-tool",
		"POST", "/verify-identity", time.Now(), time.Now().Add(time.Hour))
	if _, ok := v.IsWalletCall(wrongPath); ok {
		t.Fatal("a proof bound to another path must be refused")
	}
	wrongMethod := walletRequest(t, provider, holder, "POST", "/verify-identity",
		"GET", "/verify-identity", time.Now(), time.Now().Add(time.Hour))
	if _, ok := v.IsWalletCall(wrongMethod); ok {
		t.Fatal("a proof bound to another method must be refused")
	}
}

func TestWalletCallRejectsStaleProof(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)

	r := walletRequest(t, provider, holder, "POST", "/x", "POST", "/x",
		time.Now().Add(-10*time.Minute), time.Now().Add(time.Hour))
	if _, ok := v.IsWalletCall(r); ok {
		t.Fatal("a stale proof must be refused")
	}
}

func TestWalletCallRejectsExpiredWIA(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)

	r := walletRequest(t, provider, holder, "POST", "/x", "POST", "/x",
		time.Now(), time.Now().Add(-time.Minute))
	if _, ok := v.IsWalletCall(r); ok {
		t.Fatal("an expired WIA must be refused")
	}
}

// A WIA is not a bearer credential: holding one without the holder key
// gets you nothing.
func TestWalletCallRejectsProofFromAnotherKey(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	thief, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)

	wia := signJWT(t, provider, "wia+jwt", map[string]interface{}{
		"cnf": map[string]interface{}{"jwk": jwkOf(holder)},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	proof := signJWT(t, thief, "wallet-pop+jwt", map[string]interface{}{
		"htm": "POST", "htu": "/x", "iat": time.Now().Unix(),
	})
	r := httptest.NewRequest("POST", "/x", nil)
	r.Header.Set(WalletAttestationHeader, wia)
	r.Header.Set(WalletProofHeader, proof)
	if _, ok := v.IsWalletCall(r); ok {
		t.Fatal("a captured WIA without the holder key must be useless")
	}
}

func TestWalletCallRejectsForeignProvider(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogue, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)

	// WIA self-minted by an attacker's key, not the wallet provider's.
	r := walletRequest(t, rogue, holder, "POST", "/x", "POST", "/x",
		time.Now(), time.Now().Add(time.Hour))
	if _, ok := v.IsWalletCall(r); ok {
		t.Fatal("a WIA signed by a foreign key must be refused")
	}
}

// Another token type signed by the same provider key must not stand in
// for a WIA.
func TestWalletCallRejectsWrongTyp(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)

	notAWIA := signJWT(t, provider, "voucher+jwt", map[string]interface{}{
		"cnf": map[string]interface{}{"jwk": jwkOf(holder)},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	proof := signJWT(t, holder, "wallet-pop+jwt", map[string]interface{}{
		"htm": "POST", "htu": "/x", "iat": time.Now().Unix(),
	})
	r := httptest.NewRequest("POST", "/x", nil)
	r.Header.Set(WalletAttestationHeader, notAWIA)
	r.Header.Set(WalletProofHeader, proof)
	if _, ok := v.IsWalletCall(r); ok {
		t.Fatal("a non-WIA token must be refused")
	}
}

func TestWalletCallRejectsWrongProofTyp(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := newWalletTestVerifier(t, provider)

	wia := signJWT(t, provider, "wia+jwt", map[string]interface{}{
		"cnf": map[string]interface{}{"jwk": jwkOf(holder)},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	proof := signJWT(t, holder, "at+jwt", map[string]interface{}{
		"htm": "POST", "htu": "/x", "iat": time.Now().Unix(),
	})
	r := httptest.NewRequest("POST", "/x", nil)
	r.Header.Set(WalletAttestationHeader, wia)
	r.Header.Set(WalletProofHeader, proof)
	if _, ok := v.IsWalletCall(r); ok {
		t.Fatal("a proof with the wrong typ must be refused")
	}
}

func TestWalletCallJWKSUnreachableIsNotWallet(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := NewWalletCallVerifier("http://127.0.0.1:1/nope", zap.NewNop())

	r := walletRequest(t, provider, holder, "POST", "/x", "POST", "/x",
		time.Now(), time.Now().Add(time.Hour))
	if _, ok := v.IsWalletCall(r); ok {
		t.Fatal("no anchor means no exemption")
	}

}

// Unknown kids, or a JWKS that fails to load, trigger at most one fetch per
// oidcJWKSMinRefresh; a known kid is answered from the cache.
func TestWalletCallJWKSRefreshIsRateLimited(t *testing.T) {
	provider, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	j := jwkOf(provider)
	j["kid"] = "test-key"
	var fetches, failing atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if failing.Load() != 0 {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{j, map[string]interface{}{"kid": "other", "kty": "EC", "crv": "P-256", "x": j["x"], "y": j["y"]}}})
	}))
	t.Cleanup(srv.Close)
	v := NewWalletCallVerifier(srv.URL, zap.NewNop())

	if _, err := v.keyFor("test-key"); err != nil {
		t.Fatalf("known kid: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := v.keyFor(fmt.Sprintf("random-%d", i)); err == nil {
			t.Fatal("an unknown kid must not resolve")
		}
	}
	if _, err := v.keyFor("test-key"); err != nil {
		t.Fatalf("known kid after misses: %v", err)
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}

	failing.Store(1)
	v2 := NewWalletCallVerifier(srv.URL, zap.NewNop())
	for i := 0; i < 5; i++ {
		if _, err := v2.keyFor("test-key"); err == nil {
			t.Fatal("a failed fetch must not yield a key")
		}
	}
	if n := fetches.Load(); n != 2 {
		t.Fatalf("a failed fetch must be remembered: fetches = %d, want 2", n)
	}
}
