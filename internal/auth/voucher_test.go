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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

// voucherFixture spins up a fake IdP (OIDC discovery + JWKS) signing with a
// P-256 key, and returns a verifier pointed at it plus a signer for vouchers.
type voucherFixture struct {
	verifier *Verifier
	key      *ecdsa.PrivateKey
	kid      string
	issuer   string
}

func newVoucherFixture(t *testing.T) *voucherFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	const kid = "test-key-1"
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
		"x": b64(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": b64(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}}}

	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"jwks_uri": issuer + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwks)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL

	v, err := NewVerifier(&OIDCConfig{Issuer: issuer, Audience: "enclave-os-virtual"}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return &voucherFixture{verifier: v, key: key, kid: kid, issuer: issuer}
}

// sign builds a compact JWS with the given typ over the given claims.
func (f *voucherFixture) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": typ, "kid": f.kid})
	body, _ := json.Marshal(claims)
	signingInput := b64(hdr) + "." + b64(body)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64(sig)
}

func (f *voucherFixture) validClaims() map[string]any {
	return map[string]any{
		"iss":      f.issuer,
		"exp":      float64(time.Now().Add(10 * time.Minute).Unix()),
		"jti":      "vch-123",
		"rp_id":    "acme.example",
		"provider": "privasys",
		"claims":   []string{"privasys:age_over_18", "privasys:nationality"},
		"credits":  float64(20000),
	}
}

func TestVerifyVoucher_Valid(t *testing.T) {
	f := newVoucherFixture(t)
	vc, err := f.verifier.VerifyVoucher(f.sign(t, voucherType, f.validClaims()))
	if err != nil {
		t.Fatalf("VerifyVoucher: %v", err)
	}
	if vc.JTI != "vch-123" || vc.RPID != "acme.example" || vc.Provider != "privasys" {
		t.Fatalf("wrong voucher fields: %+v", vc)
	}
	if len(vc.Claims) != 2 || vc.Claims[0] != "privasys:age_over_18" {
		t.Fatalf("wrong claims: %+v", vc.Claims)
	}
	if vc.Credits != 20000 {
		t.Fatalf("wrong credits: %d", vc.Credits)
	}
}

// An ordinary access token (typ omitted / not voucher+jwt) must never pass as a
// voucher, even though it is signed by the same key.
func TestVerifyVoucher_RejectsWrongType(t *testing.T) {
	f := newVoucherFixture(t)
	if _, err := f.verifier.VerifyVoucher(f.sign(t, "at+jwt", f.validClaims())); err == nil {
		t.Fatal("expected rejection of non-voucher typ")
	}
}

func TestVerifyVoucher_RejectsExpired(t *testing.T) {
	f := newVoucherFixture(t)
	c := f.validClaims()
	c["exp"] = float64(time.Now().Add(-time.Minute).Unix())
	if _, err := f.verifier.VerifyVoucher(f.sign(t, voucherType, c)); err == nil {
		t.Fatal("expected rejection of expired voucher")
	}
}

func TestVerifyVoucher_RejectsTamperedSignature(t *testing.T) {
	f := newVoucherFixture(t)
	tok := f.sign(t, voucherType, f.validClaims())
	if _, err := f.verifier.VerifyVoucher(tok[:len(tok)-2] + "xy"); err == nil {
		t.Fatal("expected rejection of tampered signature")
	}
}

func TestVerifyVoucher_RejectsWrongIssuer(t *testing.T) {
	f := newVoucherFixture(t)
	c := f.validClaims()
	c["iss"] = "https://evil.example"
	if _, err := f.verifier.VerifyVoucher(f.sign(t, voucherType, c)); err == nil {
		t.Fatal("expected rejection of wrong issuer")
	}
}
