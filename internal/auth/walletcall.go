// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Wallet-originated call proof.
//
// A call is "wallet class" (the free_for:["wallet"] API-fee exemption) when
// the WALLET APP ITSELF made it — not merely when the caller's session was
// once approved by a wallet. That distinction is the whole point: a browser
// that signed in by wallet push is an ordinary paying caller, so the
// exemption cannot be a property of the session (an OIDC claim), it has to
// be a property of THIS request.
//
// The wallet proves it per call with two headers:
//
//	X-Privasys-Wallet-Attestation: <wia+jwt>
//	X-Privasys-Wallet-Proof:       <wallet-pop+jwt>
//
// The WIA is the Wallet Instance Attestation issued at enrolment against a
// hardware-attested holder key (Android Keystore / iOS App Attest); it is
// subject-less by design, so it identifies an attested wallet INSTANCE and
// never an account. The proof is a short JWT signed by that same holder key
// and bound to this request (method, path, freshness), so a captured WIA is
// useless on its own.
//
// No account attribution is needed or wanted: an exempt call charges
// nobody, and the wallet's app calls are deliberately token-less to keep
// the callee from learning the user's account.
//
// Trust anchor: the wallet-provider JWKS. A wrong or hostile anchor can
// only make calls FREE, never overcharge, which is the safe direction and
// matches the rest of the pricing design (a price itself is measured).

const (
	// WalletAttestationHeader carries the wallet instance attestation.
	WalletAttestationHeader = "X-Privasys-Wallet-Attestation"
	// WalletProofHeader carries the request-bound holder-key proof.
	WalletProofHeader = "X-Privasys-Wallet-Proof"

	wiaTyp   = "wia+jwt"
	proofTyp = "wallet-pop+jwt"

	// proofFreshness bounds proof age. A replay inside the window can only
	// repeat a call that costs nothing (the exemption charges no one), so
	// this is a containment bound, not the security boundary.
	proofFreshness = 2 * time.Minute

	// jwksTTL is how long a fetched wallet-provider JWKS is reused.
	jwksTTL = time.Hour
)

// WalletCallVerifier verifies wallet-originated call proofs against the
// wallet-provider JWKS. The zero value is unusable; build one with
// NewWalletCallVerifier. A nil verifier verifies nothing (no exemption),
// which is the fail-closed default for a discount.
type WalletCallVerifier struct {
	jwksURI string
	log     *zap.Logger

	mu        sync.Mutex
	keys      map[string]*jwkKey
	fetchedAt time.Time
}

// NewWalletCallVerifier returns a verifier reading the wallet-provider
// JWKS from jwksURI. An empty URI disables the exemption entirely (nil).
func NewWalletCallVerifier(jwksURI string, log *zap.Logger) *WalletCallVerifier {
	if jwksURI == "" {
		return nil
	}
	return &WalletCallVerifier{jwksURI: jwksURI, log: log.Named("wallet-call")}
}

// IsWalletCall reports whether this request carries a valid wallet
// instance attestation plus a matching request-bound holder-key proof. It
// returns the instance thumbprint (non-identifying, for audit logs) when
// it does. Absent headers are not an error: the call is simply not
// wallet-class.
func (v *WalletCallVerifier) IsWalletCall(r *http.Request) (instance string, ok bool) {
	if v == nil {
		return "", false
	}
	wia := strings.TrimSpace(r.Header.Get(WalletAttestationHeader))
	proof := strings.TrimSpace(r.Header.Get(WalletProofHeader))
	if wia == "" || proof == "" {
		return "", false
	}
	holder, thumb, err := v.verifyWIA(wia)
	if err != nil {
		v.log.Debug("wallet attestation rejected", zap.Error(err))
		return "", false
	}
	if err := verifyCallProof(proof, holder, r.Method, r.URL.Path); err != nil {
		v.log.Debug("wallet call proof rejected", zap.Error(err))
		return "", false
	}
	return thumb, true
}

// verifyWIA checks the token is a wia+jwt signed by the wallet-provider
// key and returns the holder key it binds plus a stable, non-identifying
// instance thumbprint.
func (v *WalletCallVerifier) verifyWIA(token string) (*ecdsa.PublicKey, string, error) {
	claims, err := v.verifySigned(token, wiaTyp)
	if err != nil {
		return nil, "", err
	}
	if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
		return nil, "", errors.New("wallet attestation expired")
	}
	cnf, _ := claims["cnf"].(map[string]interface{})
	jwk, _ := cnf["jwk"].(map[string]interface{})
	if jwk == nil {
		return nil, "", errors.New("wallet attestation carries no cnf.jwk")
	}
	pub, raw, err := ecdsaFromJWK(jwk)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return pub, base64.RawURLEncoding.EncodeToString(sum[:8]), nil
}

// verifySigned verifies a compact JWS against the wallet-provider JWKS and
// returns its claims. typ, when non-empty, must match the JOSE header, so
// another token type signed by the same key cannot stand in for a WIA.
func (v *WalletCallVerifier) verifySigned(token, typ string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed token header")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, errors.New("malformed token header")
	}
	if typ != "" && hdr.Typ != typ {
		return nil, fmt.Errorf("expected typ %q, got %q", typ, hdr.Typ)
	}
	key, err := v.keyFor(hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed signature")
	}
	if err := jwkVerify(hdr.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed claims")
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, errors.New("malformed claims")
	}
	return claims, nil
}

// keyFor returns the wallet-provider key with this kid, refreshing the
// cached JWKS when the kid is unknown or the cache has aged out.
func (v *WalletCallVerifier) keyFor(kid string) (*jwkKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	fresh := time.Since(v.fetchedAt) < jwksTTL
	if fresh {
		if k := v.lookupLocked(kid); k != nil {
			return k, nil
		}
	}
	keys, err := (&Verifier{log: v.log}).fetchJWKS(v.jwksURI)
	if err != nil {
		// Serve a stale key rather than losing the exemption on a blip.
		if k := v.lookupLocked(kid); k != nil {
			return k, nil
		}
		return nil, fmt.Errorf("wallet-provider JWKS: %w", err)
	}
	v.keys = keys
	v.fetchedAt = time.Now()
	if k := v.lookupLocked(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("unknown wallet-provider key %q", kid)
}

// lookupLocked resolves a kid, tolerating a JWKS with a single unlabelled
// key (the issuer publishes one signing key).
func (v *WalletCallVerifier) lookupLocked(kid string) *jwkKey {
	if len(v.keys) == 0 {
		return nil
	}
	if k, ok := v.keys[kid]; ok {
		return k
	}
	if len(v.keys) == 1 {
		for _, k := range v.keys {
			return k
		}
	}
	return nil
}

// verifyCallProof checks a wallet-pop+jwt signed by the holder key and
// bound to this request: htm/htu must match the method and path, and iat
// must be fresh.
func verifyCallProof(proof string, holder *ecdsa.PublicKey, method, path string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return errors.New("malformed proof")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return errors.New("malformed proof header")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return errors.New("malformed proof header")
	}
	if hdr.Typ != proofTyp {
		return fmt.Errorf("expected typ %q, got %q", proofTyp, hdr.Typ)
	}
	if hdr.Alg != "ES256" {
		return fmt.Errorf("unsupported proof alg %q", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("proof signature must be 64-byte raw ECDSA")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	rr := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(holder, digest[:], rr, ss) {
		return errors.New("proof not signed by the attested holder key")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("malformed proof claims")
	}
	var c struct {
		HTM string  `json:"htm"`
		HTU string  `json:"htu"`
		IAT float64 `json:"iat"`
	}
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return errors.New("malformed proof claims")
	}
	if !strings.EqualFold(c.HTM, method) {
		return fmt.Errorf("proof bound to method %q, request is %q", c.HTM, method)
	}
	if c.HTU != path {
		return fmt.Errorf("proof bound to path %q, request is %q", c.HTU, path)
	}
	if d := time.Since(time.Unix(int64(c.IAT), 0)); d > proofFreshness || d < -proofFreshness {
		return errors.New("proof outside the freshness window")
	}
	return nil
}

// ecdsaFromJWK reconstructs a P-256 public key from the minimal EC JWK the
// WIA embeds, returning the key and its SEC1 uncompressed point.
func ecdsaFromJWK(jwk map[string]interface{}) (*ecdsa.PublicKey, []byte, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	if kty != "EC" || crv != "P-256" {
		return nil, nil, errors.New("holder key is not an EC P-256 JWK")
	}
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	xb, err := base64.RawURLEncoding.DecodeString(xs)
	if err != nil || len(xb) != 32 {
		return nil, nil, errors.New("holder key x coordinate invalid")
	}
	yb, err := base64.RawURLEncoding.DecodeString(ys)
	if err != nil || len(yb) != 32 {
		return nil, nil, errors.New("holder key y coordinate invalid")
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, nil, errors.New("holder key is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		elliptic.Marshal(elliptic.P256(), x, y), nil
}
