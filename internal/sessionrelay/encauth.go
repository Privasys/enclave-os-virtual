// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessionrelay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// EncAuthEnvelope is the on-wire JSON form of a wallet-issued
// silent-rebind voucher. Mirrors the shape stored in the IdP's
// `sessions.encauth_blob` column. See
// `.operations/identity-platform/session-relay/crypto-contract.md` §8.
type EncAuthEnvelope struct {
	V       uint8  `json:"v"`
	Payload string `json:"payload"` // base64url(canonical CBOR)
	HwSig   string `json:"hw_sig"`  // base64url(64 B R||S)
	IdpSig  string `json:"idp_sig"` // base64url(64 B R||S)
}

// EncAuthPayload is the decoded payload. Field tags match the
// canonical CBOR encoding emitted by the wallet and the IdP (integer
// keys 1..10 in ascending order).
type EncAuthPayload struct {
	V         uint64 `cbor:"1,keyasint"`
	Sub       string `cbor:"2,keyasint"`
	SID       string `cbor:"3,keyasint"`
	AppID     []byte `cbor:"4,keyasint"`
	EncMeas   []byte `cbor:"5,keyasint"`
	EncPub    []byte `cbor:"6,keyasint"`
	QuoteHash []byte `cbor:"7,keyasint"`
	NotBefore uint64 `cbor:"8,keyasint"`
	NotAfter  uint64 `cbor:"9,keyasint"`
	HwPub     []byte `cbor:"10,keyasint"`
}

// EncAuthVerifier validates a voucher and decides whether to accept
// the silent rebind. Implementations are responsible for fetching and
// caching the IdP JWKS.
type EncAuthVerifier interface {
	// Verify returns the decoded payload if the envelope is valid for
	// this enclave. encStaticPub is the SEC1 uncompressed bytes of
	// the enclave's identity key; payload.EncPub must equal it byte
	// for byte. leafHash + hasLeaf control the optional quote_hash
	// binding (some test setups have no RA-TLS leaf).
	Verify(env *EncAuthEnvelope, encStaticPub []byte, leafHash [32]byte, hasLeaf bool, now time.Time) (*EncAuthPayload, error)
}

// JWKSResolver fetches the IdP's signing key by kid. Implementations
// SHOULD cache results.
type JWKSResolver interface {
	// PublicKey returns the P-256 public key matching kid. When kid
	// is empty, may return any current signing key.
	PublicKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error)
}

// JWKSResolverFunc is a function adapter for JWKSResolver.
type JWKSResolverFunc func(ctx context.Context, kid string) (*ecdsa.PublicKey, error)

// PublicKey implements JWKSResolver.
func (f JWKSResolverFunc) PublicKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	return f(ctx, kid)
}

// DefaultEncAuthVerifier is the canonical EncAuth verifier. It reads
// the IdP signing key from the supplied resolver (kid is currently
// not embedded in the envelope; callers should expose at least one
// signing key per IdP issuer).
type DefaultEncAuthVerifier struct {
	Resolver JWKSResolver
}

// Verify implements EncAuthVerifier.
func (v *DefaultEncAuthVerifier) Verify(env *EncAuthEnvelope, encStaticPub []byte, leafHash [32]byte, hasLeaf bool, now time.Time) (*EncAuthPayload, error) {
	if env == nil {
		return nil, errors.New("encauth: nil envelope")
	}
	if env.V != 1 {
		return nil, fmt.Errorf("encauth: unsupported version %d", env.V)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("encauth: payload b64: %w", err)
	}
	hwSig, err := base64.RawURLEncoding.DecodeString(env.HwSig)
	if err != nil {
		return nil, fmt.Errorf("encauth: hw_sig b64: %w", err)
	}
	idpSig, err := base64.RawURLEncoding.DecodeString(env.IdpSig)
	if err != nil {
		return nil, fmt.Errorf("encauth: idp_sig b64: %w", err)
	}

	var payload EncAuthPayload
	if err := cbor.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("encauth: payload cbor: %w", err)
	}

	// idp_sig must verify against the IdP's signing key, computed
	// over (payload || hw_sig). This MUST be checked before any
	// payload-derived value is trusted.
	if v.Resolver == nil {
		return nil, errors.New("encauth: no JWKS resolver configured")
	}
	idpPub, err := v.Resolver.PublicKey(context.Background(), "")
	if err != nil {
		return nil, fmt.Errorf("encauth: jwks: %w", err)
	}
	idpInput := make([]byte, 0, len(payloadBytes)+len(hwSig))
	idpInput = append(idpInput, payloadBytes...)
	idpInput = append(idpInput, hwSig...)
	if err := verifyES256Raw(idpPub, idpSig, idpInput); err != nil {
		return nil, fmt.Errorf("encauth: idp_sig: %w", err)
	}

	// hw_sig must verify against the hardware key embedded in the
	// payload. This proves the wallet co-signed the same payload the
	// IdP attested to.
	if len(payload.HwPub) != 65 || payload.HwPub[0] != 0x04 {
		return nil, errors.New("encauth: hw_pub must be P-256 SEC1 uncompressed")
	}
	hwPub, err := sec1ToP256(payload.HwPub)
	if err != nil {
		return nil, fmt.Errorf("encauth: hw_pub: %w", err)
	}
	if err := verifyES256Raw(hwPub, hwSig, payloadBytes); err != nil {
		return nil, fmt.Errorf("encauth: hw_sig: %w", err)
	}

	// enc_pub must match this enclave's identity key byte-for-byte.
	if !bytes.Equal(payload.EncPub, encStaticPub) {
		return nil, errors.New("encauth: enc_pub does not match this enclave")
	}

	// Optional leaf-cert binding.
	if hasLeaf && !bytes.Equal(payload.QuoteHash, leafHash[:]) {
		return nil, errors.New("encauth: quote_hash does not match RA-TLS leaf")
	}

	// Time window.
	nowSec := uint64(now.Unix())
	if nowSec+30 < payload.NotBefore { // 30s skew
		return nil, errors.New("encauth: not yet valid")
	}
	if nowSec >= payload.NotAfter {
		return nil, errors.New("encauth: expired")
	}
	if payload.SID == "" {
		return nil, errors.New("encauth: empty sid")
	}
	return &payload, nil
}

// HTTPJWKSResolver is a simple OIDC discovery + JWKS fetcher with a
// time-based cache. Suitable for the enclave's outbound IdP fetches.
type HTTPJWKSResolver struct {
	Issuer string        // e.g. "https://privasys.id"
	TTL    time.Duration // cache TTL; default 5 min
	Client *http.Client  // optional; uses http.DefaultClient when nil

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey // kid -> key
	any       *ecdsa.PublicKey            // fallback when caller passes empty kid
	fetchedAt time.Time
}

// PublicKey implements JWKSResolver.
func (r *HTTPJWKSResolver) PublicKey(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	r.mu.Lock()
	ttl := r.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	if r.fetchedAt.IsZero() || time.Since(r.fetchedAt) > ttl {
		if err := r.refreshLocked(ctx); err != nil {
			r.mu.Unlock()
			return nil, err
		}
	}
	if kid == "" {
		k := r.any
		r.mu.Unlock()
		if k == nil {
			return nil, errors.New("jwks: no signing key")
		}
		return k, nil
	}
	k, ok := r.keys[kid]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("jwks: kid %q not found", kid)
	}
	return k, nil
}

func (r *HTTPJWKSResolver) refreshLocked(ctx context.Context) error {
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	disc := strings.TrimRight(r.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks discovery: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return err
	}
	var d struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return fmt.Errorf("jwks discovery parse: %w", err)
	}
	if d.JwksURI == "" {
		return errors.New("jwks discovery: no jwks_uri")
	}

	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, d.JwksURI, nil)
	if err != nil {
		return err
	}
	resp2, err := client.Do(req2)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	body2, err := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
	resp2.Body.Close()
	if err != nil {
		return err
	}
	var jwks struct {
		Keys []struct {
			Kty, Crv, X, Y, Kid string
		} `json:"keys"`
	}
	if err := json.Unmarshal(body2, &jwks); err != nil {
		return fmt.Errorf("jwks parse: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey, len(jwks.Keys))
	var anyKey *ecdsa.PublicKey
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			continue
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			continue
		}
		keys[k.Kid] = pub
		if anyKey == nil {
			anyKey = pub
		}
	}
	r.keys = keys
	r.any = anyKey
	r.fetchedAt = time.Now()
	return nil
}

// --- helpers ---------------------------------------------------------

func sec1ToP256(sec1 []byte) (*ecdsa.PublicKey, error) {
	if len(sec1) != 65 || sec1[0] != 0x04 {
		return nil, errors.New("sec1: must be 65 bytes uncompressed")
	}
	x := new(big.Int).SetBytes(sec1[1:33])
	y := new(big.Int).SetBytes(sec1[33:65])
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("sec1: point not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func verifyES256Raw(pub *ecdsa.PublicKey, sig, msg []byte) error {
	if len(sig) != 64 {
		return errors.New("sig must be 64 bytes (R||S)")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("verify failed")
	}
	return nil
}
