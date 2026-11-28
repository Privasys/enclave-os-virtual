// Package auth implements OIDC-based authentication for the
// Enclave OS (Virtual) management API.
//
// # OIDC Bearer Tokens
//
// The manager accepts standard OIDC bearer tokens validated via JWKS
// discovery. Tokens must carry either the manager role
// (privasys-platform:manager) for mutating operations, or the
// monitoring role (privasys-platform:monitoring) for read-only access
// (healthz, readyz, status, metrics).
//
// # Policy: containers claim
//
// Tokens can carry a "containers" claim listing permitted image digests:
//
//	{
//	 "containers": [
//	   {"name": "postgres", "digest": "sha256:abc123..."},
//	   {"name": "myapp",    "digest": "sha256:def456..."}
//	 ]
//	}
//
// If the claim is present, load/unload operations are restricted to
// the listed containers. If absent, all operations are permitted
// (implicit trust from the signing key holder).
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
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

	"go.uber.org/zap"
)

// ContainerPermission represents a permitted container in a JWT
// "containers" claim.
type ContainerPermission struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// AuthResult is returned by successful authentication, carrying the
// parsed claims relevant for authorization.
type AuthResult struct {
	// Source is always "oidc".
	Source string

	// Role is the matched role: "manager" or "monitoring".
	Role string

	// Containers is the list of permitted containers from the token.
	// If nil, all containers are permitted (implicit trust).
	Containers []ContainerPermission

	// Subject is the authenticated identity (OIDC "sub" claim).
	Subject string
}

// HasManagerAccess returns true if the result has manager-level
// (mutating) access.
func (r *AuthResult) HasManagerAccess() bool {
	return r.Role == "manager"
}

// HasMonitoringAccess returns true if the result has at least
// monitoring-level (read-only) access. Manager-level access implies
// monitoring access.
func (r *AuthResult) HasMonitoringAccess() bool {
	return r.HasManagerAccess() || r.Role == "monitoring"
}

// IsContainerPermitted checks whether a given image reference (with
// @sha256:... digest) is permitted by this auth result.
// If Containers is nil, everything is permitted.
func (r *AuthResult) IsContainerPermitted(imageRef string) bool {
	if r.Containers == nil {
		return true
	}
	for _, c := range r.Containers {
		if c.Digest != "" && strings.Contains(imageRef, "@"+c.Digest) {
			return true
		}
	}
	return false
}

// IsUnloadPermitted checks whether unloading a container by name is
// permitted by this auth result.
func (r *AuthResult) IsUnloadPermitted(name string) bool {
	if r.Containers == nil {
		return true
	}
	for _, c := range r.Containers {
		if c.Name == name {
			return true
		}
	}
	return false
}

// OIDCConfig holds OIDC verification configuration.
type OIDCConfig struct {
	// Issuer is the OIDC issuer URL (e.g. https://auth.example.com).
	Issuer string

	// Audience is the expected "aud" claim (e.g. "enclave-os-virtual").
	Audience string

	// ManagerRole is the role required for mutating operations
	// (load/unload containers). Default: "privasys-platform:manager".
	ManagerRole string

	// MonitoringRole is the role for read-only operations
	// (healthz, readyz, status, metrics). Default: "privasys-platform:monitoring".
	MonitoringRole string

	// RoleClaim is the JWT claim key containing roles.
	// Default: "roles".
	RoleClaim string
}

// Verifier validates management API requests using OIDC tokens.
type Verifier struct {
	oidc   *OIDCConfig
	jwks   *jwksCache
	jwksMu sync.RWMutex
	log    *zap.Logger

	// refreshMu serialises JWKS refreshes and guards lastRefresh. It is
	// never held by a lookup that hits the cache.
	refreshMu   sync.Mutex
	lastRefresh time.Time
}

// oidcJWKSTTL is how long a fetched key set is served without refreshing.
const oidcJWKSTTL = 5 * time.Minute

// oidcJWKSMinRefresh bounds how often a cache miss may refresh the key set.
// The kid is caller-chosen, so without it every request with an unknown
// kid cost an OIDC discovery plus a JWKS fetch.
const oidcJWKSMinRefresh = 10 * time.Second

// NewVerifier creates a Verifier for OIDC token verification.
func NewVerifier(oidcCfg *OIDCConfig, log *zap.Logger) (*Verifier, error) {
	if oidcCfg == nil {
		return nil, errors.New("auth: OIDC configuration is required")
	}
	if oidcCfg.Issuer == "" {
		return nil, errors.New("auth: OIDC issuer is required")
	}

	if oidcCfg.RoleClaim == "" {
		oidcCfg.RoleClaim = "roles"
	}
	if oidcCfg.ManagerRole == "" {
		oidcCfg.ManagerRole = "privasys-platform:manager"
	}
	if oidcCfg.MonitoringRole == "" {
		oidcCfg.MonitoringRole = "privasys-platform:monitoring"
	}

	v := &Verifier{
		oidc: oidcCfg,
		log:  log.Named("auth"),
	}

	log.Info("OIDC authentication configured",
		zap.String("issuer", oidcCfg.Issuer),
		zap.String("audience", oidcCfg.Audience),
		zap.String("manager_role", oidcCfg.ManagerRole),
		zap.String("monitoring_role", oidcCfg.MonitoringRole),
		zap.String("role_claim", oidcCfg.RoleClaim),
	)

	return v, nil
}

// --- JWKS / OIDC discovery ---

type jwksCache struct {
	keys      map[string]*jwkKey
	fetchedAt time.Time
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type oidcDiscovery struct {
	JwksURI string `json:"jwks_uri"`
}

// getSigningKey returns the key for kid (or, with no kid, one matching alg).
//
// A hit on a fresh cache takes only the read lock. A miss or a stale cache
// refreshes the key set, but at most once per oidcJWKSMinRefresh across all
// callers, and the network round trip holds refreshMu, not jwksMu, so it
// never blocks lookups that hit. It used to hold the jwks write lock across
// discovery and fetch on every miss: a caller sending tokens with random
// kids serialised every verification behind its own IdP round trips.
func (v *Verifier) getSigningKey(kid, alg string) (*jwkKey, error) {
	if key, fresh := v.cachedKey(kid, alg); key != nil && fresh {
		return key, nil
	}

	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	// Another caller may have refreshed while we waited.
	if key, fresh := v.cachedKey(kid, alg); key != nil && fresh {
		return key, nil
	}
	if time.Since(v.lastRefresh) < oidcJWKSMinRefresh {
		// Refreshed moments ago: answer from what we have rather than
		// fetch again for a kid the IdP did not publish.
		if key, _ := v.cachedKey(kid, alg); key != nil {
			return key, nil
		}
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	v.lastRefresh = time.Now()

	jwksURI, err := v.discoverJWKS()
	if err != nil {
		return nil, err
	}
	keys, err := v.fetchJWKS(jwksURI)
	if err != nil {
		return nil, err
	}
	v.jwksMu.Lock()
	v.jwks = &jwksCache{keys: keys, fetchedAt: time.Now()}
	v.jwksMu.Unlock()

	if key := findKey(keys, kid, alg); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("key %q not found in JWKS", kid)
}

// cachedKey looks kid up in the cached key set, reporting whether the set
// is within its TTL.
func (v *Verifier) cachedKey(kid, alg string) (key *jwkKey, fresh bool) {
	v.jwksMu.RLock()
	defer v.jwksMu.RUnlock()
	if v.jwks == nil {
		return nil, false
	}
	return findKey(v.jwks.keys, kid, alg), time.Since(v.jwks.fetchedAt) < oidcJWKSTTL
}

// findKey returns the key with this kid or, when kid is empty, the first
// signing key matching alg.
func findKey(keys map[string]*jwkKey, kid, alg string) *jwkKey {
	if key, ok := keys[kid]; ok {
		return key
	}
	if kid == "" {
		for _, k := range keys {
			if k.Alg == alg || (k.Use == "sig" && k.Alg == "") {
				return k
			}
		}
	}
	return nil
}

func (v *Verifier) discoverJWKS() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := strings.TrimRight(v.oidc.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var disc oidcDiscovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return "", fmt.Errorf("OIDC discovery parse: %w", err)
	}
	if disc.JwksURI == "" {
		return "", errors.New("OIDC discovery: no jwks_uri")
	}
	return disc.JwksURI, nil
}

func (v *Verifier) fetchJWKS(uri string) (map[string]*jwkKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var jwksResp jwksResponse
	if err := json.Unmarshal(body, &jwksResp); err != nil {
		return nil, fmt.Errorf("JWKS parse: %w", err)
	}
	keys := make(map[string]*jwkKey, len(jwksResp.Keys))
	for i := range jwksResp.Keys {
		k := &jwksResp.Keys[i]
		keys[k.Kid] = k
	}
	v.log.Debug("JWKS fetched", zap.Int("keys", len(keys)))
	return keys, nil
}

// jwkVerify verifies a JWT signature using a JWK.
func jwkVerify(alg string, key *jwkKey, signingInput, sig []byte) error {
	switch {
	case strings.HasPrefix(alg, "RS"):
		return jwkVerifyRSA(alg, key, signingInput, sig)
	case strings.HasPrefix(alg, "ES"):
		return jwkVerifyEC(alg, key, signingInput, sig)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func jwkVerifyRSA(alg string, key *jwkKey, signingInput, sig []byte) error {
	if key.Kty != "RSA" {
		return fmt.Errorf("expected RSA key, got %s", key.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}

	var hashFunc crypto.Hash
	switch alg {
	case "RS256":
		hashFunc = crypto.SHA256
	case "RS384":
		hashFunc = crypto.SHA384
	case "RS512":
		hashFunc = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA algorithm: %s", alg)
	}

	h := hashFunc.New()
	h.Write(signingInput)
	return rsa.VerifyPKCS1v15(pub, hashFunc, h.Sum(nil), sig)
}

func jwkVerifyEC(alg string, key *jwkKey, signingInput, sig []byte) error {
	if key.Kty != "EC" {
		return fmt.Errorf("expected EC key, got %s", key.Kty)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return err
	}

	var curve elliptic.Curve
	var keySize int
	var hashFn func([]byte) []byte

	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
		keySize = 32
		hashFn = func(data []byte) []byte { h := sha256.Sum256(data); return h[:] }
	case "P-384":
		curve = elliptic.P384()
		keySize = 48
		hashFn = func(data []byte) []byte { h := sha512.Sum384(data); return h[:] }
	default:
		return fmt.Errorf("unsupported curve: %s", key.Crv)
	}

	if len(sig) != keySize*2 {
		return fmt.Errorf("EC sig wrong length: %d, want %d", len(sig), keySize*2)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])
	hash := hashFn(signingInput)

	if !ecdsa.Verify(pub, hash, r, s) {
		return errors.New("EC signature verification failed")
	}
	return nil
}
