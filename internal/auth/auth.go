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
	// Default: "urn:zitadel:iam:org:project:roles".
	RoleClaim string
}

// Verifier validates management API requests using OIDC tokens.
type Verifier struct {
	oidc   *OIDCConfig
	jwks   *jwksCache
	jwksMu sync.RWMutex
	log    *zap.Logger
}

// NewVerifier creates a Verifier for OIDC token verification.
func NewVerifier(oidcCfg *OIDCConfig, log *zap.Logger) (*Verifier, error) {
	if oidcCfg == nil {
		return nil, errors.New("auth: OIDC configuration is required")
	}
	if oidcCfg.Issuer == "" {
		return nil, errors.New("auth: OIDC issuer is required")
	}

	if oidcCfg.RoleClaim == "" {
		oidcCfg.RoleClaim = "urn:zitadel:iam:org:project:roles"
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

// Authenticate verifies an OIDC bearer token.
func (v *Verifier) Authenticate(tokenStr string) (*AuthResult, error) {
	return v.verifyOIDCToken(tokenStr)
}

// verifyOIDCToken validates a standard OIDC bearer token via JWKS.
func (v *Verifier) verifyOIDCToken(tokenStr string) (*AuthResult, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("auth: malformed OIDC token")
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC header decode: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("auth: OIDC header parse: %w", err)
	}

	// Get signing key from JWKS.
	jwk, err := v.getSigningKey(header.Kid, header.Alg)
	if err != nil {
		return nil, fmt.Errorf("auth: JWKS lookup: %w", err)
	}

	// Verify signature.
	signingInput := []byte(parts[0] + "." + parts[1])
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC sig decode: %w", err)
	}
	if err := jwkVerify(header.Alg, jwk, signingInput, sigBytes); err != nil {
		return nil, fmt.Errorf("auth: OIDC sig: %w", err)
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC claims decode: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("auth: OIDC claims parse: %w", err)
	}

	// Validate issuer.
	if iss, _ := claims["iss"].(string); iss != v.oidc.Issuer {
		return nil, fmt.Errorf("auth: OIDC issuer %q != %q", iss, v.oidc.Issuer)
	}

	// Validate audience.
	if v.oidc.Audience != "" && !checkAudience(claims, v.oidc.Audience) {
		return nil, fmt.Errorf("auth: OIDC audience missing %q", v.oidc.Audience)
	}

	// Validate expiry.
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("auth: OIDC token expired")
		}
	}

	// Determine role from token.
	role := ""
	if v.oidc.ManagerRole != "" && checkRole(claims, v.oidc.ManagerRole, v.oidc.RoleClaim) {
		role = "manager"
	} else if v.oidc.MonitoringRole != "" && checkRole(claims, v.oidc.MonitoringRole, v.oidc.RoleClaim) {
		role = "monitoring"
	} else if v.oidc.ManagerRole != "" || v.oidc.MonitoringRole != "" {
		return nil, fmt.Errorf("auth: OIDC token missing required role (%s or %s)", v.oidc.ManagerRole, v.oidc.MonitoringRole)
	}

	// Extract containers claim.
	var containers []ContainerPermission
	if raw, ok := claims["containers"]; ok {
		data, _ := json.Marshal(raw)
		_ = json.Unmarshal(data, &containers)
	}

	sub, _ := claims["sub"].(string)
	v.log.Info("OIDC token verified",
		zap.String("sub", sub),
		zap.String("role", role),
		zap.Int("permitted_containers", len(containers)),
	)

	return &AuthResult{
		Source:     "oidc",
		Role:       role,
		Subject:    sub,
		Containers: containers,
	}, nil
}

// --- Audience / Role helpers ---

func checkAudience(claims map[string]interface{}, expected string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == expected
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// checkRole checks multiple claim paths for the required role:
//  1. The configured roleClaim (map of role->metadata, or array)
//  2. "roles" (standard string array)
//  3. "realm_access.roles" (Keycloak)
//  4. Zitadel project-specific: any key matching "urn:zitadel:iam:org:project:*:roles"
func checkRole(claims map[string]interface{}, role, roleClaim string) bool {
	// 1. Configured claim (may be a map: {"role-name": {...}} or an array).
	if raw, ok := claims[roleClaim]; ok {
		if roleMap, ok := raw.(map[string]interface{}); ok {
			if _, has := roleMap[role]; has {
				return true
			}
		}
		if arr, ok := raw.([]interface{}); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok && s == role {
					return true
				}
			}
		}
	}

	// 2. Standard "roles" array.
	if raw, ok := claims["roles"]; ok {
		if arr, ok := raw.([]interface{}); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok && s == role {
					return true
				}
			}
		}
	}

	// 3. Keycloak "realm_access.roles".
	if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
		if arr, ok := ra["roles"].([]interface{}); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok && s == role {
					return true
				}
			}
		}
	}

	// 4. Zitadel project-specific claims: urn:zitadel:iam:org:project:{PROJECT_ID}:roles
	// Service accounts using JWT profile grants with plural "projects" scope
	// produce project-scoped claims at this path instead of the generic one.
	for key, raw := range claims {
		if key == roleClaim {
			continue // already checked in path 1
		}
		if strings.HasPrefix(key, "urn:zitadel:iam:org:project:") && strings.HasSuffix(key, ":roles") {
			if roleMap, ok := raw.(map[string]interface{}); ok {
				if _, has := roleMap[role]; has {
					return true
				}
			}
			if arr, ok := raw.([]interface{}); ok {
				for _, r := range arr {
					if s, ok := r.(string); ok && s == role {
						return true
					}
				}
			}
		}
	}

	return false
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

func (v *Verifier) getSigningKey(kid, alg string) (*jwkKey, error) {
	v.jwksMu.RLock()
	if v.jwks != nil && time.Since(v.jwks.fetchedAt) < 5*time.Minute {
		if key, ok := v.jwks.keys[kid]; ok {
			v.jwksMu.RUnlock()
			return key, nil
		}
	}
	v.jwksMu.RUnlock()

	v.jwksMu.Lock()
	defer v.jwksMu.Unlock()

	// Double-check.
	if v.jwks != nil && time.Since(v.jwks.fetchedAt) < 5*time.Minute {
		if key, ok := v.jwks.keys[kid]; ok {
			return key, nil
		}
	}

	jwksURI, err := v.discoverJWKS()
	if err != nil {
		return nil, err
	}
	keys, err := v.fetchJWKS(jwksURI)
	if err != nil {
		return nil, err
	}
	v.jwks = &jwksCache{keys: keys, fetchedAt: time.Now()}

	if key, ok := keys[kid]; ok {
		return key, nil
	}
	// If kid empty, find matching alg.
	if kid == "" {
		for _, k := range keys {
			if k.Alg == alg || (k.Use == "sig" && k.Alg == "") {
				return k, nil
			}
		}
	}
	return nil, fmt.Errorf("key %q not found in JWKS", kid)
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
