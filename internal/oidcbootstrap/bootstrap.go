// Package oidcbootstrap implements the OIDC jwt-bearer grant flow for
// self-provisioning attestation server bearer tokens.
//
// The implementation targets Zitadel (key registration via
// POST /v2/users/{id}/keys, Zitadel-specific audience scopes).
// The jwt-bearer token exchange itself is standard RFC 7523.
//
// Flow:
//  1. Generate an ECDSA P-256 keypair.
//  2. Register the public key with the OIDC provider (Zitadel AddKey API).
//  3. Build a JWT assertion (ES256) signed with the private key.
//  4. Exchange the assertion for an access token (jwt-bearer grant).
//  5. Cache the token and refresh at 75% of its lifetime.
package oidcbootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Config holds the OIDC bootstrap configuration for a single instance.
type Config struct {
	// Issuer is the OIDC provider URL (e.g. https://auth.privasys.org).
	Issuer string
	// ServiceAccountID is the Zitadel service account user ID.
	ServiceAccountID string
	// ProjectID is the OIDC project ID for audience-scoped tokens (optional).
	ProjectID string
}

// Result holds the output of a successful bootstrap or refresh.
type Result struct {
	AccessToken string
	ExpiresIn   int64
	KeyID       string
	PrivateKey  *ecdsa.PrivateKey
}

// tokenState tracks a cached token and its refresh metadata.
type tokenState struct {
	mu         sync.RWMutex
	token      string
	issuedAt   time.Time
	expiresAt  time.Time
	keyID      string
	privateKey *ecdsa.PrivateKey
	config     Config
}

// Manager orchestrates OIDC bootstrap for multiple attestation servers.
type Manager struct {
	log    *zap.Logger
	states map[string]*tokenState // keyed by attestation server URL
	mu     sync.RWMutex
	stopCh chan struct{}
}

// NewManager creates a new bootstrap manager.
func NewManager(log *zap.Logger) *Manager {
	return &Manager{
		log:    log,
		states: make(map[string]*tokenState),
		stopCh: make(chan struct{}),
	}
}

// Bootstrap executes the full OIDC bootstrap flow for an attestation server:
// keygen → register public key → exchange for access token.
func (m *Manager) Bootstrap(serverURL string, cfg Config, managerJWT string) error {
	m.log.Info("OIDC bootstrap starting",
		zap.String("server", serverURL),
		zap.String("issuer", cfg.Issuer),
		zap.String("service_account_id", cfg.ServiceAccountID),
	)

	// 1. Generate ECDSA P-256 keypair.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ECDSA keygen failed: %w", err)
	}

	// 2. Register public key with Zitadel.
	keyID, err := registerPublicKey(cfg, managerJWT, privateKey)
	if err != nil {
		return fmt.Errorf("register public key: %w", err)
	}
	m.log.Info("public key registered with OIDC provider",
		zap.String("key_id", keyID),
		zap.String("server", serverURL),
	)

	// 3. Exchange JWT assertion for access token.
	accessToken, expiresIn, err := exchangeJWTBearer(cfg, keyID, privateKey)
	if err != nil {
		return fmt.Errorf("jwt-bearer exchange: %w", err)
	}

	// Cache the token state.
	now := time.Now()
	state := &tokenState{
		token:      accessToken,
		issuedAt:   now,
		expiresAt:  now.Add(time.Duration(expiresIn) * time.Second),
		keyID:      keyID,
		privateKey: privateKey,
		config:     cfg,
	}
	m.mu.Lock()
	m.states[serverURL] = state
	m.mu.Unlock()

	m.log.Info("OIDC bootstrap OK",
		zap.String("server", serverURL),
		zap.Int64("expires_in", expiresIn),
	)
	return nil
}

// Token returns the current access token for an attestation server URL.
// If the token has reached 75% of its lifetime, it is refreshed inline.
func (m *Manager) Token(serverURL string) string {
	m.mu.RLock()
	state, ok := m.states[serverURL]
	m.mu.RUnlock()
	if !ok {
		return ""
	}

	state.mu.RLock()
	remaining := time.Until(state.expiresAt)
	total := state.expiresAt.Sub(state.issuedAt)
	token := state.token
	state.mu.RUnlock()

	// Refresh at 75% of lifetime (25% remaining) or if less than 5 minutes left.
	if remaining < total/4 || remaining < 5*time.Minute {
		m.refreshToken(serverURL, state)
		// Re-read after refresh.
		state.mu.RLock()
		token = state.token
		state.mu.RUnlock()
	}

	return token
}

// StartRefreshLoop starts a background goroutine that proactively refreshes
// tokens before they expire.
func (m *Manager) StartRefreshLoop() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.checkRefreshAll()
			case <-m.stopCh:
				return
			}
		}
	}()
}

// Stop signals the refresh loop to exit.
func (m *Manager) Stop() {
	close(m.stopCh)
}

func (m *Manager) checkRefreshAll() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for url, state := range m.states {
		state.mu.RLock()
		remaining := time.Until(state.expiresAt)
		state.mu.RUnlock()
		if remaining < 15*time.Minute {
			m.refreshToken(url, state)
		}
	}
}

func (m *Manager) refreshToken(serverURL string, state *tokenState) {
	state.mu.Lock()
	defer state.mu.Unlock()

	accessToken, expiresIn, err := exchangeJWTBearer(state.config, state.keyID, state.privateKey)
	if err != nil {
		m.log.Warn("OIDC token refresh failed",
			zap.String("server", serverURL),
			zap.Error(err),
		)
		return
	}

	state.token = accessToken
	state.issuedAt = time.Now()
	state.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	m.log.Info("OIDC token refreshed",
		zap.String("server", serverURL),
		zap.Int64("expires_in", expiresIn),
	)
}

// --------------------------------------------------------------------------
// Step 2 — Register public key with Zitadel
// --------------------------------------------------------------------------

func registerPublicKey(cfg Config, managerJWT string, key *ecdsa.PrivateKey) (string, error) {
	// Marshal the public key to SPKI DER, then PEM, then base64 (Zitadel expectation).
	spkiDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal SPKI: %w", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})
	pubKeyB64 := base64.StdEncoding.EncodeToString(pemBlock)

	// Key expiration: ~12 months from now.
	expDate := time.Now().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z")

	body, _ := json.Marshal(map[string]string{
		"type":           "KEY_TYPE_JSON",
		"publicKey":      pubKeyB64,
		"expirationDate": expDate,
	})

	apiURL := fmt.Sprintf("%s/v2/users/%s/keys",
		strings.TrimRight(cfg.Issuer, "/"),
		cfg.ServiceAccountID,
	)

	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build AddKey request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+managerJWT)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("AddKey request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("AddKey returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		KeyID string `json:"keyId"`
		Key   *struct {
			ID string `json:"id"`
		} `json:"key"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse AddKey response: %w — body: %s", err, string(respBody))
	}

	if result.KeyID != "" {
		return result.KeyID, nil
	}
	if result.Key != nil && result.Key.ID != "" {
		return result.Key.ID, nil
	}
	return "", fmt.Errorf("AddKey returned no keyId — body: %s", string(respBody))
}

// --------------------------------------------------------------------------
// Step 3 — JWT assertion + token exchange
// --------------------------------------------------------------------------

func exchangeJWTBearer(cfg Config, keyID string, key *ecdsa.PrivateKey) (string, int64, error) {
	now := time.Now()

	// Build JWT header + payload.
	header, _ := json.Marshal(map[string]string{
		"alg": "ES256",
		"kid": keyID,
	})
	payload, _ := json.Marshal(map[string]interface{}{
		"iss": cfg.ServiceAccountID,
		"sub": cfg.ServiceAccountID,
		"aud": strings.TrimRight(cfg.Issuer, "/"),
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	headerB64 := base64.RawURLEncoding.EncodeToString(header)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := headerB64 + "." + payloadB64

	// Sign with ES256 (ECDSA P-256 SHA-256).
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", 0, fmt.Errorf("JWT signing failed: %w", err)
	}

	// ES256 signature: r || s, each zero-padded to 32 bytes.
	curveBits := key.Curve.Params().BitSize
	keyBytes := curveBits / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keyBytes)
	copy(sig[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(sig[2*keyBytes-len(sBytes):2*keyBytes], sBytes)

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	assertion := signingInput + "." + sigB64

	// Token exchange via jwt-bearer grant.
	tokenURL := fmt.Sprintf("%s/oauth/v2/token", strings.TrimRight(cfg.Issuer, "/"))

	scopes := "openid urn:zitadel:iam:org:projects:roles"
	if cfg.ProjectID != "" {
		scopes += fmt.Sprintf(" urn:zitadel:iam:org:project:id:%s:aud", cfg.ProjectID)
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"scope":      {scopes},
		"assertion":  {assertion},
	}

	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("parse token response: %w — body: %s", err, string(respBody))
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

// Fingerprint returns the hex-encoded SHA-256 of the ECDSA public key (SPKI DER).
func Fingerprint(key *ecdsa.PrivateKey) string {
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	h := sha256.Sum256(spki)
	return fmt.Sprintf("%x", h)
}
