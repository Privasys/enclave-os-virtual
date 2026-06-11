// Package bootstrap implements the first-boot manager-bootstrap binary
// flow: it fetches an access token from the Privasys IdP using a
// JWT-bearer assertion built from a service-account key delivered out
// of band, then POSTs to the management-service /api/v1/enclave/bootstrap
// endpoint to receive the CA bundle (ca.crt + ca.key) and writes it
// onto the LUKS-encrypted /data partition.
//
// The flow is idempotent: on subsequent boots the systemd unit's
// ConditionPathExists=!/data/ca.crt skips re-execution. If the unit
// runs anyway, Run() short-circuits when ca.crt is already present.
package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Privasys/enclave-os-virtual/internal/tdx"
)

// Config controls a single bootstrap run. Zero values fall back to
// the production defaults.
type Config struct {
	// DataDir is the LUKS-mounted /data partition.
	DataDir string
	// ManagerEnvPath is the file the startup-script (or operator)
	// writes with OIDC_ISSUER, OIDC_AUDIENCE, MGMT_URL etc.
	ManagerEnvPath string
	// ServiceKeyPath is the JSON service-account key file delivered
	// via systemd-creds (preferred) or cloud metadata. The file must
	// match the JSON shape returned by POST /admin/service-accounts:
	//   {"type":"serviceaccount","keyId":"...","key":"-----BEGIN ...",
	//    "userId":"...","accountId":"..."}
	ServiceKeyPath string
	// DekOriginPath records "byok:<sha256-hex>" or "luks-fresh:<ts>"
	// for the bootstrap audit trail. May be empty.
	DekOriginPath string
	// IDPIssuer is the OIDC issuer URL (e.g. https://privasys.id).
	IDPIssuer string
	// IDPAudience is the audience the access token must carry
	// (e.g. privasys-platform).
	IDPAudience string
	// ManagementURL is the management-service base URL
	// (e.g. https://api.developer.privasys.org).
	ManagementURL string
	// AttestationRequired forces a TDX quote into the bootstrap
	// request even when the management-service flag is off (useful
	// for end-to-end testing).
	AttestationRequired bool
	// HTTPTimeout caps each outbound HTTP call. Default 30s.
	HTTPTimeout time.Duration
	// Hostname overrides the host name reported in the bootstrap
	// request. Default: os.Hostname().
	Hostname string
}

// Run executes a single bootstrap attempt. Safe to invoke as a
// systemd Type=oneshot ExecStart.
func Run(ctx context.Context, cfg Config) error {
	cfg = applyDefaults(cfg)

	caCertPath := filepath.Join(cfg.DataDir, "ca.crt")
	caKeyPath := filepath.Join(cfg.DataDir, "ca.key")
	if _, err := os.Stat(caCertPath); err == nil {
		fmt.Fprintf(os.Stderr, "manager-bootstrap: %s already present, nothing to do\n", caCertPath)
		return nil
	}

	host := cfg.Hostname
	if host == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("hostname: %w", err)
		}
		host = h
	}

	if _, statErr := os.Stat(cfg.ServiceKeyPath); statErr != nil {
		// No Phase-B service key delivered: fall back to self-registration
		// (Option B) — enroll with a TDX quote bound to an ephemeral key
		// and block until an admin approves or rejects. See registration.go.
		fmt.Fprintln(os.Stderr, "manager-bootstrap: no bootstrap-service-key, entering self-registration")
		return RunRegistration(ctx, cfg)
	}

	key, err := loadServiceKey(cfg.ServiceKeyPath)
	if err != nil {
		return fmt.Errorf("load service key: %w", err)
	}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}

	accessToken, err := exchangeJWTBearer(ctx, httpClient, cfg.IDPIssuer, cfg.IDPAudience, key)
	if err != nil {
		return fmt.Errorf("idp token exchange: %w", err)
	}

	dekOrigin := readOptionalLine(cfg.DekOriginPath)

	// Bind the TDX quote to a fresh nonce so a captured quote can't be
	// replayed. The verifier (management-service → attestation-server)
	// only checks the quote signature; binding to nonce is policy
	// enforced once the per-enclave attestation gate is on.
	nonce := freshNonce(host, dekOrigin)
	quoteB64 := ""
	if cfg.AttestationRequired {
		var rd [64]byte
		copy(rd[:], nonce)
		raw, qerr := tdx.GetQuote(rd)
		if qerr != nil {
			return fmt.Errorf("tdx quote: %w", qerr)
		}
		quoteB64 = base64.StdEncoding.EncodeToString(raw)
	}

	bundle, err := callBootstrap(ctx, httpClient, cfg.ManagementURL, accessToken, bootstrapRequest{
		Host:      host,
		DekOrigin: dekOrigin,
		TDXQuote:  quoteB64,
		Nonce:     nonce,
	})
	if err != nil {
		return fmt.Errorf("management-service bootstrap: %w", err)
	}

	if err := writeFileAtomic(caCertPath, []byte(bundle.CACert), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", caCertPath, err)
	}
	if err := writeFileAtomic(caKeyPath, []byte(bundle.CAKey), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", caKeyPath, err)
	}
	if len(bundle.ManagerEnv) > 0 {
		if err := mergeManagerEnv(cfg.ManagerEnvPath, bundle.ManagerEnv); err != nil {
			return fmt.Errorf("merge %s: %w", cfg.ManagerEnvPath, err)
		}
	}

	fmt.Fprintf(os.Stderr, "manager-bootstrap: wrote %s and %s (mgmt=%s)\n", caCertPath, caKeyPath, cfg.ManagementURL)
	return nil
}

func applyDefaults(c Config) Config {
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	if c.ManagerEnvPath == "" {
		c.ManagerEnvPath = "/data/manager.env"
	}
	if c.ServiceKeyPath == "" {
		if cd := os.Getenv("CREDENTIALS_DIRECTORY"); cd != "" {
			c.ServiceKeyPath = filepath.Join(cd, "bootstrap-service-key")
		} else {
			c.ServiceKeyPath = "/run/secrets/bootstrap-service-key"
		}
	}
	if c.IDPIssuer == "" {
		c.IDPIssuer = "https://privasys.id"
	}
	if c.IDPAudience == "" {
		c.IDPAudience = "privasys-platform"
	}
	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = 30 * time.Second
	}
	return c
}

// ---------------------------------------------------------------------------
//  Service key + JWT-bearer assertion
// ---------------------------------------------------------------------------

type serviceKeyFile struct {
	Type     string `json:"type"`
	KeyID    string `json:"keyId"`
	Key      string `json:"key"`
	UserID   string `json:"userId"`
	ClientID string `json:"clientId"`
	// AccountID is what current IdP versions emit; older builds used
	// ClientID. Accept both.
	AccountID string `json:"accountId"`
}

type loadedKey struct {
	keyID  string
	userID string
	signer *rsa.PrivateKey
}

func loadServiceKey(path string) (*loadedKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f serviceKeyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse service-key json: %w", err)
	}
	if f.Type != "" && f.Type != "serviceaccount" {
		return nil, fmt.Errorf("unexpected service-key type %q", f.Type)
	}
	if f.KeyID == "" || f.Key == "" || f.UserID == "" {
		return nil, errors.New("service-key json missing keyId/key/userId")
	}
	block, _ := pem.Decode([]byte(f.Key))
	if block == nil {
		return nil, errors.New("service-key PEM block not found")
	}
	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = k
	} else if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("service-key is %T, want *rsa.PrivateKey", k)
		}
		priv = rk
	} else {
		return nil, fmt.Errorf("parse service-key: %w", err)
	}
	return &loadedKey{keyID: f.KeyID, userID: f.UserID, signer: priv}, nil
}

func exchangeJWTBearer(ctx context.Context, client *http.Client, issuer, audience string, key *loadedKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": key.userID,
		"sub": key.userID,
		"aud": strings.TrimRight(issuer, "/"),
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = key.keyID
	assertion, err := tok.SignedString(key.signer)
	if err != nil {
		return "", fmt.Errorf("sign assertion: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	form.Set("scope", "openid audience:"+audience)

	tokenURL := strings.TrimRight(issuer, "/") + "/token"
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("idp /token returned %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("idp /token returned non-JSON: %s", string(body))
	}
	if out.AccessToken == "" {
		return "", errors.New("idp /token returned empty access_token")
	}
	return out.AccessToken, nil
}

// ---------------------------------------------------------------------------
//  Management-service /enclave/bootstrap call
// ---------------------------------------------------------------------------

type bootstrapRequest struct {
	Host      string `json:"host"`
	DekOrigin string `json:"dek_origin,omitempty"`
	TDXQuote  string `json:"tdx_quote,omitempty"`
	Nonce     string `json:"nonce"`
}

type bootstrapResponse struct {
	CACert     string            `json:"ca_cert"`
	CAKey      string            `json:"ca_key"`
	ManagerEnv map[string]string `json:"manager_env,omitempty"`
}

func callBootstrap(ctx context.Context, client *http.Client, mgmtURL, bearer string, req bootstrapRequest) (*bootstrapResponse, error) {
	body, _ := json.Marshal(req)
	endpoint := strings.TrimRight(mgmtURL, "/") + "/api/v1/enclave/bootstrap"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bootstrap endpoint %d: %s", resp.StatusCode, string(rb))
	}
	var out bootstrapResponse
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, fmt.Errorf("bootstrap endpoint returned non-JSON: %s", string(rb))
	}
	if out.CACert == "" || out.CAKey == "" {
		return nil, errors.New("bootstrap endpoint returned empty CA bundle")
	}
	return &out, nil
}

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

func readOptionalLine(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func freshNonce(host, dekOrigin string) string {
	// Hex sha256 of host || dek-origin || time. Bound to REPORTDATA
	// (first 32 bytes), which the verifier echoes back.
	h := sha256.New()
	h.Write([]byte(host))
	h.Write([]byte{0})
	h.Write([]byte(dekOrigin))
	h.Write([]byte{0})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	h.Write([]byte(now))
	var rnd [16]byte
	_, _ = rand.Read(rnd[:])
	h.Write(rnd[:])
	return hex.EncodeToString(h.Sum(nil))
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".bootstrap-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// mergeManagerEnv overlays the keys the management-service returned
// onto the existing systemd EnvironmentFile, preserving any operator
// overrides written by the startup script (e.g. MGMT_URL,
// ATTESTATION_SERVERS) and only appending keys that are missing.
//
// Format is `KEY=value` lines, comments and blanks preserved.
func mergeManagerEnv(path string, kv map[string]string) error {
	existing := map[string]bool{}
	var lines []string
	if b, err := os.ReadFile(path); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			lines = append(lines, ln)
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if i := strings.IndexByte(t, '='); i > 0 {
				existing[t[:i]] = true
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	added := false
	for k, v := range kv {
		if existing[k] {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s=%s", k, v))
		added = true
	}
	if !added {
		return nil
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return writeFileAtomic(path, []byte(out), 0o644)
}
