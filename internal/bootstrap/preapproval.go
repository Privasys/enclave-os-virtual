package bootstrap

// Pre-approval redemption (the enclave pre-approval design, 2026-07).
//
// The operator pre-approves the enclave BEFORE the VM exists and passes a
// single-use bootstrap token as instance metadata. On first boot — BEFORE
// /data exists — Redeem() binds an ephemeral X25519 key into a TDX quote and
// exchanges the token at POST /api/v1/enclave/redeem for a payload sealed to
// that key: the CA bundle, the per-enclave credential, the manager env, an
// attestation-server bearer, and the vault bundle (grant + constellation) for
// the manager's /data DEK. No callback listener, no polling, no admin wait:
// approval happened at provisioning time; the quote (whose RTMR1/RTMR2 must
// match the pre-approved Enclave OS release) is the boot-time gate.
//
// On later boots the /data DEK is reconstructed from the constellation; the
// attestation-server bearer for that comes from
// POST /api/v1/enclave/boot-attestation-token, authenticated by a fresh
// quote alone (the per-enclave credential is still locked inside /data).
//
// The redeemed payload is stashed under /run/enclave (tmpfs) by the LUKS
// boot path and persisted onto /data by the manager-bootstrap main run once
// data.mount is up (Run() prefers the stash over legacy registration).

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/Privasys/enclave-os-virtual/internal/tdx"
)

// redeemBindingLabel must match the management service
// (preapproval.go redeemBindingLabel).
const redeemBindingLabel = "privasys-enclave-redeem-v1"

// bootBindingLabel must match the management service
// (preapproval.go bootBindingLabel).
const bootBindingLabel = "privasys-enclave-boot-v1"

// RedeemStashPath is where the LUKS boot path parks the redeemed payload
// (tmpfs — gone on reboot) for the post-mount persist run.
const RedeemStashPath = "/run/enclave/redeem-payload.json"

// RedeemedDataKey is the vault bundle for the manager's /data DEK.
type RedeemedDataKey struct {
	Handle            string   `json:"handle"`
	Grant             string   `json:"grant"`
	Endpoints         []string `json:"endpoints"`
	Mrenclave         string   `json:"mrenclave"`
	AttestationServer string   `json:"attestation_server"`
	Threshold         int      `json:"threshold"`
}

// RedeemedEnclave is the payload the management service seals to the redeem
// epk (management-service preapproval.go redeemPayload).
type RedeemedEnclave struct {
	EnclaveID        string            `json:"enclave_id"`
	Credential       string            `json:"enclave_credential"`
	CACert           string            `json:"ca_cert"`
	CAKey            string            `json:"ca_key"`
	ManagerEnv       map[string]string `json:"manager_env"`
	AttestationToken string            `json:"attestation_token"`
	DataKey          *RedeemedDataKey  `json:"data_key"`
}

// BootstrapToken returns the pre-approval token, from the environment
// (BOOTSTRAP_TOKEN — set by luks-setup via the multi-cloud
// provisioning-secret library) or GCE instance metadata. Empty when the VM
// was not provisioned through pre-approval.
func BootstrapToken() string {
	if t := strings.TrimSpace(os.Getenv("BOOTSTRAP_TOKEN")); t != "" {
		return t
	}
	return gceMetadata("instance/attributes/bootstrap-token")
}

// Redeem exchanges the bootstrap token for the sealed enclave payload.
// Retries transient failures; a definitive rejection (bad token, measurement
// mismatch, already redeemed) fails fast — retrying cannot fix those.
func Redeem(ctx context.Context, cfg Config, token string) (*RedeemedEnclave, error) {
	cfg = applyDefaults(cfg)

	mgmtURL := cfg.ManagementURL
	if mgmtURL == "" {
		mgmtURL = gceMetadata("instance/attributes/management-url")
	}
	if mgmtURL == "" {
		return nil, errors.New("redeem: MGMT_URL not set and no management-url instance metadata")
	}
	name := gceMetadata("instance/attributes/machine-name")
	if name == "" {
		name = gceMetadata("instance/name")
	}
	if name == "" {
		if h, err := os.Hostname(); err == nil && h != "localhost" {
			name = h
		}
	}
	if name == "" {
		return nil, errors.New("redeem: cannot determine enclave name (no metadata, hostname unset)")
	}

	epk, esk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("redeem: generate keypair: %w", err)
	}
	binding := sha512.Sum512(append(append([]byte{}, epk[:]...), []byte(redeemBindingLabel)...))
	quote, err := tdx.GetQuote(binding)
	if err != nil {
		return nil, fmt.Errorf("redeem: tdx quote: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"name":            name,
		"bootstrap_token": token,
		"epk":             base64.StdEncoding.EncodeToString(epk[:]),
		"tdx_quote":       base64.StdEncoding.EncodeToString(quote),
	})
	url := strings.TrimRight(mgmtURL, "/") + "/api/v1/enclave/redeem"
	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "manager-bootstrap: redeem attempt failed: %v (retrying)\n", err)
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		// 4xx are definitive verdicts on THIS request (invalid/expired/
		// consumed token, measurement mismatch): the same retry cannot
		// succeed. 5xx and transport errors retry.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, fmt.Errorf("redeem rejected (HTTP %d): %s", resp.StatusCode, truncateStr(string(raw), 300))
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("redeem returned HTTP %d: %s", resp.StatusCode, truncateStr(string(raw), 200))
			fmt.Fprintf(os.Stderr, "manager-bootstrap: %v (retrying)\n", lastErr)
			continue
		}
		var out struct {
			Status string `json:"status"`
			Sealed string `json:"sealed"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || out.Sealed == "" {
			return nil, fmt.Errorf("redeem: bad response: %s", truncateStr(string(raw), 200))
		}
		sealed, err := base64.StdEncoding.DecodeString(out.Sealed)
		if err != nil {
			return nil, fmt.Errorf("redeem: sealed payload is not base64: %w", err)
		}
		plain, ok := box.OpenAnonymous(nil, sealed, epk, esk)
		if !ok {
			return nil, errors.New("redeem: sealed payload does not open with the redeem key")
		}
		var payload RedeemedEnclave
		if err := json.Unmarshal(plain, &payload); err != nil {
			return nil, fmt.Errorf("redeem: sealed payload is not valid JSON: %w", err)
		}
		if payload.CACert == "" || payload.CAKey == "" || payload.Credential == "" {
			return nil, errors.New("redeem: sealed payload is missing ca_cert/ca_key/enclave_credential")
		}
		fmt.Fprintf(os.Stderr, "manager-bootstrap: pre-approval redeemed (enclave_id=%s, data_key=%v)\n",
			payload.EnclaveID, payload.DataKey != nil)
		return &payload, nil
	}
	return nil, fmt.Errorf("redeem: giving up after retries: %w", lastErr)
}

// FetchBootAttestationToken gets the attestation-server bearer for the /data
// unlock, authenticated by a fresh TDX quote bound to the enclave id (the
// per-enclave credential is still locked inside /data at this point).
func FetchBootAttestationToken(ctx context.Context, cfg Config, mgmtURL, enclaveID string) (string, error) {
	cfg = applyDefaults(cfg)
	binding := sha512.Sum512([]byte(bootBindingLabel + enclaveID))
	quote, err := tdx.GetQuote(binding)
	if err != nil {
		return "", fmt.Errorf("boot-token: tdx quote: %w", err)
	}
	body, _ := json.Marshal(map[string]string{
		"enclave_id": enclaveID,
		"tdx_quote":  base64.StdEncoding.EncodeToString(quote),
	})
	url := strings.TrimRight(mgmtURL, "/") + "/api/v1/enclave/boot-attestation-token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: cfg.HTTPTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("boot-token request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("boot-token: HTTP %d: %s", resp.StatusCode, truncateStr(strings.TrimSpace(string(raw)), 200))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return "", errors.New("boot-token: bad response")
	}
	return out.Token, nil
}

// StashRedeemed parks the payload on tmpfs for the post-mount persist run.
func StashRedeemed(p *RedeemedEnclave) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(RedeemStashPath), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(RedeemStashPath, raw, 0o600)
}

// loadStashedRedeem returns the parked payload, or nil when none exists.
func loadStashedRedeem() (*RedeemedEnclave, error) {
	raw, err := os.ReadFile(RedeemStashPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p RedeemedEnclave
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("stashed redeem payload unreadable: %w", err)
	}
	return &p, nil
}

// persistRedeemed writes the redeemed CA bundle and manager env onto /data
// (mirror of persistRegistration for the pre-approval flow; the manager env
// from the platform already carries ENCLAVE_ID/ENCLAVE_TOKEN/MGMT_URL).
func persistRedeemed(cfg Config, p *RedeemedEnclave) error {
	caCertPath := filepath.Join(cfg.DataDir, "ca.crt")
	caKeyPath := filepath.Join(cfg.DataDir, "ca.key")
	if err := writeFileAtomic(caCertPath, []byte(p.CACert), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", caCertPath, err)
	}
	if err := writeFileAtomic(caKeyPath, []byte(p.CAKey), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", caKeyPath, err)
	}
	env := map[string]string{
		"ENCLAVE_ID":    p.EnclaveID,
		"ENCLAVE_TOKEN": p.Credential,
	}
	for k, v := range p.ManagerEnv {
		env[k] = v
	}
	if err := mergeManagerEnv(cfg.ManagerEnvPath, env); err != nil {
		return fmt.Errorf("merge %s: %w", cfg.ManagerEnvPath, err)
	}
	// One-shot: never persist the credential twice, and never leave it on
	// tmpfs longer than needed.
	_ = os.Remove(RedeemStashPath)
	fmt.Fprintf(os.Stderr, "manager-bootstrap: redeemed registration persisted, wrote %s + %s (enclave_id=%s)\n",
		caCertPath, caKeyPath, p.EnclaveID)
	return nil
}
