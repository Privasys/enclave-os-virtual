package bootstrap

// Self-registration flow (Option B): when neither /data/ca.crt nor a
// bootstrap service key is available, the enclave enrolls itself with
// the management service and waits for an admin decision.
//
//  1. Generate an ephemeral X25519 keypair; bind its public key into a
//     TDX quote: ReportData = SHA-512(epk || registration label).
//  2. POST /api/v1/enclave/register {name, gateway_host, callback_port,
//     image_profile, epk, tdx_quote}. Only quote-verified requests
//     create pending rows server-side.
//  3. Serve a plain-HTTP listener (default :443 — free, caddy is not
//     running yet) for POST /registration-result. The management
//     service pushes {status, callback_token, sealed} on approval;
//     `sealed` is a NaCl anonymous box to the epk containing the CA
//     bundle and the per-enclave credential.
//  4. Re-register every 30 minutes (same keypair) in case of missed
//     callbacks or Spot IP drift. Active rows are not re-registrable:
//     a missed callback after approval is recovered by the admin
//     reset-registration endpoint.
//
// Design: .operations/platform/enclave-registration-plan.md

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
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

// registrationBindingLabel must match the management service
// (registration.go registrationBindingLabel).
const registrationBindingLabel = "privasys-enclave-registration-v1"

// reRegisterInterval is how often a pending enclave refreshes its
// registration. Kept short: each re-register re-syncs the callback
// token to BOTH the row and this process's listener, so an admin
// approving (or re-approving after a reset-registration) within a few
// minutes always reaches a listener holding the matching token — even
// if manager-bootstrap restarted and lost its in-memory token. The
// cost is one quote verification per interval while pending only; the
// loop exits the moment the result callback arrives.
const reRegisterInterval = 60 * time.Second

type registerRequest struct {
	Name         string `json:"name"`
	GatewayHost  string `json:"gateway_host"`
	CallbackPort int    `json:"callback_port"`
	ImageProfile string `json:"image_profile"`
	EPK          string `json:"epk"`
	TDXQuote     string `json:"tdx_quote"`
}

type registerResponse struct {
	Status         string `json:"status"`
	RegistrationID string `json:"registration_id"`
	CallbackToken  string `json:"callback_token"`
	Reason         string `json:"reason"`
}

type registrationResult struct {
	Status        string `json:"status"`
	CallbackToken string `json:"callback_token"`
	Reason        string `json:"reason"`
	Sealed        string `json:"sealed"`
}

type sealedRegistrationPayload struct {
	EnclaveID  string            `json:"enclave_id"`
	Credential string            `json:"enclave_credential"`
	CACert     string            `json:"ca_cert"`
	CAKey      string            `json:"ca_key"`
	ManagerEnv map[string]string `json:"manager_env"`
}

// RunRegistration enrolls this enclave and blocks until an admin
// approves (writes CA + manager.env, returns nil) or rejects (returns
// an error). ctx cancellation aborts the wait.
func RunRegistration(ctx context.Context, cfg Config) error {
	cfg = applyDefaults(cfg)

	mgmtURL := cfg.ManagementURL
	if mgmtURL == "" {
		mgmtURL = gceMetadata("instance/attributes/management-url")
	}
	if mgmtURL == "" {
		return errors.New("registration: MGMT_URL not set and no management-url instance metadata")
	}
	// The OS hostname is still "localhost" this early in first boot
	// (the startup script sets it later), so prefer instance metadata:
	// machine-name (our canonical enclave name) or the instance name.
	name := gceMetadata("instance/attributes/machine-name")
	if name == "" {
		name = gceMetadata("instance/name")
	}
	if name == "" {
		h, err := os.Hostname()
		if err != nil || h == "localhost" {
			return errors.New("registration: cannot determine enclave name (no metadata, hostname unset)")
		}
		name = h
	}
	gateway := gceMetadata("instance/network-interfaces/0/access-configs/0/external-ip")
	if gateway == "" {
		gateway = os.Getenv("REGISTRATION_GATEWAY_HOST")
	}
	if gateway == "" {
		return errors.New("registration: cannot determine public IP (no GCE metadata, REGISTRATION_GATEWAY_HOST unset)")
	}
	listenAddr := os.Getenv("REGISTRATION_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":443"
	}
	callbackPort := 443
	if _, p, err := splitHostPort(listenAddr); err == nil && p != 0 {
		callbackPort = p
	}
	imageProfile := readOptionalLine("/etc/privasys/image-profile")

	// One keypair for the whole wait: re-registration refreshes the
	// server-side epk to the same value, so an approval sealed at any
	// point stays decryptable.
	epk, esk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("registration: generate keypair: %w", err)
	}
	binding := sha512.Sum512(append(append([]byte{}, epk[:]...), []byte(registrationBindingLabel)...))
	quote, err := tdx.GetQuote(binding)
	if err != nil {
		return fmt.Errorf("registration: tdx quote: %w", err)
	}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	resultCh := make(chan registrationResult, 1)
	tokenCh := make(chan string, 1) // latest callback token for the listener

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: registrationListener(tokenCh, resultCh),
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "manager-bootstrap: registration listener: %v\n", err)
		}
	}()
	defer srv.Close()

	register := func() (*registerResponse, error) {
		body, _ := json.Marshal(registerRequest{
			Name:         name,
			GatewayHost:  gateway,
			CallbackPort: callbackPort,
			ImageProfile: imageProfile,
			EPK:          base64.StdEncoding.EncodeToString(epk[:]),
			TDXQuote:     base64.StdEncoding.EncodeToString(quote),
		})
		req, err := http.NewRequestWithContext(ctx, "POST",
			strings.TrimRight(mgmtURL, "/")+"/api/v1/enclave/register",
			strings.NewReader(string(body)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var out registerResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("register returned HTTP %d: %s", resp.StatusCode, truncateStr(string(raw), 200))
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("register returned HTTP %d: %s", resp.StatusCode, truncateStr(string(raw), 200))
		}
		return &out, nil
	}

	fmt.Fprintf(os.Stderr, "manager-bootstrap: registering %s (gateway=%s, profile=%s) with %s\n",
		name, gateway, imageProfile, mgmtURL)

	ticker := time.NewTicker(reRegisterInterval)
	defer ticker.Stop()
	for {
		resp, err := register()
		switch {
		case err != nil:
			// Transient (mgmt unreachable, attestation server down):
			// retry on the ticker. Boot keeps waiting — there is nothing
			// useful an unregistered enclave can do.
			fmt.Fprintf(os.Stderr, "manager-bootstrap: register attempt failed: %v (retrying in %s)\n", err, reRegisterInterval)
		case resp.Status == "rejected":
			return fmt.Errorf("registration rejected: %s", resp.Reason)
		case resp.Status == "pending":
			fmt.Fprintf(os.Stderr, "manager-bootstrap: pending approval (id=%s), waiting for callback on %s\n",
				resp.RegistrationID, listenAddr)
			// Make the latest token available to the listener.
			select {
			case <-tokenCh:
			default:
			}
			tokenCh <- resp.CallbackToken
		default:
			fmt.Fprintf(os.Stderr, "manager-bootstrap: unexpected register status %q\n", resp.Status)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-resultCh:
			if result.Status == "rejected" {
				return fmt.Errorf("registration rejected: %s", result.Reason)
			}
			payload, err := openSealedPayload(result.Sealed, epk, esk)
			if err != nil {
				fmt.Fprintf(os.Stderr, "manager-bootstrap: bad approval payload: %v (continuing to wait)\n", err)
				continue
			}
			return persistRegistration(cfg, payload)
		case <-ticker.C:
			// re-register
		}
	}
}

// registrationListener accepts the management service's result push.
// Token comparison is against the most recent register response.
func registrationListener(tokenCh chan string, resultCh chan registrationResult) http.Handler {
	var currentToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/registration-result", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		select {
		case t := <-tokenCh:
			currentToken = t
		default:
		}
		var res registrationResult
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&res); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if currentToken == "" ||
			subtle.ConstantTimeCompare([]byte(res.CallbackToken), []byte(currentToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		select {
		case resultCh <- res:
		default:
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return mux
}

func openSealedPayload(sealedB64 string, epk, esk *[32]byte) (*sealedRegistrationPayload, error) {
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return nil, fmt.Errorf("sealed payload is not base64: %w", err)
	}
	plain, ok := box.OpenAnonymous(nil, sealed, epk, esk)
	if !ok {
		return nil, errors.New("sealed payload does not open with the registration key")
	}
	var payload sealedRegistrationPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("sealed payload is not valid JSON: %w", err)
	}
	if payload.CACert == "" || payload.CAKey == "" || payload.Credential == "" {
		return nil, errors.New("sealed payload is missing ca_cert/ca_key/enclave_credential")
	}
	return &payload, nil
}

func persistRegistration(cfg Config, payload *sealedRegistrationPayload) error {
	caCertPath := filepath.Join(cfg.DataDir, "ca.crt")
	caKeyPath := filepath.Join(cfg.DataDir, "ca.key")
	if err := writeFileAtomic(caCertPath, []byte(payload.CACert), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", caCertPath, err)
	}
	if err := writeFileAtomic(caKeyPath, []byte(payload.CAKey), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", caKeyPath, err)
	}
	env := map[string]string{
		"ENCLAVE_ID":    payload.EnclaveID,
		"ENCLAVE_TOKEN": payload.Credential,
	}
	for k, v := range payload.ManagerEnv {
		env[k] = v
	}
	if err := mergeManagerEnv(cfg.ManagerEnvPath, env); err != nil {
		return fmt.Errorf("merge %s: %w", cfg.ManagerEnvPath, err)
	}
	fmt.Fprintf(os.Stderr, "manager-bootstrap: registration approved, wrote %s + %s (enclave_id=%s)\n",
		caCertPath, caKeyPath, payload.EnclaveID)
	return nil
}

// ReportMeasurements posts a fresh TDX quote to the management service
// for the measurement audit log (pragmatic re-approval: image upgrades
// are auto-accepted server-side, every change is recorded). Requires
// ENCLAVE_ID + ENCLAVE_TOKEN in manager.env. Best-effort: callers
// should never fail the boot on errors here.
func ReportMeasurements(ctx context.Context, cfg Config) error {
	cfg = applyDefaults(cfg)
	env, err := readEnvFile(cfg.ManagerEnvPath)
	if err != nil {
		return err
	}
	enclaveID, token := env["ENCLAVE_ID"], env["ENCLAVE_TOKEN"]
	mgmtURL := cfg.ManagementURL
	if mgmtURL == "" {
		mgmtURL = env["MGMT_URL"]
	}
	if enclaveID == "" || token == "" || mgmtURL == "" {
		return errors.New("measurements: ENCLAVE_ID/ENCLAVE_TOKEN/MGMT_URL not configured (legacy enclave?)")
	}

	binding := sha512.Sum512([]byte("privasys-enclave-measurements-v1" + enclaveID))
	quote, err := tdx.GetQuote(binding)
	if err != nil {
		return fmt.Errorf("measurements: tdx quote: %w", err)
	}
	body, _ := json.Marshal(map[string]string{
		"enclave_id": enclaveID,
		"tdx_quote":  base64.StdEncoding.EncodeToString(quote),
	})
	req, err := http.NewRequestWithContext(ctx, "POST",
		strings.TrimRight(mgmtURL, "/")+"/api/v1/enclave/measurements",
		strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: cfg.HTTPTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("measurements returned HTTP %d: %s", resp.StatusCode, truncateStr(string(raw), 200))
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

// gceMetadata fetches a GCE metadata path; empty string off-GCE.
func gceMetadata(path string) string {
	req, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/"+path, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return strings.TrimSpace(string(b))
}

func splitHostPort(addr string) (string, int, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, 0, errors.New("no port")
	}
	var p int
	if _, err := fmt.Sscanf(addr[i+1:], "%d", &p); err != nil {
		return addr[:i], 0, err
	}
	return addr[:i], p, nil
}

// readEnvFile parses KEY=VALUE lines (comments and blanks ignored).
func readEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out, nil
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
