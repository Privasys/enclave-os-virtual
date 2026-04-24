// Package runtimestatus pushes the manager's view of fast-changing
// runtime state (GPU utilisation, loaded model, vLLM proxy progress)
// to the management-service via POST /api/v1/enclave/runtime-status.
//
// The receiver is the FleetHandlers.PushRuntimeStatus handler in the
// management-service, gated by a static EnclaveToken bearer (the same
// token used for /api/v1/enclave/checkin). The sender is best-effort:
// network or upstream failures are logged and the loop continues.
//
// Two source feeds are merged into one EnclaveRuntimeStatus payload:
//
//   - GPU samples from `nvidia-smi --query-gpu=...`
//   - Proxy state from GET <proxy>/v1/models/status (the
//     confidential-ai model manager state machine).
//
// Either feed may be missing; absent fields are sent as JSON null
// (encoded as omitempty pointers in the receiver struct).
package runtimestatus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Config configures the runtime-status sender.
type Config struct {
	// MgmtBaseURL is the management-service base URL, without trailing
	// slash (e.g. "https://api.developer.privasys.org").
	MgmtBaseURL string

	// EnclaveToken is the static bearer credential expected by
	// /api/v1/enclave/runtime-status.
	EnclaveToken string

	// EnclaveID is the UUID assigned to this enclave by the
	// management-service (returned from the prior /checkin call, or
	// configured at boot).
	EnclaveID string

	// ProxyBaseURL is the local confidential-ai proxy base URL
	// (typically "http://localhost:8080"). Empty disables the proxy
	// feed; only GPU samples will be sent.
	ProxyBaseURL string

	// Interval is the wall-clock interval between samples. Defaults
	// to 30s when zero.
	Interval time.Duration
}

// Sender periodically pushes EnclaveRuntimeStatus deltas to the
// management-service.
type Sender struct {
	cfg    Config
	log    *zap.Logger
	client *http.Client
}

// New constructs a Sender. Returns nil when MgmtBaseURL or EnclaveID
// are unset (disabled mode).
func New(cfg Config, log *zap.Logger) *Sender {
	if cfg.MgmtBaseURL == "" || cfg.EnclaveID == "" {
		return nil
	}
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	return &Sender{
		cfg: cfg,
		log: log.Named("runtime-status"),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Run pushes one snapshot immediately, then a snapshot per Interval
// until ctx is cancelled. Errors are logged and the loop continues.
func (s *Sender) Run(ctx context.Context) error {
	s.log.Info("runtime-status sender starting",
		zap.String("mgmt_url", s.cfg.MgmtBaseURL),
		zap.String("enclave_id", s.cfg.EnclaveID),
		zap.Duration("interval", s.cfg.Interval),
	)

	s.pushOnce(ctx)

	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("runtime-status sender stopping")
			return nil
		case <-t.C:
			s.pushOnce(ctx)
		}
	}
}

// pushOnce gathers a snapshot and POSTs it. Any error is logged.
func (s *Sender) pushOnce(ctx context.Context) {
	payload := s.snapshot(ctx)
	body, err := json.Marshal(payload)
	if err != nil {
		s.log.Warn("failed to marshal runtime-status payload", zap.Error(err))
		return
	}
	url := strings.TrimRight(s.cfg.MgmtBaseURL, "/") + "/api/v1/enclave/runtime-status"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		s.log.Warn("failed to build runtime-status request", zap.Error(err))
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.EnclaveToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("runtime-status push failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		s.log.Warn("runtime-status push rejected",
			zap.Int("status", resp.StatusCode),
		)
	}
}

// runtimeStatus mirrors management-service.EnclaveRuntimeStatus.
// Kept as a local type to avoid a cross-repo go module dependency.
// Fields are pointers so omitempty drops absent measurements.
type runtimeStatus struct {
	EnclaveID         string    `json:"enclave_id"`
	GPUUsedVRAMMiB    *int64    `json:"gpu_used_vram_mib,omitempty"`
	GPUTemperatureC   *int      `json:"gpu_temperature_c,omitempty"`
	GPUPowerW         *int      `json:"gpu_power_w,omitempty"`
	LoadedModel       *string   `json:"loaded_model,omitempty"`
	LoadedModelDigest *string   `json:"loaded_model_digest,omitempty"`
	ProxyStatus       *string   `json:"proxy_status,omitempty"`
	ProxyProgress     *float64  `json:"proxy_progress,omitempty"`
	ProxyMessage      *string   `json:"proxy_message,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// snapshot collects current GPU + proxy state into one payload.
func (s *Sender) snapshot(ctx context.Context) runtimeStatus {
	out := runtimeStatus{
		EnclaveID: s.cfg.EnclaveID,
		UpdatedAt: time.Now().UTC(),
	}
	if vram, temp, power, ok := sampleGPU(ctx); ok {
		v := vram
		t := temp
		p := power
		out.GPUUsedVRAMMiB = &v
		out.GPUTemperatureC = &t
		out.GPUPowerW = &p
	}
	if s.cfg.ProxyBaseURL != "" {
		if ps, ok := s.sampleProxy(ctx); ok {
			out.LoadedModel = ps.Model
			out.LoadedModelDigest = ps.ModelDigest
			out.ProxyStatus = ps.State
			out.ProxyProgress = ps.Progress
			out.ProxyMessage = ps.Message
		}
	}
	return out
}

// sampleGPU runs `nvidia-smi --query-gpu=memory.used,temperature.gpu,power.draw
// --format=csv,noheader,nounits` and parses the first line. Returns ok=false
// if nvidia-smi is missing or the output is unparseable.
func sampleGPU(ctx context.Context) (vram int64, temp int, power int, ok bool) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "nvidia-smi",
		"--query-gpu=memory.used,temperature.gpu,power.draw",
		"--format=csv,noheader,nounits")
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, 0, false
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return 0, 0, 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil {
		return 0, 0, 0, false
	}
	t, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, 0, false
	}
	// power.draw is a float ("87.42"); round to nearest int W.
	pf, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	if err != nil {
		return 0, 0, 0, false
	}
	return v, t, int(pf + 0.5), true
}

// proxyStatus is the subset of the confidential-ai /v1/models/status
// response the sender forwards.
type proxyStatus struct {
	State       *string  `json:"state,omitempty"`
	Model       *string  `json:"model,omitempty"`
	ModelDigest *string  `json:"model_digest,omitempty"`
	Progress    *float64 `json:"progress,omitempty"`
	Message     *string  `json:"message,omitempty"`
}

// sampleProxy fetches the local confidential-ai model state. Failures
// (proxy down, no model loaded yet) yield ok=false; the manager keeps
// pushing GPU-only deltas until the proxy comes back.
func (s *Sender) sampleProxy(ctx context.Context) (proxyStatus, bool) {
	url := strings.TrimRight(s.cfg.ProxyBaseURL, "/") + "/v1/models/status"
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return proxyStatus{}, false
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return proxyStatus{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return proxyStatus{}, false
	}
	// Decode permissively; the proxy adds fields over time and the
	// sender only forwards the subset above.
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return proxyStatus{}, false
	}
	out := proxyStatus{}
	if v, ok := raw["state"].(string); ok && v != "" {
		out.State = &v
	}
	if v, ok := raw["model"].(string); ok && v != "" {
		out.Model = &v
	}
	if v, ok := raw["model_digest"].(string); ok && v != "" {
		out.ModelDigest = &v
	}
	if v, ok := raw["progress"].(float64); ok {
		out.Progress = &v
	}
	if v, ok := raw["message"].(string); ok && v != "" {
		out.Message = &v
	}
	return out, true
}

// guard against an unused import lint when fmt isn't reached in some builds.
var _ = fmt.Sprintf
