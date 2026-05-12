// Package toolspec polls the management-service for the resolved
// MCP_SERVERS env-string for this enclave's fleet, and applies it to
// the local AI inference container in-place.
//
// Endpoint: GET <mgmt-url>/api/v1/enclave/tool-spec?enclave_id=<uuid>
// Auth:     Bearer <ENCLAVE_TOKEN> (same static token as runtime-status)
// Response: {"spec": "...", "generation": "<hex>"}
//
// On generation change the syncer:
//
//  1. Writes the spec to /data/manager-overrides/confidential-ai.env so
//     a crash + boot-time replay still picks up the latest tools.
//  2. Calls Server.ReloadAppEnv(name, "MCP_SERVERS", spec) to mutate
//     the registry entry and restart the container in-place.
//
// The package has no compile-time dependency on the management-service
// repo: the response shape is duplicated here.
package toolspec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// EnvReloader is the subset of *manager.Server the syncer needs.
// Defined as an interface so the syncer can be tested in isolation.
type EnvReloader interface {
	ReloadAppEnv(ctx context.Context, name, key, value string) (bool, error)
}

// Config configures the syncer.
type Config struct {
	// MgmtBaseURL is the management-service base URL (no trailing slash).
	MgmtBaseURL string

	// EnclaveToken is the static bearer credential.
	EnclaveToken string

	// EnclaveID is this enclave's UUID.
	EnclaveID string

	// AppName is the registered container name to mutate
	// (default: "confidential-ai").
	AppName string

	// OverridesDir is where the env override file is written
	// (default: "/data/manager-overrides").
	OverridesDir string

	// Interval between polls. Defaults to 60s when zero.
	Interval time.Duration
}

// Syncer polls the tool-spec endpoint and reloads the AI container.
type Syncer struct {
	cfg     Config
	log     *zap.Logger
	client  *http.Client
	reload  EnvReloader
	lastGen string
}

// New constructs a Syncer. Returns nil when MgmtBaseURL or EnclaveID
// are unset (disabled mode), matching the runtime-status sender.
func New(cfg Config, log *zap.Logger, reload EnvReloader) *Syncer {
	if cfg.MgmtBaseURL == "" || cfg.EnclaveID == "" {
		return nil
	}
	if cfg.AppName == "" {
		cfg.AppName = "confidential-ai"
	}
	if cfg.OverridesDir == "" {
		cfg.OverridesDir = "/data/manager-overrides"
	}
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	return &Syncer{
		cfg:    cfg,
		log:    log.Named("tool-spec"),
		reload: reload,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Run polls until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) error {
	s.log.Info("tool-spec syncer starting",
		zap.String("mgmt_url", s.cfg.MgmtBaseURL),
		zap.String("enclave_id", s.cfg.EnclaveID),
		zap.String("app_name", s.cfg.AppName),
		zap.Duration("interval", s.cfg.Interval),
	)
	s.tick(ctx)
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.log.Info("tool-spec syncer stopping")
			return nil
		case <-t.C:
			s.tick(ctx)
		}
	}
}

type response struct {
	Spec       string `json:"spec"`
	Generation string `json:"generation"`
}

func (s *Syncer) tick(ctx context.Context) {
	url := fmt.Sprintf("%s/api/v1/enclave/tool-spec?enclave_id=%s",
		strings.TrimRight(s.cfg.MgmtBaseURL, "/"), s.cfg.EnclaveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		s.log.Warn("build request failed", zap.Error(err))
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.EnclaveToken)
	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("tool-spec poll failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		s.log.Warn("tool-spec poll rejected", zap.Int("status", resp.StatusCode))
		return
	}
	var body response
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		s.log.Warn("tool-spec decode failed", zap.Error(err))
		return
	}
	if body.Generation == s.lastGen {
		return
	}
	if err := s.writeOverride(body.Spec); err != nil {
		s.log.Warn("write override failed", zap.Error(err))
		// Do not return: still attempt the in-memory reload. The
		// override file is only needed to survive a crash before the
		// next poll.
	}
	changed, err := s.reload.ReloadAppEnv(ctx, s.cfg.AppName, "MCP_SERVERS", body.Spec)
	if err != nil {
		// Most common cause: the AI container is not yet deployed on
		// this enclave. Log at info, leave lastGen unchanged so we
		// retry on the next tick.
		s.log.Info("env reload skipped",
			zap.String("app", s.cfg.AppName),
			zap.String("generation", body.Generation),
			zap.Error(err))
		return
	}
	s.lastGen = body.Generation
	s.log.Info("tool spec applied",
		zap.String("generation", body.Generation),
		zap.Bool("container_restarted", changed),
		zap.Int("spec_len", len(body.Spec)),
	)
}

// writeOverride writes "MCP_SERVERS=<spec>\n" to the overrides file.
// The file is created with mode 0600 inside a 0700 directory because
// the spec may contain bearer audiences.
func (s *Syncer) writeOverride(spec string) error {
	if err := os.MkdirAll(s.cfg.OverridesDir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", s.cfg.OverridesDir, err)
	}
	path := filepath.Join(s.cfg.OverridesDir, s.cfg.AppName+".env")
	tmp, err := os.CreateTemp(s.cfg.OverridesDir, ".tool-spec.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := fmt.Fprintf(tmp, "MCP_SERVERS=%s\n", spec); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
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
