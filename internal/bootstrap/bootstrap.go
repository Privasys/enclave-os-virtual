// Package bootstrap implements the first-boot manager-bootstrap binary.
//
// Every new enclave enrolls through self-registration (registration.go):
// it binds an ephemeral key into a TDX quote, registers with the
// management service, and blocks until a platform admin approves the
// machine. Approval delivers the CA bundle (ca.crt + ca.key) and a
// per-enclave credential, written onto the LUKS-encrypted /data
// partition. There is no other way to obtain a CA: admin approval is
// mandatory for every new VM.
//
// (The legacy Phase-B flow — an IdP service-account key delivered out
// of band redeemed at /api/v1/enclave/bootstrap — was removed
// 2026-06-11; see .operations/platform/enclave-registration-plan.md.)
//
// The flow is idempotent: on subsequent boots the systemd unit's
// ConditionPathExists=!/data/ca.crt skips re-execution. If the unit
// runs anyway, Run() short-circuits when ca.crt is already present.
package bootstrap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config controls a single bootstrap run. Zero values fall back to
// the production defaults.
type Config struct {
	// DataDir is the LUKS-mounted /data partition.
	DataDir string
	// ManagerEnvPath is the systemd EnvironmentFile the registration
	// flow writes (ENCLAVE_ID, ENCLAVE_TOKEN, MGMT_URL, ...). The
	// startup script may add operator overrides later; existing keys
	// are never overwritten.
	ManagerEnvPath string
	// ManagementURL is the management-service base URL
	// (e.g. https://api.developer.privasys.org). When empty, the
	// registration flow falls back to the `management-url` GCE
	// instance metadata attribute.
	ManagementURL string
	// HTTPTimeout caps each outbound HTTP call. Default 30s.
	HTTPTimeout time.Duration
}

// Run executes a single bootstrap attempt. Safe to invoke as a
// systemd Type=oneshot ExecStart.
func Run(ctx context.Context, cfg Config) error {
	cfg = applyDefaults(cfg)

	caCertPath := filepath.Join(cfg.DataDir, "ca.crt")
	if _, err := os.Stat(caCertPath); err == nil {
		fmt.Fprintf(os.Stderr, "manager-bootstrap: %s already present, nothing to do\n", caCertPath)
		return nil
	}

	return RunRegistration(ctx, cfg)
}

func applyDefaults(c Config) Config {
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	if c.ManagerEnvPath == "" {
		c.ManagerEnvPath = "/data/manager.env"
	}
	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = 30 * time.Second
	}
	return c
}

// readOptionalLine returns the first trimmed line of path, or "".
func readOptionalLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
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

// mergeManagerEnv overlays keys onto the existing systemd
// EnvironmentFile, preserving any operator overrides (existing keys
// win) and only appending keys that are missing.
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
