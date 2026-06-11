// manager-bootstrap is a Type=oneshot helper that runs before manager.service
// on first boot. It fetches an access token from the Privasys IdP using a
// JWT-bearer assertion built from a service-account key delivered via
// systemd-creds (or cloud metadata), then asks the management service for
// the CA bundle and writes it to /data/ca.crt + /data/ca.key.
//
// All configuration comes from the systemd EnvironmentFile=/data/manager.env
// the startup script wrote, plus the systemd credential
// `bootstrap-service-key` exposed via $CREDENTIALS_DIRECTORY.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/bootstrap"
)

func main() {
	cfg := bootstrap.Config{
		DataDir:             os.Getenv("BOOTSTRAP_DATA_DIR"),
		ManagerEnvPath:      os.Getenv("BOOTSTRAP_MANAGER_ENV"),
		ServiceKeyPath:      os.Getenv("BOOTSTRAP_SERVICE_KEY"),
		DekOriginPath:       os.Getenv("BOOTSTRAP_DEK_ORIGIN"),
		IDPIssuer:           os.Getenv("OIDC_ISSUER"),
		IDPAudience:         os.Getenv("OIDC_AUDIENCE"),
		ManagementURL:       os.Getenv("MGMT_URL"),
		AttestationRequired: os.Getenv("BOOTSTRAP_ATTESTATION_REQUIRED") == "true",
	}
	if v := os.Getenv("BOOTSTRAP_HTTP_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.HTTPTimeout = time.Duration(n) * time.Second
		}
	}
	// -measurements: post a fresh TDX quote to the management service
	// for the measurement audit log (enclave-measurements.service, runs
	// on boots where the enclave is already registered). Always exits 0:
	// the audit trail must never break a boot, and legacy enclaves
	// without a per-enclave credential simply skip it.
	if len(os.Args) > 1 && os.Args[1] == "-measurements" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := bootstrap.ReportMeasurements(ctx, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "manager-bootstrap: measurements not reported: %v\n", err)
		}
		return
	}

	// MGMT_URL may be absent on first boot before manager.env exists;
	// the self-registration path resolves it from instance metadata.
	// No overall deadline: the registration flow legitimately blocks
	// until an admin approves (per-request timeouts still apply).
	if err := bootstrap.Run(context.Background(), cfg); err != nil {
		fmt.Fprintf(os.Stderr, "manager-bootstrap: %v\n", err)
		os.Exit(1)
	}
}
