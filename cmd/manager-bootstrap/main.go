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
	if cfg.ManagementURL == "" {
		fmt.Fprintln(os.Stderr, "manager-bootstrap: MGMT_URL is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := bootstrap.Run(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "manager-bootstrap: %v\n", err)
		os.Exit(1)
	}
}
