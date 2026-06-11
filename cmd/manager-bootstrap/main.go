// manager-bootstrap is a Type=oneshot helper that runs before manager.service
// on first boot. It enrolls the enclave with the management service via
// self-registration (TDX quote bound to an ephemeral key) and blocks until
// a platform admin approves the machine; approval delivers the CA bundle
// and a per-enclave credential, written to /data. Admin approval is the
// only way a new VM obtains a CA.
//
// With -measurements it instead posts a fresh TDX quote for the
// measurement audit log and always exits 0.
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
		DataDir:        os.Getenv("BOOTSTRAP_DATA_DIR"),
		ManagerEnvPath: os.Getenv("BOOTSTRAP_MANAGER_ENV"),
		ManagementURL:  os.Getenv("MGMT_URL"),
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
