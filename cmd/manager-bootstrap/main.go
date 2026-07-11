// manager-bootstrap is a Type=oneshot helper that runs before manager.service
// on first boot. It enrolls the enclave with the management service: a
// pre-approved enclave redeems its bootstrap token during the LUKS phase
// (`dek` subcommand, below) and this run persists the stashed payload; a
// legacy enclave self-registers (TDX quote bound to an ephemeral key) and
// blocks until a platform admin approves the machine. Either way the CA
// bundle and per-enclave credential land on /data — enrolment (pre-approval
// or admin approval) is the only way a new VM obtains a CA.
//
// With `dek --device <dev>` (run by luks-setup BEFORE data.mount) it resolves
// the vault-backed /data DEK and prints it (hex) on stdout: reconstruction
// via the LUKS2 header locator on reboots, pre-approval redemption + key
// creation on first boot. Exit 3 means the volume is not vault-managed and
// luks-setup falls back to the BYOK metadata passphrase.
//
// With -measurements it instead posts a fresh TDX quote for the
// measurement audit log and always exits 0.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

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
	// dek --device <dev>: resolve the vault-backed /data DEK for
	// luks-setup (runs BEFORE data.mount — see internal/bootstrap/dek.go).
	// stdout carries ONLY the hex DEK; all logging goes to stderr (the
	// journal, via luks-data.service).
	if len(os.Args) > 1 && os.Args[1] == "dek" {
		device := ""
		for i := 2; i < len(os.Args)-1; i++ {
			if os.Args[i] == "--device" {
				device = os.Args[i+1]
			}
		}
		if device == "" {
			fmt.Fprintln(os.Stderr, "manager-bootstrap: usage: manager-bootstrap dek --device <block-device>")
			os.Exit(1)
		}
		log, err := zap.NewDevelopment()
		if err != nil {
			fmt.Fprintf(os.Stderr, "manager-bootstrap: logger: %v\n", err)
			os.Exit(1)
		}
		// Generous overall deadline: first boot chains redeem + key
		// creation on k vaults; reboots retry mgmt/vault transients.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		dek, err := bootstrap.ResolveDataDEK(ctx, log, cfg, device)
		if errors.Is(err, bootstrap.ErrNotVaultManaged) {
			fmt.Fprintln(os.Stderr, "manager-bootstrap: volume is not vault-managed (BYOK fallback)")
			os.Exit(3)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "manager-bootstrap: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(dek)
		return
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
