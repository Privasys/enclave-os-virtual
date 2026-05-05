// Package tdx provides a minimal helper to obtain a TDX attestation
// quote via the kernel's configfs-tsm interface (Linux ≥ 6.7).
//
// We avoid pulling in google/go-tdx-guest because the bootstrap binary
// only needs the raw quote bytes (the management-service forwards them
// to the attestation server unchanged). Implementing the configfs
// dance directly keeps the dependency surface small and lets us run
// the bootstrap binary on bare-metal QEMU/OVH without modifying the
// caddy module's go.mod.
package tdx

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultConfigFSRoot is the path systemd auto-mounts at boot when
// configfs is enabled in the kernel.
const DefaultConfigFSRoot = "/sys/kernel/config/tsm/report"

// GetQuote requests a TDX quote bound to the given 64-byte report-data
// (the REPORTDATA field embedded in the quote, which the verifier uses
// to bind the quote to a freshness nonce / TLS challenge).
//
// On a non-TDX guest (or when configfs-tsm is unavailable), GetQuote
// returns ErrNotTDX. Callers should treat that as a soft failure when
// the per-enclave attestation gate is off.
func GetQuote(reportData [64]byte) ([]byte, error) {
	return getQuoteAt(DefaultConfigFSRoot, reportData)
}

// ErrNotTDX is returned when the kernel does not expose a TDX TSM
// report device.
var ErrNotTDX = errors.New("tdx: configfs-tsm report interface not present")

func getQuoteAt(root string, reportData [64]byte) ([]byte, error) {
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotTDX
		}
		return nil, fmt.Errorf("stat %s: %w", root, err)
	}
	// Each request needs a unique sub-directory so concurrent callers
	// don't clobber each other.
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	dir := filepath.Join(root, fmt.Sprintf("manager-bootstrap-%x", suffix))
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	defer os.Remove(dir)

	// Write the 64-byte REPORTDATA. configfs-tsm pads with zeros if
	// the input is shorter, so we always write the full 64 bytes.
	if err := os.WriteFile(filepath.Join(dir, "inblob"), reportData[:], 0o600); err != nil {
		return nil, fmt.Errorf("write inblob: %w", err)
	}
	quote, err := os.ReadFile(filepath.Join(dir, "outblob"))
	if err != nil {
		return nil, fmt.Errorf("read outblob: %w", err)
	}
	return quote, nil
}
