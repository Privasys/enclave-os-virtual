package ratls

import (
	"crypto/x509/pkix"
	"fmt"

	"go.uber.org/zap"
)

// Attester abstracts hardware-specific confidential computing attestation.
// Implementations produce attestation evidence (quotes/reports) for a given
// 64-byte ReportData value.
//
// To add a new backend, implement this interface and register a factory via
// RegisterAttester in an init() function — typically in a file named
// attester_<backend>.go.
type Attester interface {
	// Name returns the short identifier for this attester (e.g. "tdx",
	// "sev-snp"). Used in log messages and issuer keys.
	Name() string

	// Provision initialises the attester, validating hardware availability
	// and setting up any providers. Called once during Caddy provisioning.
	Provision(logger *zap.Logger) error

	// Quote generates raw attestation evidence for the given 64-byte
	// report data.
	Quote(reportData [64]byte) ([]byte, error)

	// CertExtension returns the X.509 extension (OID + value) used to
	// embed the attestation evidence in an RA-TLS certificate. The raw
	// quote bytes are passed in as the extension value.
	CertExtension(quote []byte) pkix.Extension
}

// ---------------------------------------------------------------------------
// Attester registry
// ---------------------------------------------------------------------------

// attesterRegistry maps backend names to factory functions that create a
// new, zero-value Attester ready for provisioning.
var attesterRegistry = map[string]func() Attester{}

// RegisterAttester registers an Attester factory under the given name.
// Call this from an init() function in the backend's source file.
func RegisterAttester(name string, factory func() Attester) {
	if _, exists := attesterRegistry[name]; exists {
		panic(fmt.Sprintf("ra_tls: duplicate attester registration for %q", name))
	}
	attesterRegistry[name] = factory
}

// newAttester creates a fresh Attester for the given backend name, or
// returns an error listing the available backends.
func newAttester(name string) (Attester, error) {
	factory, ok := attesterRegistry[name]
	if !ok {
		available := make([]string, 0, len(attesterRegistry))
		for k := range attesterRegistry {
			available = append(available, k)
		}
		return nil, fmt.Errorf("ra_tls: unknown backend %q (available: %v)", name, available)
	}
	return factory(), nil
}
