package ratls

import (
	"fmt"

	"go.uber.org/zap"
)

// Attester abstracts hardware-specific confidential computing attestation.
// Implementations produce attestation evidence (quotes/reports) for a given
// 64-byte ReportData value.
//
// To add a new backend, implement this interface and register a factory via
// RegisterAttester in an init() function (attester_<backend>.go).
type Attester interface {
	// Name returns the evidence family this attester produces ("tdx"), as it
	// appears in the attest response's "tee" field.
	Name() string

	// Provision initialises the attester, validating hardware availability
	// and setting up any providers. Called once during Caddy provisioning.
	Provision(logger *zap.Logger) error

	// Quote generates raw attestation evidence for the given 64-byte
	// report data.
	Quote(reportData [64]byte) ([]byte, error)
}

// attesterRegistry maps backend names to factory functions.
var attesterRegistry = map[string]func() Attester{}

// RegisterAttester registers an Attester factory under the given name.
func RegisterAttester(name string, factory func() Attester) {
	if _, exists := attesterRegistry[name]; exists {
		panic(fmt.Sprintf("ra_tls: duplicate attester registration for %q", name))
	}
	attesterRegistry[name] = factory
}

// newAttester creates a fresh Attester for the given backend name.
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
