// Package tpm provides application-level measurement operations for TDX
// runtime attestation.
//
// RTMR[3] is currently unused (left as zeros). Container workloads are
// identified via OID extensions in the RA-TLS certificate, not via
// runtime measurements.
package tpm

import (
	"go.uber.org/zap"
)

// Event represents a single application measurement event.
// Currently unused — kept for API compatibility.
type Event struct {
	Timestamp    string `json:"timestamp"`
	PCR          int    `json:"pcr"`
	DigestSHA384 string `json:"digest_sha384"`
	DigestSHA256 string `json:"digest_sha256"`
	Type         string `json:"type"`
	Description  string `json:"description"`
}

// Extender is a no-op placeholder. RTMR[3] is currently unused;
// container identity is conveyed via OID extensions.
type Extender struct {
	log *zap.Logger
}

// NewExtender creates a new (no-op) Extender.
func NewExtender(log *zap.Logger) *Extender {
	return &Extender{log: log.Named("tpm")}
}

// Events returns the application event log (always empty — RTMR[3] unused).
func (e *Extender) Events() []Event {
	return nil
}
