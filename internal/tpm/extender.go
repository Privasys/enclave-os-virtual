// Package tpm provides vTPM PCR extend operations for application-level
// measurements. In a TDX VM, extending PCR 16 automatically feeds RTMR[3]
// (the application-defined measurement register).
//
// The extend operation is cumulative and irreversible:
//
//	RTMR[3]_new = SHA-384(RTMR[3]_old || digest)
//
// Each container load/unload is recorded as a separate event. Verifiers
// replay the application event log to reconstruct the expected RTMR[3].
package tpm

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"go.uber.org/zap"
)

const (
	// pcr16 is the application-defined PCR that maps to RTMR[3] in TDX.
	pcr16 = 16
)

// Event represents a single application measurement event for RTMR[3]
// replay verification.
type Event struct {
	Timestamp    string `json:"timestamp"`
	PCR          int    `json:"pcr"`
	DigestSHA384 string `json:"digest_sha384"` // hex
	DigestSHA256 string `json:"digest_sha256"` // hex
	Type         string `json:"type"`           // "container_load" or "container_unload"
	Description  string `json:"description"`
}

// Extender manages TPM PCR extend operations and maintains an application
// event log for RTMR[3] replay verification.
type Extender struct {
	log       *zap.Logger
	device    string
	events    []Event
	available bool
	mu        sync.Mutex
}

// NewExtender creates a new TPM extender. Returns a no-op extender if the
// TPM device is not available (graceful degradation for non-TDX environments).
func NewExtender(log *zap.Logger) *Extender {
	e := &Extender{
		log:    log.Named("tpm"),
		events: make([]Event, 0),
	}

	// Prefer the resource manager device.
	for _, dev := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(dev); err == nil {
			e.device = dev
			e.available = true
			log.Info("TPM device found — RTMR[3] extend enabled",
				zap.String("device", dev))
			return e
		}
	}

	log.Warn("no TPM device found — RTMR[3] extend disabled")
	return e
}

// Available returns whether the TPM device is accessible.
func (e *Extender) Available() bool {
	return e.available
}

// ExtendContainerLoad extends PCR 16 with the container's identity:
// digest = SHA-384(name || image_digest).
func (e *Extender) ExtendContainerLoad(name string, imageDigest []byte) error {
	data := append([]byte(name), imageDigest...)
	return e.extend("container_load", fmt.Sprintf("load:%s", name), data)
}

// ExtendContainerUnload extends PCR 16 with an unload marker:
// digest = SHA-384("unload:" || name).
func (e *Extender) ExtendContainerUnload(name string) error {
	data := []byte("unload:" + name)
	return e.extend("container_unload", fmt.Sprintf("unload:%s", name), data)
}

// Events returns a copy of the application event log for RTMR[3] replay.
func (e *Extender) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, len(e.events))
	copy(out, e.events)
	return out
}

// extend hashes the data and performs the PCR extend.
func (e *Extender) extend(eventType, description string, data []byte) error {
	hash384 := sha512.Sum384(data)
	hash256 := sha256.Sum256(data)

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.available {
		if err := e.pcrExtend(hash384[:], hash256[:]); err != nil {
			e.log.Error("PCR 16 extend failed",
				zap.Error(err),
				zap.String("event", description))
			return fmt.Errorf("tpm: PCR extend failed: %w", err)
		}
	}

	e.events = append(e.events, Event{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		PCR:          pcr16,
		DigestSHA384: fmt.Sprintf("%x", hash384),
		DigestSHA256: fmt.Sprintf("%x", hash256),
		Type:         eventType,
		Description:  description,
	})

	e.log.Info("RTMR[3] extended (PCR 16)",
		zap.String("event", description),
		zap.String("sha384", fmt.Sprintf("%x", hash384[:8])))
	return nil
}

// pcrExtend sends a TPM2_PCR_Extend command to extend PCR 16 with both
// SHA-384 (maps to RTMR[3]) and SHA-256 banks.
func (e *Extender) pcrExtend(sha384Digest, sha256Digest []byte) error {
	t, err := transport.OpenTPM(e.device)
	if err != nil {
		return fmt.Errorf("open TPM %s: %w", e.device, err)
	}
	defer t.Close()

	cmd := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(pcr16),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA384,
					Digest:  sha384Digest,
				},
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  sha256Digest,
				},
			},
		},
	}

	if _, err := cmd.Execute(t); err != nil {
		return fmt.Errorf("TPM2_PCR_Extend: %w", err)
	}
	return nil
}
