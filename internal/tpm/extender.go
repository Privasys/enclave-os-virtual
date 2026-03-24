// Package tpm provides application-level measurement operations for TDX
// runtime attestation.
//
// Measurements are recorded in two places:
//   - TDX RTMR[3] via the kernel sysfs interface (primary — appears in
//     the TDX quote and is verified by remote attesters).
//   - vTPM PCR 16 via TPM2_PCR_Extend (secondary — appears in the vTPM
//     event log for cross-verification).
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
	// pcr16 is the application-defined PCR used for vTPM event logging.
	pcr16 = 16

	// rtmr3Sysfs is the kernel sysfs path for extending TDX RTMR[3].
	// Writing a 48-byte SHA-384 digest triggers TDG.MR.RTMR.EXTEND via
	// the tdx_guest kernel module.
	rtmr3Sysfs = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"
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

// Extender manages RTMR and PCR extend operations and maintains an
// application event log for RTMR[3] replay verification.
type Extender struct {
	log       *zap.Logger
	device    string // vTPM device path
	rtmrPath  string // sysfs path for direct RTMR[3] extend
	events    []Event
	available bool
	mu        sync.Mutex
}

// NewExtender creates a new TPM extender. Returns a no-op extender if
// neither the TDX sysfs interface nor a vTPM device is available.
func NewExtender(log *zap.Logger) *Extender {
	e := &Extender{
		log:    log.Named("tpm"),
		events: make([]Event, 0),
	}

	// Check for the TDX RTMR sysfs interface (primary).
	if info, err := os.Stat(rtmr3Sysfs); err == nil && info.Mode().Perm()&0200 != 0 {
		e.rtmrPath = rtmr3Sysfs
		log.Info("TDX RTMR[3] sysfs interface available",
			zap.String("path", rtmr3Sysfs))
	}

	// Check for a vTPM device (secondary — event log).
	for _, dev := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(dev); err == nil {
			e.device = dev
			break
		}
	}

	if e.rtmrPath != "" || e.device != "" {
		e.available = true
		log.Info("TPM device found — RTMR[3] extend enabled",
			zap.String("device", e.device),
			zap.Bool("direct_rtmr", e.rtmrPath != ""))
	} else {
		log.Warn("no TPM device found — RTMR[3] extend disabled")
	}

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

// extend hashes the data and performs the RTMR + PCR extend.
func (e *Extender) extend(eventType, description string, data []byte) error {
	hash384 := sha512.Sum384(data)
	hash256 := sha256.Sum256(data)

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.available {
		// Primary: extend TDX RTMR[3] directly via the kernel sysfs interface.
		if e.rtmrPath != "" {
			if err := e.rtmrExtend(hash384[:]); err != nil {
				e.log.Error("RTMR[3] sysfs extend failed",
					zap.Error(err),
					zap.String("event", description))
				return fmt.Errorf("tpm: RTMR[3] extend failed: %w", err)
			}
		}

		// Secondary: extend vTPM PCR 16 for event log cross-verification.
		if e.device != "" {
			if err := e.pcrExtend(hash384[:], hash256[:]); err != nil {
				e.log.Warn("PCR 16 extend failed (non-fatal)",
					zap.Error(err),
					zap.String("event", description))
			}
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

	e.log.Info("RTMR[3] extended",
		zap.String("event", description),
		zap.String("sha384", fmt.Sprintf("%x", hash384[:8])),
		zap.Bool("direct_rtmr", e.rtmrPath != ""))
	return nil
}

// pcrExtend sends a TPM2_PCR_Extend command to extend PCR 16 with both
// SHA-384 and SHA-256 banks for event log cross-verification.
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

// rtmrExtend writes a 48-byte SHA-384 digest to the kernel sysfs interface,
// triggering TDG.MR.RTMR.EXTEND via the tdx_guest kernel module.
func (e *Extender) rtmrExtend(sha384Digest []byte) error {
	if err := os.WriteFile(e.rtmrPath, sha384Digest, 0); err != nil {
		return fmt.Errorf("write %s: %w", e.rtmrPath, err)
	}
	return nil
}
