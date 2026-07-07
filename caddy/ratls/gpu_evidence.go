// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"path/filepath"
)

// oidNVIDIAGPUEvidence is the X.509 extension OID carrying the NVIDIA GPU
// Confidential-Computing attestation evidence envelope alongside the primary
// TDX quote (the tdx-gpu combined case). Kept in lock-step with
// enclave-os-virtual/internal/oids.NVIDIAGPUEvidence and the RA-TLS client's
// OidNVIDIAGPUEvidence (this module has its own go.mod, so the value is
// duplicated here, like oidTDXQuote in attester_tdx.go).
var oidNVIDIAGPUEvidence = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65230, 5, 1}

// defaultGPUEvidenceDir is where the gpu-attest daemon writes the cached
// deterministic evidence (see internal/gpuattest, cmd/gpu-attest).
const defaultGPUEvidenceDir = "/run"

const gpuEvidenceFile = "gpu-evidence.bin"

// maxGPUEvidence bounds the evidence blob read into a cert extension (the real
// envelope is ~9 KiB: SPDM report + PEM cert chain + CEC).
const maxGPUEvidence = 64 * 1024

// loadGPUEvidence reads the cached GPU CC attestation evidence envelope from
// dir (defaulting to /run). ok is false when there is no GPU / no cached
// evidence, in which case the caller omits the extension and the cert is
// byte-identical to a non-GPU cert. Also returns SHA-256(evidence), the value
// the RA-TLS REPORTDATA commits to (plan D1).
func loadGPUEvidence(dir string) (evidence []byte, sum [32]byte, ok bool) {
	if dir == "" {
		dir = defaultGPUEvidenceDir
	}
	b, err := os.ReadFile(filepath.Join(dir, gpuEvidenceFile))
	if err != nil || len(b) == 0 || len(b) > maxGPUEvidence {
		return nil, [32]byte{}, false
	}
	return b, sha256.Sum256(b), true
}

// gpuBinding returns the REPORTDATA binding B extended with SHA-256(evidence)
// when GPU evidence is present, else B unchanged. This is what turns
// report_data into SHA-512(SHA-256(pubkey) ‖ B ‖ SHA-256(evidence)) via the
// existing computeReportData(pubkey, binding).
func gpuBinding(b []byte, sum [32]byte, ok bool) []byte {
	if !ok {
		return b
	}
	out := make([]byte, 0, len(b)+len(sum))
	out = append(out, b...)
	out = append(out, sum[:]...)
	return out
}

// gpuExtension builds the OID-5.1 cert extension carrying the evidence blob.
func gpuExtension(evidence []byte) pkix.Extension {
	return pkix.Extension{Id: oidNVIDIAGPUEvidence, Value: evidence}
}
