// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"crypto/sha256"
	"os"
	"path/filepath"
)

// defaultGPUEvidenceDir is where the gpu-attest daemon writes the cached
// deterministic evidence (see internal/gpuattest, cmd/gpu-attest).
const defaultGPUEvidenceDir = "/run"

const gpuEvidenceFile = "gpu-evidence.bin"

// maxGPUEvidence bounds the evidence blob served in an attest response (the
// real envelope is ~9 KiB: SPDM report + PEM cert chain + CEC).
const maxGPUEvidence = 64 * 1024

// loadGPUEvidence reads the cached GPU CC attestation evidence envelope from
// dir (defaulting to /run). ok is false when there is no GPU / no cached
// evidence, in which case the attest response carries no gpu_evidence and the
// report_data binding is unchanged. Also returns SHA-256(evidence), the value
// the report_data commits to.
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

// gpuBinding returns the report_data binding B extended with SHA-256(evidence)
// when GPU evidence is present, else B unchanged:
// report_data = SHA-512(SHA-256(SPKI) || B || SHA-256(evidence)).
func gpuBinding(b []byte, sum [32]byte, ok bool) []byte {
	if !ok {
		return b
	}
	out := make([]byte, 0, len(b)+len(sum))
	out = append(out, b...)
	out = append(out, sum[:]...)
	return out
}
