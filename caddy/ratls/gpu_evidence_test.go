// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadGPUEvidenceAbsent(t *testing.T) {
	// No file ⇒ ok=false, binding unchanged, no extension (byte-identical cert).
	_, _, ok := loadGPUEvidence(t.TempDir())
	if ok {
		t.Fatal("expected ok=false when no evidence file")
	}
	b := []byte("2026-07-07T12:00Z")
	if got := gpuBinding(b, [32]byte{}, false); !bytes.Equal(got, b) {
		t.Fatal("gpuBinding must leave B unchanged when absent")
	}
}

func TestLoadGPUEvidencePresentBindsHash(t *testing.T) {
	dir := t.TempDir()
	evidence := []byte("PGAE\x01...sample envelope bytes...")
	if err := os.WriteFile(filepath.Join(dir, gpuEvidenceFile), evidence, 0o644); err != nil {
		t.Fatal(err)
	}
	ev, sum, ok := loadGPUEvidence(dir)
	if !ok || !bytes.Equal(ev, evidence) {
		t.Fatal("expected the evidence bytes back")
	}
	if sum != sha256.Sum256(evidence) {
		t.Fatal("sum must be SHA-256 of the evidence")
	}
	// The binding must be B ‖ SHA256(evidence), i.e. report_data commits to it.
	B := []byte("deadbeef-nonce")
	got := gpuBinding(B, sum, ok)
	want := append(append([]byte{}, B...), sum[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("gpuBinding mismatch:\n got=%x\nwant=%x", got, want)
	}
	// The extension carries the raw envelope under the GPU OID.
	if e := gpuExtension(ev); !e.Id.Equal(oidNVIDIAGPUEvidence) || !bytes.Equal(e.Value, evidence) {
		t.Fatal("gpuExtension mismatch")
	}
}

func TestLoadGPUEvidenceRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, gpuEvidenceFile), make([]byte, maxGPUEvidence+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := loadGPUEvidence(dir); ok {
		t.Fatal("oversize evidence must be rejected")
	}
}
