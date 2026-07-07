// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gpuattest

import (
	"bytes"
	"testing"
)

func sample() *Evidence {
	e := &Evidence{
		AttestationReport:    []byte{0x11, 0xe0, 0x01, 0xff, 0xaa, 0xbb},
		AttestationCertChain: []byte("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n"),
		CecReport:            []byte{0xde, 0xad},
		GPUUUID:              "GPU-bd658688-a7a7-9ac0-5282-130b7d11b70c",
		DriverVersion:        "595.71.05",
		VBIOSVersion:         "96.00.CF.00.01",
		CCEnvironment:        2,
		CCFeature:            1,
		DevToolsMode:         0,
	}
	for i := range e.Nonce {
		e.Nonce[i] = byte(i)
	}
	return e
}

func TestEvidenceRoundTrip(t *testing.T) {
	in := sample()
	out, err := Unmarshal(in.Marshal())
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Nonce != in.Nonce ||
		!bytes.Equal(out.AttestationReport, in.AttestationReport) ||
		!bytes.Equal(out.AttestationCertChain, in.AttestationCertChain) ||
		!bytes.Equal(out.CecReport, in.CecReport) ||
		out.GPUUUID != in.GPUUUID || out.DriverVersion != in.DriverVersion ||
		out.VBIOSVersion != in.VBIOSVersion || out.CCEnvironment != in.CCEnvironment ||
		out.CCFeature != in.CCFeature || out.DevToolsMode != in.DevToolsMode {
		t.Fatalf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestSha256Stable(t *testing.T) {
	// The hash must be deterministic (it is what REPORTDATA commits to).
	if sample().Sha256() != sample().Sha256() {
		t.Fatal("Sha256 not deterministic")
	}
	// A changed field must change the hash.
	a := sample()
	b := sample()
	b.AttestationReport = append(b.AttestationReport, 0x00)
	if a.Sha256() == b.Sha256() {
		t.Fatal("Sha256 did not change with report content")
	}
}

func TestUnmarshalRejectsGarbage(t *testing.T) {
	if _, err := Unmarshal([]byte("nope")); err == nil {
		t.Fatal("expected bad-magic error")
	}
	if _, err := Unmarshal(append([]byte("PGAE"), 0x02)); err == nil {
		t.Fatal("expected unsupported-version error")
	}
}
