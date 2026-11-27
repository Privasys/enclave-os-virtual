// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gpuattest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
	out, err := unmarshal(in.Marshal())
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
	if _, err := unmarshal([]byte("nope")); err == nil {
		t.Fatal("expected bad-magic error")
	}
	if _, err := unmarshal(append([]byte("PGAE"), 0x02)); err == nil {
		t.Fatal("expected unsupported-version error")
	}
}

// unmarshal decodes an envelope produced by Marshal, as a verifier reads it,
// so the tests check the format end to end.
func unmarshal(b []byte) (*Evidence, error) {
	if len(b) < 5 || [4]byte{b[0], b[1], b[2], b[3]} != envMagic {
		return nil, errors.New("gpuattest: bad envelope magic")
	}
	if b[4] != envVersion {
		return nil, fmt.Errorf("gpuattest: unsupported envelope version %d", b[4])
	}
	e := &Evidence{}
	p := 5
	for p < len(b) {
		if p+5 > len(b) {
			return nil, errors.New("gpuattest: truncated TLV header")
		}
		typ := b[p]
		l := binary.BigEndian.Uint32(b[p+1 : p+5])
		p += 5
		if l > maxEnvelope || p+int(l) > len(b) {
			return nil, errors.New("gpuattest: truncated TLV value")
		}
		v := b[p : p+int(l)]
		p += int(l)
		switch typ {
		case fNonce:
			if len(v) != NonceSize {
				return nil, errors.New("gpuattest: bad nonce length")
			}
			copy(e.Nonce[:], v)
		case fReport:
			e.AttestationReport = append([]byte(nil), v...)
		case fCertChain:
			e.AttestationCertChain = append([]byte(nil), v...)
		case fCecReport:
			e.CecReport = append([]byte(nil), v...)
		case fUUID:
			e.GPUUUID = string(v)
		case fDriver:
			e.DriverVersion = string(v)
		case fVBIOS:
			e.VBIOSVersion = string(v)
		case fCCEnv:
			if len(v) == 4 {
				e.CCEnvironment = binary.BigEndian.Uint32(v)
			}
		case fCCFeature:
			if len(v) == 4 {
				e.CCFeature = binary.BigEndian.Uint32(v)
			}
		case fDevTools:
			if len(v) == 4 {
				e.DevToolsMode = binary.BigEndian.Uint32(v)
			}
		default:
			// Unknown field: skip (forward-compatible).
		}
	}
	return e, nil
}
