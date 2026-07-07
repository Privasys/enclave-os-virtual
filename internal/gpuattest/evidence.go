// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package gpuattest

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Evidence is the self-contained NVIDIA GPU CC attestation evidence carried in
// the RA-TLS cert's GPU-evidence extension (OID 1.3.6.1.4.1.65230.5.1) and
// verified by the attestation server.
type Evidence struct {
	Nonce                [NonceSize]byte // the B the report was bound to (mode value)
	AttestationReport    []byte          // SPDM MEASUREMENTS response, signed by the GSP FMC key
	AttestationCertChain []byte          // PEM chain: GSP FMC → … → NVIDIA Device Identity CA
	CecReport            []byte          // optional CEC/caps report
	GPUUUID              string
	DriverVersion        string
	VBIOSVersion         string
	CCEnvironment        uint32 // nvmlConfComputeState.environment (2 = production)
	CCFeature            uint32 // nvmlConfComputeState.ccFeature (1 = CC on)
	DevToolsMode         uint32 // nvmlConfComputeState.devToolsMode (0 = off)
}

// Envelope wire format: magic "PGAE", version 1, then TLV fields
// (type u8, len u32-BE, value). Deterministic field order so Hash is stable.
var envMagic = [4]byte{'P', 'G', 'A', 'E'}

const envVersion = 1

const (
	fNonce      = 0x01
	fReport     = 0x02
	fCertChain  = 0x03
	fCecReport  = 0x04
	fUUID       = 0x05
	fDriver     = 0x06
	fVBIOS      = 0x07
	fCCEnv      = 0x08
	fCCFeature  = 0x09
	fDevTools   = 0x0a
	maxEnvelope = 1 << 20 // 1 MiB sanity bound
)

// Marshal encodes the evidence into the versioned TLV envelope.
func (e *Evidence) Marshal() []byte {
	var buf []byte
	buf = append(buf, envMagic[:]...)
	buf = append(buf, envVersion)

	put := func(typ byte, v []byte) {
		buf = append(buf, typ)
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(v)))
		buf = append(buf, l[:]...)
		buf = append(buf, v...)
	}
	u32 := func(x uint32) []byte {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], x)
		return b[:]
	}

	put(fNonce, e.Nonce[:])
	put(fReport, e.AttestationReport)
	put(fCertChain, e.AttestationCertChain)
	if len(e.CecReport) > 0 {
		put(fCecReport, e.CecReport)
	}
	put(fUUID, []byte(e.GPUUUID))
	put(fDriver, []byte(e.DriverVersion))
	put(fVBIOS, []byte(e.VBIOSVersion))
	put(fCCEnv, u32(e.CCEnvironment))
	put(fCCFeature, u32(e.CCFeature))
	put(fDevTools, u32(e.DevToolsMode))
	return buf
}

// Sha256 is SHA-256 over the marshaled envelope — the value the RA-TLS
// REPORTDATA commits to (D1: report_data = SHA512(SHA256(pubkey) ‖ B ‖ this)).
func (e *Evidence) Sha256() [32]byte { return sha256.Sum256(e.Marshal()) }

// Unmarshal decodes an envelope produced by Marshal. Used by the verifier.
func Unmarshal(b []byte) (*Evidence, error) {
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
