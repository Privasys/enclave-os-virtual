// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package gpuattest collects NVIDIA GPU Confidential-Computing attestation
// evidence (the SPDM attestation report + the GPU attestation certificate
// chain + the CEC report) bound to a caller-supplied 32-byte nonce, plus the
// GPU identity metadata a verifier needs (UUID, driver, VBIOS, CC state).
//
// It binds NVML at runtime via purego (dlopen/dlsym) so the enclave binaries
// keep building CGO_ENABLED=0 and carry no NVML build dependency; a host with
// no GPU / no libnvidia-ml simply returns ErrUnavailable and the caller omits
// GPU evidence from the RA-TLS cert.
//
// Struct layouts + the "no version field, sizes-before-nonce" ordering are the
// authoritative nvidia-ml-py definitions, validated live on driver 595.71.05 /
// H100 (see gpu-attestation-plan.md Phase 0).
package gpuattest

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

// ErrUnavailable is returned when NVML or a CC-capable GPU is not present.
// Callers treat this as "no GPU evidence" (not a hard failure).
var ErrUnavailable = errors.New("gpuattest: NVML/CC GPU unavailable")

// NonceSize is the SPDM nonce the GPU attestation report binds (32 bytes).
const NonceSize = 0x20

// NVML struct sizes (authoritative, from nvidia-ml-py; verified on 595.71.05).
const (
	gpuCertChainSize    = 0x1000
	attCertChainSize    = 0x1400
	atstReportSize      = 0x2000
	cecReportSize       = 0x1000
	driverVersionBuffer = 80
	uuidBuffer          = 96
	vbiosBuffer         = 32
)

// confComputeState mirrors nvmlConfComputeSystemState_t — {environment,
// ccFeature, devToolsMode}, NO version field (authoritative from
// nvidia-ml-py; an extra leading field silently shifts every value).
type confComputeState struct {
	environment  uint32
	ccFeature    uint32
	devToolsMode uint32
}

// NVML CC system-state enum values.
const (
	ccEnvProd       = 2 // NVML_CC_SYSTEM_ENVIRONMENT_PROD (1 = SIM, 0 = unavailable)
	ccFeatureOn     = 1 // NVML_CC_SYSTEM_FEATURE_ENABLED
	ccDevToolsOnVal = 1 // NVML_CC_SYSTEM_DEVTOOLS_MODE_ON
)

// gpuCertificate mirrors nvmlConfComputeGpuCertificate_t (no version field).
type gpuCertificate struct {
	certChainSize            uint32
	attestationCertChainSize uint32
	certChain                [gpuCertChainSize]byte
	attestationCertChain     [attCertChainSize]byte
}

// gpuAttestationReport mirrors nvmlConfComputeGpuAttestationReport_t: the three
// output sizes come BEFORE the input nonce, and there is no version field.
type gpuAttestationReport struct {
	isCecAttestationReportPresent uint32
	attestationReportSize         uint32
	cecAttestationReportSize      uint32
	nonce                         [NonceSize]byte
	attestationReport             [atstReportSize]byte
	cecAttestationReport          [cecReportSize]byte
}

// nvml holds the resolved NVML entry points.
type nvml struct {
	initV2               func() int32
	shutdown             func() int32
	handleByIndex        func(idx uint32, dev *uintptr) int32
	systemGetDriver      func(buf *byte, length uint32) int32
	deviceGetUUID        func(dev uintptr, buf *byte, length uint32) int32
	deviceGetVbios       func(dev uintptr, buf *byte, length uint32) int32
	getConfComputeState  func(state *confComputeState) int32
	getGpuAttestation    func(dev uintptr, report *gpuAttestationReport) int32
	getGpuCertificate    func(dev uintptr, cert *gpuCertificate) int32
}

var (
	loadOnce sync.Once
	loaded   *nvml
	loadErr  error
)

// load resolves libnvidia-ml.so.1 once. Absent library ⇒ ErrUnavailable.
func load() (*nvml, error) {
	loadOnce.Do(func() {
		h, err := purego.Dlopen("libnvidia-ml.so.1", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			loadErr = fmt.Errorf("%w: dlopen libnvidia-ml: %v", ErrUnavailable, err)
			return
		}
		n := &nvml{}
		// RegisterLibFunc panics on a missing symbol; recover into loadErr so a
		// driver without the CC-attestation API degrades to ErrUnavailable.
		defer func() {
			if r := recover(); r != nil {
				loadErr = fmt.Errorf("%w: NVML symbol: %v", ErrUnavailable, r)
				loaded = nil
			}
		}()
		purego.RegisterLibFunc(&n.initV2, h, "nvmlInit_v2")
		purego.RegisterLibFunc(&n.shutdown, h, "nvmlShutdown")
		purego.RegisterLibFunc(&n.handleByIndex, h, "nvmlDeviceGetHandleByIndex_v2")
		purego.RegisterLibFunc(&n.systemGetDriver, h, "nvmlSystemGetDriverVersion")
		purego.RegisterLibFunc(&n.deviceGetUUID, h, "nvmlDeviceGetUUID")
		purego.RegisterLibFunc(&n.deviceGetVbios, h, "nvmlDeviceGetVbiosVersion")
		purego.RegisterLibFunc(&n.getConfComputeState, h, "nvmlSystemGetConfComputeState")
		purego.RegisterLibFunc(&n.getGpuAttestation, h, "nvmlDeviceGetConfComputeGpuAttestationReport")
		purego.RegisterLibFunc(&n.getGpuCertificate, h, "nvmlDeviceGetConfComputeGpuCertificate")
		loaded = n
	})
	if loadErr != nil {
		return nil, loadErr
	}
	return loaded, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Collect fetches CC attestation evidence bound to nonce. The returned Evidence
// is self-contained (report + attestation cert chain + CEC + identity). Returns
// ErrUnavailable when NVML/CC GPU is absent.
func Collect(nonce [NonceSize]byte) (*Evidence, error) {
	n, err := load()
	if err != nil {
		return nil, err
	}
	if rc := n.initV2(); rc != 0 {
		return nil, fmt.Errorf("%w: nvmlInit rc=%d", ErrUnavailable, rc)
	}
	defer n.shutdown()

	var dev uintptr
	if rc := n.handleByIndex(0, &dev); rc != 0 {
		return nil, fmt.Errorf("gpuattest: GetHandleByIndex rc=%d", rc)
	}

	ev := &Evidence{Nonce: nonce}

	// CC state. Fail closed unless CC is ON in a PRODUCTION environment (a SIM
	// environment or DevTools-on would make the evidence untrustworthy).
	var st confComputeState
	if rc := n.getConfComputeState(&st); rc != 0 {
		return nil, fmt.Errorf("gpuattest: GetConfComputeState rc=%d", rc)
	}
	ev.CCEnvironment = st.environment
	ev.CCFeature = st.ccFeature
	ev.DevToolsMode = st.devToolsMode
	if st.ccFeature != ccFeatureOn {
		return nil, fmt.Errorf("%w: GPU CC feature not ON (feature=%d env=%d)", ErrUnavailable, st.ccFeature, st.environment)
	}
	if st.environment != ccEnvProd {
		return nil, fmt.Errorf("gpuattest: GPU CC environment is not PRODUCTION (env=%d) — refusing", st.environment)
	}
	if st.devToolsMode == ccDevToolsOnVal {
		return nil, errors.New("gpuattest: GPU CC DevTools mode is ON — refusing (debug/untrusted)")
	}

	// Identity metadata.
	drv := make([]byte, driverVersionBuffer)
	if rc := n.systemGetDriver(&drv[0], driverVersionBuffer); rc == 0 {
		ev.DriverVersion = cstr(drv)
	}
	uuid := make([]byte, uuidBuffer)
	if rc := n.deviceGetUUID(dev, &uuid[0], uuidBuffer); rc == 0 {
		ev.GPUUUID = cstr(uuid)
	}
	vb := make([]byte, vbiosBuffer)
	if rc := n.deviceGetVbios(dev, &vb[0], vbiosBuffer); rc == 0 {
		ev.VBIOSVersion = cstr(vb)
	}

	// The nonce-bound SPDM attestation report.
	rep := &gpuAttestationReport{nonce: nonce}
	if rc := n.getGpuAttestation(dev, rep); rc != 0 {
		return nil, fmt.Errorf("gpuattest: GetGpuAttestationReport rc=%d", rc)
	}
	if rep.attestationReportSize == 0 || rep.attestationReportSize > atstReportSize {
		return nil, fmt.Errorf("gpuattest: implausible report size %d", rep.attestationReportSize)
	}
	ev.AttestationReport = append([]byte(nil), rep.attestationReport[:rep.attestationReportSize]...)
	if rep.isCecAttestationReportPresent != 0 && rep.cecAttestationReportSize > 0 && rep.cecAttestationReportSize <= cecReportSize {
		ev.CecReport = append([]byte(nil), rep.cecAttestationReport[:rep.cecAttestationReportSize]...)
	}
	// The GPU echoes the nonce it signed over; refuse if it doesn't match ours.
	if rep.nonce != nonce {
		return nil, errors.New("gpuattest: GPU report nonce mismatch (report not bound to our nonce)")
	}

	// The attestation cert chain (PEM) that verifies the report signature.
	cert := &gpuCertificate{}
	if rc := n.getGpuCertificate(dev, cert); rc != 0 {
		return nil, fmt.Errorf("gpuattest: GetGpuCertificate rc=%d", rc)
	}
	if cert.attestationCertChainSize == 0 || cert.attestationCertChainSize > attCertChainSize {
		return nil, fmt.Errorf("gpuattest: implausible cert chain size %d", cert.attestationCertChainSize)
	}
	ev.AttestationCertChain = append([]byte(nil), cert.attestationCertChain[:cert.attestationCertChainSize]...)

	return ev, nil
}
