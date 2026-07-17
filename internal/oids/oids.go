// Package oids defines the X.509 OID extensions used in Enclave OS (Virtual)
// RA-TLS certificates. These mirror the Privasys OID arc used in Enclave OS
// Mini (SGX) with unified naming conventions for cross-product alignment.
//
// OID hierarchy under 1.3.6.1.4.1.65230 (Privasys arc):
//
//	1.1   Platform Config Merkle Root (enclave/VM-wide)
//	2.*   Platform-wide module OIDs
//	  2.1 Egress CA bundle hash (Mini only)
//	  2.4 Runtime version hash (containerd in Virtual, Wasmtime in Mini)
//	  2.5 Combined workloads hash (container images in Virtual, WASM apps in Mini)
//	  2.6 Data Encryption Key Origin ("byok:<fingerprint>")
//	  2.7 Attestation Servers Hash
//	  2.8 Image Profile ("production" or "dev")
//	3.*   Per-container OIDs (via SNI routing)
//	  3.1 Container Config Merkle Root
//	  3.2 Container Image Digest (SHA-256 of OCI manifest)
//	  3.3 Container Image Reference (e.g. ghcr.io/example/myapp)
//	  3.4 Container Volume Encryption
//	  3.5 Container Model Digest (legacy slot; canonical home is app arc 3.5.5)
//	  3.6 Container App Id (apps.id, raw 16-byte UUID)
//	5.*   Hardware accelerator attestation evidence
//	  5.1 NVIDIA GPU CC attestation evidence (carried alongside the TDX
//	      quote; the tdx-gpu combined case). Aligned with the RA-TLS
//	      client's OidNVIDIAGPUEvidence.
//
// The TDX and SGX quote OIDs are defined by Intel:
//
//	1.2.840.113741.1.5.5.1.6  Intel TDX DCAP Quote
//	1.2.840.113741.1.13.1.0   Intel SGX DCAP Quote
package oids

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// --- Intel hardware quote OIDs -------------------------------------------

// TDXQuote is the X.509 extension OID for an Intel TDX attestation quote.
var TDXQuote = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 5, 5, 1, 6}

// SGXQuote is the X.509 extension OID for an Intel SGX attestation quote.
var SGXQuote = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 0}

// --- Privasys arc: 1.3.6.1.4.1.65230 ------------------------------------

// privasysArc is the base OID arc for all Privasys extensions.
var privasysArc = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65230}

// --- Platform-wide OIDs (1.3.6.1.4.1.65230.1.*) -------------------------

// PlatformConfigMerkleRoot is the SHA-256 Merkle root of all platform
// configuration inputs. This covers the base image, CA certs, and the
// combined state of all loaded containers.
var PlatformConfigMerkleRoot = append(append(asn1.ObjectIdentifier{}, privasysArc...), 1, 1)

// --- Module OIDs (1.3.6.1.4.1.65230.2.*) --------------------------------

// RuntimeVersionHash is the SHA-256 of the runtime binary version
// string. In Virtual this is the containerd version; in Mini it is
// reserved for the Wasmtime engine version.
//
// Aligned with enclave-os-mini OID 2.4 (Runtime Version Hash).
var RuntimeVersionHash = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 4)

// CombinedWorkloadsHash is the SHA-256 of all workload code hashes
// (sorted by name, concatenated). In Virtual this covers container image
// digests; in Mini it covers WASM app bytecode hashes.
//
// Aligned with enclave-os-mini OID 2.5 (Combined Workloads Hash).
var CombinedWorkloadsHash = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 5)

// DataEncryptionKeyOrigin describes how the LUKS data-encryption key was
// provisioned.  The value is a UTF-8 string:
//
//   - "byok:<fingerprint>" — operator-supplied via instance metadata;
//     <fingerprint> is the hex SHA-256 of the passphrase bytes
//
// BYOK is currently the only supported source. Its presence in the
// certificate proves data-at-rest is encrypted with an externally
// managed key.
var DataEncryptionKeyOrigin = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 6)

// AttestationServersHash is the SHA-256 of the canonical attestation
// server URL list (sorted, newline-joined). Proves which remote
// verification servers are trusted by the platform.
//
// Aligned with enclave-os-mini OID 2.7 (Attestation Servers Hash).
var AttestationServersHash = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 7)

// ImageProfile is the build flavor of the VM image, as a UTF-8 string:
//
//   - "production" -- no SSH daemon, no debug tools, no interactive
//     entry point
//   - "dev"        -- built with the mkosi `dev` profile (openssh,
//     strace, tcpdump, ...); NEVER acceptable for production workloads
//
// The value is read from /etc/privasys/image-profile, a marker baked
// into the dm-verity-measured rootfs at image build time — it cannot be
// changed at runtime, and a forged value would change the rootfs
// measurement. Verifiers MUST reject "dev" unless explicitly opted in
// (allowDebugImages). The OID is absent on images that predate the
// marker.
var ImageProfile = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 8)

// --- Accelerator attestation OIDs (1.3.6.1.4.1.65230.5.*) ---------------

// NVIDIAGPUEvidence carries the NVIDIA GPU Confidential-Computing attestation
// evidence envelope (SPDM report + attestation cert chain + CC state; see
// internal/gpuattest) as a SECONDARY extension alongside the primary TDX
// quote — the "tdx-gpu" combined case. Its presence signals to a verifier
// that the TDX REPORTDATA additionally commits to SHA-256(evidence) and that
// the GPU report is bound to the same mode value B. Aligned byte-for-byte
// with the RA-TLS client's OidNVIDIAGPUEvidence (1.3.6.1.4.1.65230.5.1).
var NVIDIAGPUEvidence = append(append(asn1.ObjectIdentifier{}, privasysArc...), 5, 1)

// --- Per-container OIDs (1.3.6.1.4.1.65230.3.*) -------------------------

// ContainerConfigMerkleRoot is the SHA-256 Merkle root of a specific
// container's configuration (image digest, env vars, mounts, etc.).
var ContainerConfigMerkleRoot = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 1)

// ContainerImageDigest is the SHA-256 digest of the OCI image manifest
// for a specific container.
var ContainerImageDigest = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 2)

// ContainerImageRef is the image name and registry path (e.g.
// "ghcr.io/example/myapp") for a specific container. The digest is
// stored separately in ContainerImageDigest (OID 3.2).
var ContainerImageRef = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 3)

// ContainerVolumeEncryption indicates whether a per-container encrypted
// volume is provisioned and how the volume key was obtained.  The value
// is a UTF-8 string:
//
//   - "byok:<fingerprint>" -- volume key supplied via the API;
//     <fingerprint> is the hex SHA-256 of the raw key bytes
//   - "generated"          -- volume key randomly generated inside the enclave
//
// The OID is omitted entirely when no encrypted volume is attached.
// Its presence proves the container's persistent data is individually
// encrypted with its own LUKS2+AEAD key.
var ContainerVolumeEncryption = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 4)

// ContainerModelDigest is the LEGACY slot for the SHA-256 digest of the AI/ML
// model weights loaded inside the container (raw 32-byte hash, self-declared
// by the container via /.well-known/attestation-extensions — the manager never
// stamps it, and this constant is not referenced by manager code).
//
// Deprecated: the model digest is an app-specific value and moved under the
// app arc, to 3.5.5 (fleet images v0.5+; older fleets emit both during the
// migration). Literal 3.5 is enclave-os-mini's runtime-stamped configuration
// hash — once no live verifier reads the model digest here, remove the legacy
// emission and reserve literal 3.5 in the Caddy filter so every top-level 3.x
// OID is uniformly runtime-stamped.
var ContainerModelDigest = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 5)

// ContainerAppId is the platform-assigned app identity (apps.id, the raw
// 16-byte UUID) for a specific container. It pins WHICH app a container is, so a
// vault key bound to it (MR_APP sealing mode) cannot be unsealed by a same-image
// peer carrying a different app-id, and so clients (wallet, dependents) can read
// the management app id straight off the attested leaf. The platform assigns it;
// the measured manager stamps it — on the standing serving cert (via
// ContainerExtensions) and on manager-minted vault identity leaves alike — so a
// container cannot forge another app's id. See the MR_APP / promote-step-up design.
var ContainerAppId = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 6)

// AttestedDependencySet carries a container's set of DIRECT attested
// cross-enclave dependency identities (the peers it is pinned to and will only
// complete an RA-TLS handshake with). The value is the canonical dependency-set
// encoding, byte-identical to the RA-TLS SDKs. The manager (measured) owns and
// stamps it; the container cannot write it, so the advertised set and the
// enforced set are one object. The top-level 6 arc is distinct from the
// hardware-evidence arcs (4.x SEV-SNP, 5.x NVIDIA GPU).
var AttestedDependencySet = append(append(asn1.ObjectIdentifier{}, privasysArc...), 6, 1)

// ContainerEnvVarArcPrefix is the dot-notation prefix for per-environment-
// variable attestation extensions. Each runtime-supplied env var may be
// pinned at a sub-OID 1.3.6.1.4.1.65230.3.5.<n>[.<n>...]. The extension
// value contains either the raw UTF-8 value bytes (public vars) or the
// 32-byte SHA-256 of the value (secret vars). Sub-OID assignment is
// chosen by the deployer at deploy time.
const ContainerEnvVarArcPrefix = "1.3.6.1.4.1.65230.3.5."

// ParseEnvVarOID parses an OID for an env-var attestation extension.
// It accepts either:
//   - the full dot-notation OID under ContainerEnvVarArcPrefix
//     (e.g. "1.3.6.1.4.1.65230.3.5.1.2"), or
//   - just the sub-arc tail under that prefix
//     (e.g. "1.2", "1") — the prefix is implied.
//
// Returns an error for empty input, empty components, or non-numeric
// components.
func ParseEnvVarOID(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, fmt.Errorf("oid is empty")
	}
	sub := s
	if strings.HasPrefix(s, ContainerEnvVarArcPrefix) {
		sub = strings.TrimPrefix(s, ContainerEnvVarArcPrefix)
	}
	if sub == "" {
		return nil, fmt.Errorf("oid %q is missing sub-arc components", s)
	}
	out := append(asn1.ObjectIdentifier{}, privasysArc...)
	out = append(out, 3, 5)
	for _, p := range strings.Split(sub, ".") {
		if p == "" {
			return nil, fmt.Errorf("oid %q has empty sub-arc component", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("oid %q sub-arc must be non-negative integers", s)
		}
		out = append(out, n)
	}
	return out, nil
}

// --- Extension builders --------------------------------------------------

// Extension creates a non-critical X.509 extension with the given OID and
// raw value bytes.
func Extension(oid asn1.ObjectIdentifier, value []byte) pkix.Extension {
	return pkix.Extension{
		Id:       oid,
		Critical: false,
		Value:    value,
	}
}

// PlatformExtensions returns the set of X.509 extensions for a platform-wide
// (non-per-container) RA-TLS certificate.  If dekOrigin is non-empty the Data
// Encryption Key Origin (OID 2.6) extension is included.  If attestationServersHash
// is non-nil the Attestation Servers Hash (OID 2.7) extension is included.
func PlatformExtensions(quote []byte, quoteOID asn1.ObjectIdentifier, merkleRoot [32]byte, runtimeVersionHash [32]byte, combinedWorkloadsHash [32]byte, dekOrigin string, attestationServersHash *[32]byte) []pkix.Extension {
	exts := []pkix.Extension{
		Extension(quoteOID, quote),
		Extension(PlatformConfigMerkleRoot, merkleRoot[:]),
		Extension(RuntimeVersionHash, runtimeVersionHash[:]),
		Extension(CombinedWorkloadsHash, combinedWorkloadsHash[:]),
	}
	if dekOrigin != "" {
		exts = append(exts, Extension(DataEncryptionKeyOrigin, []byte(dekOrigin)))
	}
	if attestationServersHash != nil {
		exts = append(exts, Extension(AttestationServersHash, attestationServersHash[:]))
	}
	return exts
}

// ContainerExtensions returns the set of X.509 extensions for a per-container
// RA-TLS leaf certificate.  volumeEncryption may be empty to omit the OID.
// appID is the platform-assigned app identity (raw 16-byte UUID) stamped at
// OID 3.6; nil/empty omits the OID (pre-app-id deployments).
//
// Note: application-specific OIDs (e.g. OID 3.5 model digest) are not included
// here. Those are served by the container itself via the
// /.well-known/attestation-extensions endpoint and pulled by Caddy's RA-TLS
// module at certificate issuance time, the same way enclave-os-mini's
// custom_oids() works.
func ContainerExtensions(configMerkleRoot [32]byte, imageDigest []byte, imageRef string, volumeEncryption string, appID []byte) []pkix.Extension {
	// Strip @sha256:... from the image ref; the digest is captured in OID 3.2.
	if i := strings.Index(imageRef, "@"); i >= 0 {
		imageRef = imageRef[:i]
	}
	exts := []pkix.Extension{
		Extension(ContainerConfigMerkleRoot, configMerkleRoot[:]),
		Extension(ContainerImageDigest, imageDigest),
		Extension(ContainerImageRef, []byte(imageRef)),
	}
	if volumeEncryption != "" {
		exts = append(exts, Extension(ContainerVolumeEncryption, []byte(volumeEncryption)))
	}
	if len(appID) > 0 {
		exts = append(exts, Extension(ContainerAppId, appID))
	}
	return exts
}
