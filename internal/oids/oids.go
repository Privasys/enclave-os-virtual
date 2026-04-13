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
//	  2.6 Data Encryption Key Origin ("byok:<fingerprint>" or "generated")
//	  2.7 Attestation Servers Hash
//	3.*   Per-container OIDs (via SNI routing)
//	  3.1 Container Config Merkle Root
//	  3.2 Container Image Digest (SHA-256 of OCI manifest)
//	  3.3 Container Image Reference (e.g. ghcr.io/example/myapp)
//	  3.4 Container Volume Encryption
//	  3.5 Container Model Digest (SHA-256 of AI/ML model weights)
//
// The TDX and SGX quote OIDs are defined by Intel:
//
//	1.2.840.113741.1.5.5.1.6  Intel TDX DCAP Quote
//	1.2.840.113741.1.13.1.0   Intel SGX DCAP Quote
package oids

import (
	"crypto/x509/pkix"
	"encoding/asn1"
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
//   - "byok:<fingerprint>" — operator-supplied via BYOK (GCP instance metadata);
//     <fingerprint> is the hex SHA-256 of the passphrase bytes
//   - "generated"         — randomly generated inside the enclave at first boot
//
// Its presence in the certificate proves data-at-rest is encrypted; the value
// tells the verifier whether the key is externally managed or ephemeral.
var DataEncryptionKeyOrigin = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 6)

// AttestationServersHash is the SHA-256 of the canonical attestation
// server URL list (sorted, newline-joined). Proves which remote
// verification servers are trusted by the platform.
//
// Aligned with enclave-os-mini OID 2.7 (Attestation Servers Hash).
var AttestationServersHash = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 7)

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

// ContainerModelDigest is the SHA-256 digest of the AI/ML model weights
// loaded inside the container.  The value is the raw 32-byte hash.
// This OID is only present when the container reports a model digest
// (e.g. via the /health endpoint's model_digest field).
//
// It allows verifiers to confirm exactly which model weights are being
// used for inference, complementing the container image digest (OID 3.2)
// which covers the code but not the dynamically-loaded model.
var ContainerModelDigest = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 5)

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
//
// Note: application-specific OIDs (e.g. OID 3.5 model digest) are not included
// here. Those are served by the container itself via the
// /.well-known/attestation-extensions endpoint and pulled by Caddy's RA-TLS
// module at certificate issuance time, the same way enclave-os-mini's
// custom_oids() works.
func ContainerExtensions(configMerkleRoot [32]byte, imageDigest []byte, imageRef string, volumeEncryption string) []pkix.Extension {
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
	return exts
}
