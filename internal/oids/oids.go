// Package oids defines the X.509 OID extensions used in Enclave OS (Virtual)
// RA-TLS certificates. These mirror the Privasys OID arc used in Enclave OS
// Mini (SGX) but are extended for container workloads.
//
// OID hierarchy under 1.3.6.1.4.1.65230 (Privasys arc):
//
//	1.1   Platform Config Merkle Root (enclave/VM-wide)
//	2.*   Platform-wide module OIDs
//	  2.4 Containerd runtime version hash
//	  2.5 Combined container images hash
//	  2.6 Data Encryption Key Origin ("external" or "enclave-generated")
//	3.*   Per-container OIDs (via SNI routing)
//	  3.1 Container Config Merkle Root
//	  3.2 Container Image Digest (SHA-256 of OCI manifest)
//	  3.3 Container Image Reference (e.g. ghcr.io/example/myapp@sha256:...)
//
// The TDX and SGX quote OIDs are defined by Intel:
//
//	1.2.840.113741.1.5.5.1.6  Intel TDX DCAP Quote
//	1.2.840.113741.1.13.1.0   Intel SGX DCAP Quote
package oids

import (
	"crypto/x509/pkix"
	"encoding/asn1"
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

// ContainerdVersionHash is the SHA-256 of the containerd binary version
// string, establishing the runtime version in use.
var ContainerdVersionHash = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 4)

// CombinedContainerImagesHash is the SHA-256 of all container image digests
// (sorted by name, concatenated), providing a single check for the full set
// of loaded workloads.
var CombinedContainerImagesHash = append(append(asn1.ObjectIdentifier{}, privasysArc...), 2, 5)

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

// --- Per-container OIDs (1.3.6.1.4.1.65230.3.*) -------------------------

// ContainerConfigMerkleRoot is the SHA-256 Merkle root of a specific
// container's configuration (image digest, env vars, mounts, etc.).
var ContainerConfigMerkleRoot = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 1)

// ContainerImageDigest is the SHA-256 digest of the OCI image manifest
// for a specific container.
var ContainerImageDigest = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 2)

// ContainerImageRef is the full image reference string (e.g.
// "ghcr.io/example/myapp@sha256:abc123...") for a specific container.
var ContainerImageRef = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 3)

// ContainerVolumeEncryption indicates whether a per-container encrypted
// volume is provisioned and how the volume key was obtained.  The value
// is a UTF-8 string:
//
//   - "byok:<fingerprint>" — volume key supplied via the API;
//     <fingerprint> is the hex SHA-256 of the raw key bytes
//   - "generated"          — volume key randomly generated inside the enclave
//
// The OID is omitted entirely when no encrypted volume is attached.
// Its presence proves the container's persistent data is individually
// encrypted with its own LUKS2+AEAD key.
var ContainerVolumeEncryption = append(append(asn1.ObjectIdentifier{}, privasysArc...), 3, 4)

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
// Encryption Key Origin (OID 2.6) extension is included, proving at the TLS
// level that the data partition is LUKS-encrypted and how the key was provisioned.
func PlatformExtensions(quote []byte, quoteOID asn1.ObjectIdentifier, merkleRoot [32]byte, containerdHash [32]byte, combinedImagesHash [32]byte, dekOrigin string) []pkix.Extension {
	exts := []pkix.Extension{
		Extension(quoteOID, quote),
		Extension(PlatformConfigMerkleRoot, merkleRoot[:]),
		Extension(ContainerdVersionHash, containerdHash[:]),
		Extension(CombinedContainerImagesHash, combinedImagesHash[:]),
	}
	if dekOrigin != "" {
		exts = append(exts, Extension(DataEncryptionKeyOrigin, []byte(dekOrigin)))
	}
	return exts
}

// ContainerExtensions returns the set of X.509 extensions for a per-container
// RA-TLS leaf certificate.  volumeEncryption may be empty to omit the OID.
func ContainerExtensions(configMerkleRoot [32]byte, imageDigest []byte, imageRef string, volumeEncryption string) []pkix.Extension {
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
