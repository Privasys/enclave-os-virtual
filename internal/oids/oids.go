// Package oids defines the X.509 OID extensions of Enclave OS (Virtual) RA-TLS
// certificates: the Privasys OID scheme v2, generated from
// ra-tls-clients/oids.json (docs/oids.md there is the reference), with the
// same numbering on Enclave OS Mini (SGX).
//
// Scheme v2 under 1.3.6.1.4.1.65230 (Privasys arc), platform arcs 1 to 3
// mirrored by workload arcs 4 to 6, then trust relationships and evidence types:
//
//	1.*  Platform identity
//	  1.1 Runtime Version Hash (containerd on Virtual, Wasmtime on Mini)
//	  1.2 Image Profile ("production" or "dev")
//	  1.3 Enclave Instance ID (management-service enclave_id, 16-byte UUID)
//	  1.4 Platform Hardware Identity (reserved)
//	2.*  Platform configuration
//	  2.1 Config Merkle Root
//	  2.2 Egress CA Bundle Hash (Mini only)
//	  2.3 Attestation Servers Hash
//	  2.4 Combined Workloads Hash
//	3.*  Platform keys and state
//	  3.1 Data Encryption Key Origin ("byok:<fingerprint>" or "generated")
//	  3.2 Authenticated State Root (Mini)
//	4.*  Workload identity
//	  4.1 Workload App ID (apps.id, raw 16-byte UUID)
//	  4.2 Workload Code Digest (SHA-256 of the OCI manifest)
//	  4.3 Workload Image Ref
//	5.*  Workload configuration
//	  5.1 Workload Config Merkle Root
//	  5.2 Workload Configuration Hash
//	  5.4.<n> App-defined extensions (SDK set-attestation-extension)
//	6.*  Workload keys and state
//	  6.1 Workload Key Source ("byok:<fingerprint>", "generated")
//	7.*  Trust relationships
//	  7.1 Attested Dependency Set
//	8.*  Evidence types (never certificate extensions)
//
// Attestation evidence (the TDX quote, GPU evidence) is not a certificate
// extension in v2: it is served after the handshake (caddy/ratls/attest.go).
package oids

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// privasysArc is the base OID arc for all Privasys extensions.
var privasysArc = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 65230}

func oid(sub ...int) asn1.ObjectIdentifier {
	return append(append(asn1.ObjectIdentifier{}, privasysArc...), sub...)
}

// --- Arc 1, platform identity -------------------------------------------

// RuntimeVersionHash is the SHA-256 of the runtime version string (containerd).
var RuntimeVersionHash = oid(1, 1)

// ImageProfile is the build flavor of the VM image as a UTF-8 string:
// "production" (no SSH daemon, no debug tools) or "dev" (mkosi dev profile).
// Read from /etc/privasys/image-profile, a marker baked into the
// dm-verity-measured rootfs. Verifiers reject "dev" unless opted in.
var ImageProfile = oid(1, 2)

// EnclaveInstanceID is the management-service enclave_id of this VM (raw
// 16-byte UUID), received at registration. It pins WHICH enclave instance
// serves a connection.
var EnclaveInstanceID = oid(1, 3)

// --- Arc 2, platform configuration --------------------------------------

// ConfigMerkleRoot is the SHA-256 Merkle root of all platform configuration
// inputs (base image, CA certs, the combined state of all loaded containers).
var ConfigMerkleRoot = oid(2, 1)

// AttestationServersHash is the SHA-256 of the canonical attestation server
// URL list (sorted, newline-joined).
var AttestationServersHash = oid(2, 3)

// CombinedWorkloadsHash is the SHA-256 of all workload code hashes (sorted by
// name, concatenated): the container image digests.
var CombinedWorkloadsHash = oid(2, 4)

// --- Arc 3, platform keys and state -------------------------------------

// DataEncryptionKeyOrigin describes how the LUKS data-encryption key was
// provisioned: "byok:<fingerprint>" (hex SHA-256 of the passphrase bytes).
var DataEncryptionKeyOrigin = oid(3, 1)

// --- Arc 4, workload identity -------------------------------------------

// WorkloadAppID is the platform-assigned app identity (apps.id, raw 16-byte
// UUID) of a container. The platform assigns it; the measured manager stamps
// it on the serving leaf and on manager-minted client identities alike.
var WorkloadAppID = oid(4, 1)

// WorkloadCodeHash is the SHA-256 digest of the OCI image manifest of a container.
var WorkloadCodeHash = oid(4, 2)

// WorkloadImageRef is the image name and registry path (digest stripped).
var WorkloadImageRef = oid(4, 3)

// --- Arc 5, workload configuration --------------------------------------

// WorkloadConfigMerkleRoot is the SHA-256 Merkle root of a container's
// configuration (image digest, env vars, mounts).
var WorkloadConfigMerkleRoot = oid(5, 1)

// WorkloadConfigurationHash is the runtime-stamped hash of the workload
// configuration.
var WorkloadConfigurationHash = oid(5, 2)

// AppExtensionArcPrefix is the dot-notation prefix of the app-defined sub-arc:
// a workload publishes attested values at 1.3.6.1.4.1.65230.5.4.<n>[.<n>...]
// through the SDK set-attestation-extension call or the deployer's env-var
// pinning. The root 5.4 carries no value.
const AppExtensionArcPrefix = "1.3.6.1.4.1.65230.5.4."

// --- Arc 6, workload keys and state -------------------------------------

// WorkloadKeySource says how a container's volume key was obtained:
// "byok:<fingerprint>" (hex SHA-256 of the raw key bytes) or "generated".
// Omitted when no encrypted volume is attached.
var WorkloadKeySource = oid(6, 1)

// --- Arc 7, trust relationships -----------------------------------------

// AttestedDependencySet carries a container's set of DIRECT attested
// cross-enclave dependency identities, in the canonical dependency-set
// encoding of the RA-TLS SDKs. Manager-owned; a container cannot write it.
var AttestedDependencySet = oid(7, 1)

// ParseEnvVarOID parses an OID for an app-defined attestation extension. It
// accepts the full dot-notation OID under AppExtensionArcPrefix
// ("1.3.6.1.4.1.65230.5.4.1.2") or just the sub-arc tail ("1.2", "1").
func ParseEnvVarOID(s string) (asn1.ObjectIdentifier, error) {
	if s == "" {
		return nil, fmt.Errorf("oid is empty")
	}
	sub := s
	if strings.HasPrefix(s, AppExtensionArcPrefix) {
		sub = strings.TrimPrefix(s, AppExtensionArcPrefix)
	}
	if sub == "" {
		return nil, fmt.Errorf("oid %q is missing sub-arc components", s)
	}
	out := oid(5, 4)
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
	return pkix.Extension{Id: oid, Critical: false, Value: value}
}

// PlatformExtensions returns the extensions of the platform (non-workload)
// leaf. dekOrigin and attestationServersHash are optional; enclaveID (16
// bytes) is stamped when known.
func PlatformExtensions(merkleRoot, runtimeVersionHash, combinedWorkloadsHash [32]byte, dekOrigin string, attestationServersHash *[32]byte, enclaveID []byte) []pkix.Extension {
	exts := []pkix.Extension{
		Extension(ConfigMerkleRoot, merkleRoot[:]),
		Extension(RuntimeVersionHash, runtimeVersionHash[:]),
		Extension(CombinedWorkloadsHash, combinedWorkloadsHash[:]),
	}
	if dekOrigin != "" {
		exts = append(exts, Extension(DataEncryptionKeyOrigin, []byte(dekOrigin)))
	}
	if attestationServersHash != nil {
		exts = append(exts, Extension(AttestationServersHash, attestationServersHash[:]))
	}
	if len(enclaveID) == 16 {
		exts = append(exts, Extension(EnclaveInstanceID, enclaveID))
	}
	return exts
}

// ContainerExtensions returns the workload extensions of a per-container leaf.
// keySource may be empty to omit 6.1; appID (raw 16-byte UUID) empty omits 4.1.
// App-defined 5.4.* extensions are pulled from the container by the Caddy
// module at issuance and are not built here.
func ContainerExtensions(configMerkleRoot [32]byte, imageDigest []byte, imageRef string, keySource string, appID []byte) []pkix.Extension {
	if i := strings.Index(imageRef, "@"); i >= 0 {
		imageRef = imageRef[:i]
	}
	exts := []pkix.Extension{
		Extension(WorkloadConfigMerkleRoot, configMerkleRoot[:]),
		Extension(WorkloadCodeHash, imageDigest),
		Extension(WorkloadImageRef, []byte(imageRef)),
	}
	if keySource != "" {
		exts = append(exts, Extension(WorkloadKeySource, []byte(keySource)))
	}
	if len(appID) > 0 {
		exts = append(exts, Extension(WorkloadAppID, appID))
	}
	return exts
}
