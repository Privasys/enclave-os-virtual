// Package manifest defines the workload manifest format for Enclave OS
// Virtual. The manifest describes which OCI containers to run, their
// configuration, and how they map to RA-TLS hostnames.
//
// The manifest is the primary input to the platform Config Merkle Tree —
// every field that affects container behaviour is measured and attested.
//
// # Manifest location
//
// The workload launcher reads the manifest from (in priority order):
//  1. Path specified via --manifest flag
//  2. /data/manifest.yaml (on the LUKS-encrypted data partition)
//  3. GCP instance metadata key "enclave-os-manifest" (base64-encoded)
//
// # Security model
//
// The manifest IS the authorization for what runs inside the VM. It is
// measured into the Config Merkle Tree, which is embedded in every RA-TLS
// certificate. Changing the manifest changes the Merkle root, causing
// clients pinning a known-good root to reject the connection.
package manifest

import (
	"crypto/sha256"
	"fmt"
	"os"
	"sort"

	"github.com/Privasys/enclave-os-virtual/internal/merkle"
	"gopkg.in/yaml.v3"
)

// Manifest is the top-level workload configuration.
type Manifest struct {
	// Version is the manifest schema version. Currently "1".
	Version string `yaml:"version"`

	// Platform contains platform-wide settings.
	Platform Platform `yaml:"platform"`

	// Containers is the list of OCI containers to run.
	Containers []Container `yaml:"containers"`
}

// Platform contains platform-level configuration.
type Platform struct {
	// Hostname is the VM's primary FQDN for the management API
	// (e.g. "v-fr-1.example.com").
	Hostname string `yaml:"hostname"`

	// CACertPath is the path to the PEM-encoded intermediary CA certificate.
	CACertPath string `yaml:"ca_cert"`

	// CAKeyPath is the path to the PEM-encoded intermediary CA private key.
	CAKeyPath string `yaml:"ca_key"`

	// AttestationServers is a list of attestation server URLs for remote
	// quote verification.  The list is hashed (sorted, newline-joined)
	// and published as OID 2.7 for verifier transparency.
	AttestationServers []string `yaml:"attestation_servers"`
}

// Container defines a single OCI container workload.
type Container struct {
	// Name is a unique identifier for this container (e.g. "postgres").
	Name string `yaml:"name"`

	// Image is the full OCI image reference WITH digest pinning.
	// Example: "ghcr.io/example/myapp@sha256:abc123..."
	// Tags without digest pins are rejected.
	Image string `yaml:"image"`

	// Hostname is the external FQDN for SNI routing, auto-derived by the
	// launcher: <name>.<machine_name>.<hostname>.
	// If empty, the container is internal-only (no external TLS).
	Hostname string `yaml:"hostname,omitempty"`

	// Port is the container's listening port that ra-tls-caddy will
	// reverse-proxy to.
	Port int `yaml:"port"`

	// Env is a map of environment variables passed to the container.
	// These are measured into the per-container Config Merkle Tree.
	Env map[string]string `yaml:"env,omitempty"`

	// Volumes is a list of host:container mount paths.
	Volumes []string `yaml:"volumes,omitempty"`

	// Command overrides the container's default entrypoint.
	Command []string `yaml:"command,omitempty"`

	// HealthCheck defines how to verify the container is ready.
	HealthCheck *HealthCheck `yaml:"health_check,omitempty"`

	// Internal marks this container as not externally accessible.
	// It will not get an RA-TLS certificate or Caddy route.
	Internal bool `yaml:"internal,omitempty"`

	// Storage is the requested size for a per-container encrypted volume
	// (e.g. "1G", "500M"). If non-empty the launcher provisions a
	// LUKS2+AEAD LV and bind-mounts it into the container at /data.
	// This field IS measured into the per-container Config Merkle Tree.
	Storage string `yaml:"storage,omitempty"`

	// Devices is a list of host device paths to pass into the container
	// (e.g. "/dev/nvidia0", "/dev/nvidiactl"). Each path must exist on
	// the host. This field IS measured into the per-container Config
	// Merkle Tree.
	Devices []string `yaml:"devices,omitempty"`
}

// HealthCheck defines a container health check.
type HealthCheck struct {
	// HTTP is an HTTP GET health check endpoint.
	HTTP string `yaml:"http,omitempty"`

	// TCP is a TCP port to connect to.
	TCP string `yaml:"tcp,omitempty"`

	// IntervalSeconds is the time between checks.
	IntervalSeconds int `yaml:"interval_seconds,omitempty"`

	// TimeoutSeconds is the maximum time to wait for a response.
	TimeoutSeconds int `yaml:"timeout_seconds,omitempty"`

	// Retries is the number of consecutive failures before unhealthy.
	Retries int `yaml:"retries,omitempty"`
}

// Load reads and parses a manifest from the given YAML file path.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: failed to read %q: %w", path, err)
	}
	return Parse(data)
}

// Parse parses a manifest from raw YAML bytes.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: failed to parse YAML: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate checks the manifest for required fields and consistency.
func (m *Manifest) Validate() error {
	if m.Version != "1" {
		return fmt.Errorf("manifest: unsupported version %q (expected \"1\")", m.Version)
	}
	if m.Platform.CACertPath == "" {
		return fmt.Errorf("manifest: platform.ca_cert is required")
	}
	if m.Platform.CAKeyPath == "" {
		return fmt.Errorf("manifest: platform.ca_key is required")
	}

	names := make(map[string]bool)
	hostnames := make(map[string]bool)
	for i, c := range m.Containers {
		if c.Name == "" {
			return fmt.Errorf("manifest: containers[%d].name is required", i)
		}
		if names[c.Name] {
			return fmt.Errorf("manifest: duplicate container name %q", c.Name)
		}
		names[c.Name] = true

		if c.Image == "" {
			return fmt.Errorf("manifest: containers[%d] (%s).image is required", i, c.Name)
		}

		if c.Hostname != "" {
			if hostnames[c.Hostname] {
				return fmt.Errorf("manifest: duplicate hostname %q", c.Hostname)
			}
			hostnames[c.Hostname] = true
		}

		if c.Port <= 0 || c.Port > 65535 {
			return fmt.Errorf("manifest: containers[%d] (%s).port must be 1-65535, got %d", i, c.Name, c.Port)
		}
	}
	return nil
}

// PlatformMerkleTree computes the platform-wide Config Merkle Tree from
// the manifest, CA certificate, and resolved container image digests.
//
// imageDigests maps container name → resolved SHA-256 digest bytes.
func (m *Manifest) PlatformMerkleTree(caCertDER []byte, imageDigests map[string][]byte) *merkle.Tree {
	var leaves []merkle.Leaf

	// Platform CA certificate.
	leaves = append(leaves, merkle.Leaf{
		Name: "platform.ca_cert",
		Data: caCertDER,
	})

	// Manifest hash (the full YAML, measuring all config choices).
	manifestYAML, _ := yaml.Marshal(m)
	leaves = append(leaves, merkle.Leaf{
		Name: "platform.manifest",
		Data: manifestYAML,
	})

	// Per-container image digests.
	for _, c := range m.Containers {
		digest, ok := imageDigests[c.Name]
		if !ok {
			continue
		}
		leaves = append(leaves, merkle.Leaf{
			Name: fmt.Sprintf("container.%s.image_digest", c.Name),
			Data: digest,
		})
	}

	return merkle.New(leaves)
}

// ContainerMerkleTree computes a per-container Config Merkle Tree for the
// given container, including its image digest, environment, and volumes.
func (c *Container) ContainerMerkleTree(imageDigest []byte) *merkle.Tree {
	var leaves []merkle.Leaf

	// Image digest.
	leaves = append(leaves, merkle.Leaf{
		Name: "container.image_digest",
		Data: imageDigest,
	})

	// Image reference.
	leaves = append(leaves, merkle.Leaf{
		Name: "container.image_ref",
		Data: []byte(c.Image),
	})

	// Environment variables (sorted for determinism).
	if len(c.Env) > 0 {
		keys := make([]string, 0, len(c.Env))
		for k := range c.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		h := sha256.New()
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte("="))
			h.Write([]byte(c.Env[k]))
			h.Write([]byte{0}) // null separator
		}
		leaves = append(leaves, merkle.Leaf{
			Name: "container.env_hash",
			Data: h.Sum(nil),
		})
	}

	// Volumes (sorted).
	if len(c.Volumes) > 0 {
		sortedVols := make([]string, len(c.Volumes))
		copy(sortedVols, c.Volumes)
		sort.Strings(sortedVols)

		h := sha256.New()
		for _, v := range sortedVols {
			h.Write([]byte(v))
			h.Write([]byte{0})
		}
		leaves = append(leaves, merkle.Leaf{
			Name: "container.volumes_hash",
			Data: h.Sum(nil),
		})
	}

	// Command.
	if len(c.Command) > 0 {
		h := sha256.New()
		for _, arg := range c.Command {
			h.Write([]byte(arg))
			h.Write([]byte{0})
		}
		leaves = append(leaves, merkle.Leaf{
			Name: "container.command_hash",
			Data: h.Sum(nil),
		})
	}

	// Container name.
	leaves = append(leaves, merkle.Leaf{
		Name: "container.name",
		Data: []byte(c.Name),
	})

	return merkle.New(leaves)
}

// CombinedImagesHash computes a single SHA-256 hash covering all container
// image digests (sorted by container name). This is the value embedded in
// OID 1.3.6.1.4.1.65230.2.5.
func CombinedImagesHash(containers []Container, imageDigests map[string][]byte) [32]byte {
	// Sort by name.
	sorted := make([]Container, len(containers))
	copy(sorted, containers)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	h := sha256.New()
	for _, c := range sorted {
		h.Write([]byte(c.Name))
		if d, ok := imageDigests[c.Name]; ok {
			h.Write(d)
		}
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}
