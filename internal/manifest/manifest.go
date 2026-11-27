// Package manifest defines a container workload as the launcher loads it,
// and the per-container Config Merkle Tree measured into its RA-TLS
// certificate: every field that affects the container's behaviour is
// measured and attested.
package manifest

import (
	"crypto/sha256"
	"sort"

	ratls "enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-os-virtual/internal/merkle"
)

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

	// Port is the container's listening port that Caddy will
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
	// NOT measured (capacity, not identity): only the injected /data
	// mount reaches the Config Merkle Tree, via Volumes.
	Storage string `yaml:"storage,omitempty"`

	// Devices is a list of host device paths to pass into the container
	// (e.g. "/dev/nvidia0", "/dev/nvidiactl"). Each path must exist on
	// the host. NOT currently measured into the Config Merkle Tree (see
	// ContainerMerkleTree for the measured set).
	Devices []string `yaml:"devices,omitempty"`

	// ResourceVCPUs / ResourceMemoryMB cap the container's CPU (CFS
	// quota) and memory (hard limit, MiB) — the Confidential-* instance
	// size chosen at deploy. Zero = unlimited. NOT measured: sizing is
	// capacity/cost, never workload identity, so a resize does not change
	// the attested container.
	ResourceVCPUs    int   `yaml:"resource_vcpus,omitempty"`
	ResourceMemoryMB int64 `yaml:"resource_memory_mb,omitempty"`

	// IngressAllowedCallers, when non-empty, enables ingress mutual RA-TLS for
	// this container: only callers whose attested identity (app-id OID 3.6,
	// measurement, and required OIDs) matches one of these entries may reach the
	// app. Every request is verified by the manager and annotated with
	// X-Privasys-Peer-* identity headers before it is proxied to the container.
	// This is the callee-side counterpart of a caller's egress dependency set,
	// reusing the byte-identical DependencySet shape. Manager-owned: the app can
	// never self-declare it (it is not sourced from the container's
	// /.well-known extensions), so the advertised and enforced sets are one.
	// NOT measured: whom an app is willing to accept is authorization policy,
	// set at deploy time, not workload code identity.
	IngressAllowedCallers *ratls.DependencySet `yaml:"ingress_allowed_callers,omitempty"`
	// IngressAllowedPlatforms is the owner's platform allow-list for those
	// callers (the machines their quotes may come from). An entry with
	// app_id "*" in IngressAllowedCallers admits ANY attested caller that
	// carries an app id, and is only honoured together with this list: the
	// app id is asserted by the caller's own runtime, so the platform is
	// what makes it trustworthy. Manager-owned and NOT measured, like the
	// caller set.
	IngressAllowedPlatforms []string `yaml:"ingress_allowed_platforms,omitempty"`

	// Dependencies is the container's set of DIRECT attested cross-enclave
	// dependencies (the egress counterpart of IngressAllowedCallers, same
	// DependencySet shape). When non-empty the manager stamps its canonical
	// encoding into the container's serving certificate at OID
	// 1.3.6.1.4.1.65230.6.1, so verifiers (wallet consent, dependents) read
	// the declared set off the attested leaf. Manager-owned: the platform
	// supplies it at deploy (or via the set-dependencies API) and the
	// issuance filter drops any self-declared 6.* extension, so the
	// advertised set and the platform-declared set are one object.
	// NOT measured into the config Merkle tree: like the WASM runtime's
	// 6.1 re-mint, a dependency change re-mints the leaf (wallets see a
	// dependency change and re-consent) without changing the container's
	// code identity — the identity FOLD computed by mgmt/wallets is what
	// makes deep dependency changes ripple.
	Dependencies *ratls.DependencySet `yaml:"dependencies,omitempty"`
}

// HealthCheck defines a container health check.
type HealthCheck struct {
	// HTTP is an HTTP GET health check endpoint.
	HTTP string `yaml:"http,omitempty" json:"http,omitempty"`

	// TCP is a TCP port to connect to.
	TCP string `yaml:"tcp,omitempty" json:"tcp,omitempty"`

	// IntervalSeconds is the time between checks.
	IntervalSeconds int `yaml:"interval_seconds,omitempty" json:"interval_seconds,omitempty"`

	// TimeoutSeconds is the maximum time to wait for a response.
	TimeoutSeconds int `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`

	// Retries is the number of consecutive failures before unhealthy.
	Retries int `yaml:"retries,omitempty" json:"retries,omitempty"`

	// ReadinessTimeoutSeconds bounds how long a freshly started container may
	// take to pass its FIRST health check. A container that never becomes
	// healthy within this window is stopped and removed, rather than being left
	// running while it probes a closed/wrong port forever — e.g. an app that
	// ignores the injected $PORT and binds a different one, which then collides
	// with co-located apps under host networking. Zero disables the deadline
	// (probe indefinitely; the prior behaviour). Not part of the measured
	// config (see ContainerMerkleTree), so it never changes attestation.
	ReadinessTimeoutSeconds int `yaml:"readiness_timeout_seconds,omitempty" json:"readiness_timeout_seconds,omitempty"`
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
// OID 1.3.6.1.4.1.65230.2.4.
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
