// Package launcher orchestrates the container workload lifecycle.
//
// Unlike the previous manifest-at-boot model, the launcher starts with
// zero containers and exposes methods for dynamic load/unload operations.
// This is how Enclave OS (Mini) works - containers are loaded at runtime
// via the management API.
//
// The boot sequence is now:
//
//  1. Manager starts, connects to containerd
//  2. Management API comes online (OIDC authentication)
//  3. Operator calls POST /api/v1/containers with a container spec
//  4. Launcher pulls image, verifies digest, starts container
//  5. Attestation Merkle trees are recomputed
//  6. Any RA-TLS certificate issued after this point includes the new state
//
// Authentication:
//
//   - All API requests require an OIDC bearer token with the appropriate
//     role (manager for mutations, monitoring for read-only).
package launcher

import (
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/caddy"
	"github.com/Privasys/enclave-os-virtual/internal/container"
	"github.com/Privasys/enclave-os-virtual/internal/extensions"
	"github.com/Privasys/enclave-os-virtual/internal/manifest"
	"github.com/Privasys/enclave-os-virtual/internal/merkle"
	"github.com/Privasys/enclave-os-virtual/internal/oids"
	"github.com/Privasys/enclave-os-virtual/internal/volume"

	"github.com/containerd/containerd/v2/client"
)

// Config holds the launcher configuration.
type Config struct {
	// ContainerdSocket is the containerd socket path (default: /run/containerd/containerd.sock).
	ContainerdSocket string

	// CaddyAdminAddr is the Caddy admin API address (e.g. "localhost:2019"
	// or "unix//run/caddy/admin.sock").
	CaddyAdminAddr string

	// CaddyListenAddr is the external HTTPS listen address for Caddy
	// (default: ":443").
	CaddyListenAddr string

	// ExtensionsDir is the directory where the launcher writes per-hostname
	// OID extension JSON files for ra-tls-caddy.  If empty, OID extensions
	// are not written and Caddy integration is disabled.
	ExtensionsDir string

	// MachineName is the instance machine name (e.g. "prod1").  Together
	// with Hostname it determines all RA-TLS hostnames:
	//   Manager:   manager.<MachineName>.<Hostname>
	//   Container: <name>.<MachineName>.<Hostname>
	MachineName string

	// Hostname is the domain suffix for RA-TLS hostnames
	// (e.g. "example.com").
	Hostname string

	// PlatformHostname is the computed FQDN for the management API route
	// in Caddy (manager.<MachineName>.<Hostname>).  Set by the caller.
	PlatformHostname string

	// ManagementPort is the local port for the management API
	// (default: "9443").  Caddy reverse-proxies to this port.
	ManagementPort string

	// CACertPath is the path to the PEM-encoded CA certificate for
	// platform attestation. Optional - if empty, the platform Merkle
	// tree will not include a CA cert leaf.
	CACertPath string

	// CAKeyPath is the intermediary CA private key for RA-TLS.
	CAKeyPath string

	// AttestationServers is a list of attestation server URLs for remote
	// quote verification.  The list is hashed (sorted, newline-joined,
	// SHA-256) into the platform Merkle tree and published as OID 2.7.
	//
	// Aligned with enclave-os-mini's attestation_servers configuration.
	AttestationServers []string

	// DEKOriginFile is the path to a file containing the data-encryption key
	// origin string ("external" or "enclave-generated").  Written by
	// luks-setup at boot.  If empty or the file does not exist, OID 2.6
	// is omitted from RA-TLS certificates (data partition is unencrypted).
	DEKOriginFile string
}

// LoadRequest is the API request to load a container.
type LoadRequest struct {
	// Name is a unique identifier for this container.
	Name string `json:"name"`

	// Image is the full OCI image reference WITH digest pinning.
	// Example: "ghcr.io/example/myapp@sha256:abc123..."
	Image string `json:"image"`

	// Port is the container's listening port.
	Port int `json:"port"`

	// Env is a map of environment variables.
	Env map[string]string `json:"env,omitempty"`

	// Volumes is a list of "host:container" mount paths.
	Volumes []string `json:"volumes,omitempty"`

	// Command overrides the container's default entrypoint.
	Command []string `json:"command,omitempty"`

	// Internal marks this container as not externally accessible.
	Internal bool `json:"internal,omitempty"`

	// HealthCheck defines how to verify the container is ready.
	HealthCheck *manifest.HealthCheck `json:"health_check,omitempty"`

	// VaultToken is an optional bearer token for authenticating to
	// vault instances. If set, it is injected as the VAULT_TOKEN
	// environment variable at container creation time.
	//
	// IMPORTANT: This field is a runtime secret and is deliberately
	// excluded from the per-container Config Merkle Tree. Changing
	// the vault token does not change the attested container identity.
	VaultToken string `json:"vault_token,omitempty"`

	// Storage is the requested size for a per-container encrypted volume
	// (e.g. "1G", "500M"). If non-empty a LUKS2+AEAD logical volume of
	// this size is created on the "containers" VG and bind-mounted into
	// the container at /data.
	//
	// This field IS measured into the per-container Merkle tree — changing
	// the storage size changes the attested container identity.
	Storage string `json:"storage,omitempty"`

	// StorageKey is the LUKS passphrase for the per-container volume.
	// If empty, a random 256-bit key is generated inside the enclave.
	//
	// IMPORTANT: This is a runtime secret and is deliberately excluded
	// from the per-container Config Merkle Tree.
	StorageKey string `json:"storage_key,omitempty"`
}

// Validate checks the load request for required fields.
func (r *LoadRequest) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if r.Image == "" {
		return fmt.Errorf("image is required")
	}
	if r.Port <= 0 || r.Port > 65535 {
		return fmt.Errorf("port must be 1-65535, got %d", r.Port)
	}
	return nil
}

// toContainerSpec converts a LoadRequest to a manifest.Container spec
// that the container manager understands.
//
// Note: VaultToken is deliberately NOT included here — it is a runtime
// secret that must not be measured into the Config Merkle Tree. It is
// injected separately at container creation time via runtimeEnv().
func (r *LoadRequest) toContainerSpec() manifest.Container {
	return manifest.Container{
		Name:        r.Name,
		Image:       r.Image,
		Port:        r.Port,
		Env:         r.Env,
		Volumes:     r.Volumes,
		Command:     r.Command,
		Internal:    r.Internal,
		HealthCheck: r.HealthCheck,
		Storage:     r.Storage,
	}
}

// runtimeEnv returns additional environment variables that should be
// injected at container creation time but NOT measured into attestation.
func (r *LoadRequest) runtimeEnv() map[string]string {
	env := make(map[string]string)
	if r.VaultToken != "" {
		env["VAULT_TOKEN"] = r.VaultToken
	}
	return env
}

// Launcher is the main workload orchestrator.
type Launcher struct {
	cfg Config
	log *zap.Logger
	mgr *container.Manager

	// caddyClient manages Caddy routes via the admin API.  Nil when
	// Caddy integration is disabled (no ExtensionsDir configured).
	caddyClient *caddy.Client

	// volMgr manages per-container encrypted volumes (LVM + LUKS2).
	// Nil when the "containers" VG is not available.
	volMgr *volume.Manager

	// Computed attestation data - recomputed on every load/unload.
	platformTree    *merkle.Tree
	containerTrees  map[string]*merkle.Tree
	imageDigests    map[string][]byte
	containerdHash  []byte
	combinedImgHash [32]byte

	// attestationServersHash is the SHA-256 of the canonical attestation
	// server URL list (sorted, newline-joined).  Nil-like (zero) when no
	// servers are configured.
	attestationServersHash [32]byte
	hasAttestationServers  bool

	// dekOrigin is the data-encryption key origin string ("byok:<fingerprint>"
	// or "generated").  Empty when the data partition is not encrypted.
	dekOrigin string

	// volumeEncryption tracks per-container volume encryption status.
	// Values: "byok:<fingerprint>" or "generated".  Absent when no volume.
	volumeEncryption map[string]string

	// Loaded container specs (mirrors what is running).
	specs map[string]manifest.Container

	// Runtime state.
	pulledImages map[string]client.Image

	mu sync.RWMutex
}

// New creates a new Launcher with the given config.
func New(cfg Config, log *zap.Logger) *Launcher {
	l := &Launcher{
		cfg:              cfg,
		log:              log.Named("launcher"),
		containerTrees:   make(map[string]*merkle.Tree),
		imageDigests:     make(map[string][]byte),
		pulledImages:     make(map[string]client.Image),
		specs:            make(map[string]manifest.Container),
		volumeEncryption: make(map[string]string),
	}

	// Compute attestation servers hash (sorted, newline-joined, SHA-256)
	// matching the canonical form used in enclave-os-mini.
	if len(cfg.AttestationServers) > 0 {
		sorted := make([]string, len(cfg.AttestationServers))
		copy(sorted, cfg.AttestationServers)
		sort.Strings(sorted)
		canonical := strings.Join(sorted, "\n")
		l.attestationServersHash = sha256.Sum256([]byte(canonical))
		l.hasAttestationServers = true
	}

	// Initialise per-container volume manager.
	vm := volume.NewManager(log)
	if vm.IsVGReady() {
		l.volMgr = vm
		l.log.Info("per-container encrypted volumes enabled (VG 'containers' found)")
	} else {
		l.log.Info("per-container encrypted volumes disabled (no VG 'containers')")
	}

	// Auto-detect TEE backend from hardware.
	backend := detectTEEBackend()
	log.Info("detected TEE backend", zap.String("backend", backend))

	// Initialise Caddy client when extensions_dir is configured.
	if cfg.ExtensionsDir != "" {
		caddyCfg := caddy.Config{
			AdminAddr:     cfg.CaddyAdminAddr,
			ListenAddr:    cfg.CaddyListenAddr,
			Backend:       backend,
			CACertPath:    cfg.CACertPath,
			CAKeyPath:     cfg.CAKeyPath,
			ExtensionsDir: cfg.ExtensionsDir,
		}
		l.caddyClient = caddy.NewClient(caddyCfg, log)
	}

	return l
}

// Run is the main entry point. It connects to containerd, computes initial
// (empty) attestation data, and blocks until shutdown.
func (l *Launcher) Run(ctx context.Context) error {
	// 1. Connect to containerd.
	l.log.Info("connecting to containerd")
	mgr, err := container.NewManager(l.log, l.cfg.ContainerdSocket)
	if err != nil {
		return err
	}
	defer mgr.Close()
	l.mgr = mgr

	// Get containerd version hash for OID 2.4.
	l.containerdHash, err = mgr.ContainerdVersionHash(ctx)
	if err != nil {
		return err
	}
	l.log.Info("containerd connected",
		zap.String("version_hash", hex.EncodeToString(l.containerdHash)),
	)

	// 1b. Read DEK origin if the LUKS setup service wrote one.
	if l.cfg.DEKOriginFile != "" {
		if raw, err := os.ReadFile(l.cfg.DEKOriginFile); err == nil {
			origin := strings.TrimSpace(string(raw))
			switch {
			case origin == "generated", strings.HasPrefix(origin, "byok:"):
				l.dekOrigin = origin
				l.log.Info("LUKS DEK origin loaded (OID 2.6)",
					zap.String("dek_origin", origin))
			default:
				l.log.Warn("ignoring unknown DEK origin value",
					zap.String("path", l.cfg.DEKOriginFile),
					zap.String("value", origin))
			}
		} else {
			l.log.Info("no DEK origin file found — data partition is not LUKS-encrypted",
				zap.String("path", l.cfg.DEKOriginFile))
		}
	}

	// 2. Compute initial attestation data (empty - no containers).
	l.recomputeAttestation()

	platformRoot := l.platformTree.Root()
	l.log.Info("manager ready (no containers loaded)",
		zap.String("platform_merkle_root", hex.EncodeToString(platformRoot[:])),
		zap.Int("attestation_servers", len(l.cfg.AttestationServers)),
		zap.String("machine_name", l.cfg.MachineName),
		zap.String("platform_hostname", l.cfg.PlatformHostname),
	)

	// 3. Set up Caddy routes if configured.
	if l.caddyClient != nil {
		// Write the platform OID extensions for the management API hostname.
		if err := l.writePlatformExtensions(); err != nil {
			return fmt.Errorf("launcher: failed to write platform extensions: %w", err)
		}

		// Register the management API route in Caddy.
		if l.cfg.PlatformHostname != "" {
			mgmtPort := l.cfg.ManagementPort
			if mgmtPort == "" {
				mgmtPort = "9443"
			}
			if err := l.caddyClient.AddRoute(l.cfg.PlatformHostname, "localhost:"+mgmtPort); err != nil {
				return fmt.Errorf("launcher: failed to add management API Caddy route: %w", err)
			}
			l.log.Info("management API route registered in Caddy",
				zap.String("hostname", l.cfg.PlatformHostname),
				zap.String("upstream", "localhost:"+mgmtPort))
		}
	}

	// 4. Wait for shutdown signal.
	return l.waitForShutdown(ctx)
}

// ContainerCount returns the number of running containers.
func (l *Launcher) ContainerCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.specs)
}

// CACertPath returns the configured path to the intermediary CA certificate.
func (l *Launcher) CACertPath() string {
	return l.cfg.CACertPath
}

// ReloadCA writes the new CA certificate and key to the configured paths,
// reloads the Caddy configuration so ra-tls-caddy picks up the new CA, and
// recomputes all attestation data (the platform Merkle tree includes the CA
// cert as a leaf, so changing it changes the attestation root).
func (l *Launcher) ReloadCA(certPEM, keyPEM []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Write certificate atomically (tmp + rename).
	if err := atomicWrite(l.cfg.CACertPath, certPEM); err != nil {
		return fmt.Errorf("launcher: failed to write CA cert: %w", err)
	}
	if err := atomicWrite(l.cfg.CAKeyPath, keyPEM); err != nil {
		return fmt.Errorf("launcher: failed to write CA key: %w", err)
	}

	l.log.Info("CA certificate updated, recomputing attestation",
		zap.String("cert_path", l.cfg.CACertPath),
		zap.String("key_path", l.cfg.CAKeyPath),
	)

	// Recompute all attestation (CA cert leaf changes).
	l.recomputeAttestation()

	// Reload Caddy so it picks up the new CA.
	if l.caddyClient != nil {
		if err := l.caddyClient.Reload(); err != nil {
			l.log.Warn("failed to reload Caddy after CA update (will use new CA on next route change)",
				zap.Error(err),
			)
		}
	}

	return nil
}

// atomicWrite writes data to a file atomically by writing to a temporary
// file in the same directory and renaming.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load pulls, verifies, and starts a container. Returns the resolved image
// digest. The caller is responsible for authentication.
func (l *Launcher) Load(ctx context.Context, req LoadRequest) ([]byte, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("launcher: invalid load request: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Check for duplicate name.
	if _, exists := l.specs[req.Name]; exists {
		return nil, fmt.Errorf("launcher: container %q already loaded", req.Name)
	}

	spec := req.toContainerSpec()

	// Auto-derive the external hostname from the machine name scheme:
	//   <name>.<machine_name>.<hostname>
	if !req.Internal && l.cfg.MachineName != "" {
		spec.Hostname = req.Name + "." + l.cfg.MachineName + "." + l.cfg.Hostname
	}

	// Check for duplicate hostname (should not happen with deterministic
	// derivation, but guard against name collisions).
	if spec.Hostname != "" {
		for _, s := range l.specs {
			if s.Hostname == spec.Hostname {
				return nil, fmt.Errorf("launcher: hostname %q already in use by %q", spec.Hostname, s.Name)
			}
		}
	}

	// Pull image.
	l.log.Info("pulling image",
		zap.String("name", req.Name),
		zap.String("image", req.Image),
		zap.String("hostname", spec.Hostname),
	)
	img, digest, err := l.mgr.Pull(ctx, spec)
	if err != nil {
		return nil, err
	}

	// Verify digest pin.
	if err := verifyPinnedDigest(req.Image, digest); err != nil {
		return nil, fmt.Errorf("launcher: %w", err)
	}
	l.log.Info("image verified",
		zap.String("name", req.Name),
		zap.String("digest", hex.EncodeToString(digest)),
	)

	// Provision per-container encrypted volume if requested.
	var volEncryption string
	if req.Storage != "" {
		if l.volMgr == nil {
			return nil, fmt.Errorf("launcher: encrypted storage requested but no 'containers' VG available")
		}
		vi, err := l.volMgr.Create(req.Name, req.Storage, req.StorageKey)
		if err != nil {
			return nil, fmt.Errorf("launcher: failed to create encrypted volume: %w", err)
		}
		volEncryption = vi.KeyOrigin
		// Auto-inject the volume mount: /run/containers/<name>:/data
		spec.Volumes = append(spec.Volumes, vi.MountPath+":/data")
	}

	// Start container. Inject runtime env vars (vault token etc.) into a
	// copy of the spec — these are NOT stored in l.specs and therefore NOT
	// included in the attestation Merkle tree.
	runtimeSpec := spec
	runtimeEnv := req.runtimeEnv()
	if len(runtimeEnv) > 0 {
		if runtimeSpec.Env == nil {
			runtimeSpec.Env = make(map[string]string, len(runtimeEnv))
		} else {
			// Clone the map so we don't mutate the original spec.
			clone := make(map[string]string, len(runtimeSpec.Env)+len(runtimeEnv))
			for k, v := range runtimeSpec.Env {
				clone[k] = v
			}
			runtimeSpec.Env = clone
		}
		for k, v := range runtimeEnv {
			runtimeSpec.Env[k] = v
		}
	}
	mc, err := l.mgr.Create(ctx, runtimeSpec, img)
	if err != nil {
		// Clean up volume if container creation fails.
		if req.Storage != "" && l.volMgr != nil {
			_ = l.volMgr.Remove(req.Name)
		}
		return nil, err
	}
	mc.ImageDigest = digest

	// Start health checks.
	l.mgr.StartHealthChecks(ctx, mc)

	// Record state.
	l.specs[req.Name] = spec
	l.pulledImages[req.Name] = img
	l.imageDigests[req.Name] = digest
	if volEncryption != "" {
		l.volumeEncryption[req.Name] = volEncryption
	}

	// Recompute attestation.
	l.recomputeAttestation()

	// Write OID extensions and register Caddy route.
	if l.caddyClient != nil {
		// Update the platform extensions (reflects new container set).
		if err := l.writePlatformExtensions(); err != nil {
			l.log.Warn("failed to update platform extensions", zap.Error(err))
		}

		// Write per-container extensions and add Caddy route if hostname is set.
		if spec.Hostname != "" && !req.Internal {
			if err := l.writeContainerExtensions(req.Name, spec.Hostname); err != nil {
				l.log.Warn("failed to write container extensions",
					zap.String("name", req.Name), zap.Error(err))
			}
			upstream := fmt.Sprintf("localhost:%d", req.Port)
			if err := l.caddyClient.AddRoute(spec.Hostname, upstream); err != nil {
				l.log.Warn("failed to add Caddy route",
					zap.String("hostname", spec.Hostname), zap.Error(err))
			}
		}
	}

	platformRoot := l.platformTree.Root()
	l.log.Info("container loaded",
		zap.String("name", req.Name),
		zap.String("image", req.Image),
		zap.String("digest", hex.EncodeToString(digest)),
		zap.String("platform_merkle_root", hex.EncodeToString(platformRoot[:])),
		zap.Int("total_containers", len(l.specs)),
	)

	return digest, nil
}

// Unload stops and removes a container, then recomputes attestation.
func (l *Launcher) Unload(ctx context.Context, name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.specs[name]; !exists {
		return fmt.Errorf("launcher: container %q not loaded", name)
	}

	// Remove Caddy route and extensions before cleaning state.
	removedSpec := l.specs[name]

	// Stop the container.
	if err := l.mgr.Stop(ctx, name); err != nil {
		return err
	}

	// Tear down per-container encrypted volume if one was provisioned.
	if l.volumeEncryption[name] != "" && l.volMgr != nil {
		if err := l.volMgr.Remove(name); err != nil {
			l.log.Warn("failed to remove encrypted volume (data may leak)",
				zap.String("container", name), zap.Error(err))
		}
	}

	// Clean up state.
	delete(l.specs, name)
	delete(l.pulledImages, name)
	delete(l.imageDigests, name)
	delete(l.containerTrees, name)
	delete(l.volumeEncryption, name)

	// Recompute attestation.
	l.recomputeAttestation()

	// Update Caddy configuration.
	if l.caddyClient != nil {
		// Update platform extensions (reflects removed container).
		if err := l.writePlatformExtensions(); err != nil {
			l.log.Warn("failed to update platform extensions", zap.Error(err))
		}

		// Remove per-container route and extensions.
		if removedSpec.Hostname != "" && !removedSpec.Internal {
			if err := l.caddyClient.RemoveRoute(removedSpec.Hostname); err != nil {
				l.log.Warn("failed to remove Caddy route",
					zap.String("hostname", removedSpec.Hostname), zap.Error(err))
			}
			if err := extensions.Remove(l.cfg.ExtensionsDir, removedSpec.Hostname); err != nil {
				l.log.Warn("failed to remove container extensions",
					zap.String("hostname", removedSpec.Hostname), zap.Error(err))
			}
		}
	}

	platformRoot := l.platformTree.Root()
	l.log.Info("container unloaded",
		zap.String("name", name),
		zap.String("platform_merkle_root", hex.EncodeToString(platformRoot[:])),
		zap.Int("total_containers", len(l.specs)),
	)

	return nil
}

// recomputeAttestation rebuilds all Merkle trees from current state.
// Must be called with l.mu held.
func (l *Launcher) recomputeAttestation() {
	// Read CA cert if configured.
	var caCertDER []byte
	if l.cfg.CACertPath != "" {
		var err error
		caCertDER, err = os.ReadFile(l.cfg.CACertPath)
		if err != nil {
			l.log.Warn("failed to read CA cert for merkle tree", zap.Error(err))
		}
	}

	// Build the list of containers in current state.
	containers := l.containerList()

	// Platform Merkle tree.
	var leaves []merkle.Leaf

	// CA certificate leaf.
	leaves = append(leaves, merkle.Leaf{
		Name: "platform.ca_cert",
		Data: caCertDER,
	})

	// Attestation servers (sorted, newline-joined canonical form).
	if l.hasAttestationServers {
		sorted := make([]string, len(l.cfg.AttestationServers))
		copy(sorted, l.cfg.AttestationServers)
		sort.Strings(sorted)
		canonical := strings.Join(sorted, "\n")
		leaves = append(leaves, merkle.Leaf{
			Name: "platform.attestation_servers",
			Data: []byte(canonical),
		})
	}

	// Per-container image digests.
	for _, c := range containers {
		digest := l.imageDigests[c.Name]
		leaves = append(leaves, merkle.Leaf{
			Name: fmt.Sprintf("container.%s.image_digest", c.Name),
			Data: digest,
		})
	}

	l.platformTree = merkle.New(leaves)

	// Per-container Merkle trees.
	for _, c := range containers {
		digest := l.imageDigests[c.Name]
		l.containerTrees[c.Name] = c.ContainerMerkleTree(digest)
	}

	// Combined images hash (OID 2.5).
	l.combinedImgHash = manifest.CombinedImagesHash(containers, l.imageDigests)
}

// containerList returns a slice of current container specs.
func (l *Launcher) containerList() []manifest.Container {
	result := make([]manifest.Container, 0, len(l.specs))
	for _, s := range l.specs {
		result = append(result, s)
	}
	return result
}

// PlatformExtensions returns the RA-TLS X.509 extensions for the
// platform-wide certificate.
func (l *Launcher) PlatformExtensions(quote []byte, quoteOID asn1.ObjectIdentifier) []pkix.Extension {
	l.mu.RLock()
	defer l.mu.RUnlock()

	root := l.platformTree.Root()
	var cdHash [32]byte
	copy(cdHash[:], l.containerdHash)
	var asHash *[32]byte
	if l.hasAttestationServers {
		asHash = &l.attestationServersHash
	}
	return oids.PlatformExtensions(quote, quoteOID, root, cdHash, l.combinedImgHash, l.dekOrigin, asHash)
}

// ContainerExtensions returns the RA-TLS X.509 extensions for a
// per-container leaf certificate.
func (l *Launcher) ContainerExtensions(containerName string) ([]pkix.Extension, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	tree, ok := l.containerTrees[containerName]
	if !ok {
		return nil, fmt.Errorf("launcher: container %q not found", containerName)
	}

	spec, ok := l.specs[containerName]
	if !ok {
		return nil, fmt.Errorf("launcher: container spec %q not found", containerName)
	}

	root := tree.Root()
	digest := l.imageDigests[containerName]
	volEnc := l.volumeEncryption[containerName]

	return oids.ContainerExtensions(root, digest, spec.Image, volEnc), nil
}

// StatusReport returns a summary of all containers and their health.
func (l *Launcher) StatusReport() []ContainerStatus {
	mgr := l.mgr
	if mgr == nil {
		return nil
	}
	containers := mgr.List()
	result := make([]ContainerStatus, 0, len(containers))
	for _, mc := range containers {
		result = append(result, ContainerStatus{
			Name:   mc.Name,
			Image:  mc.Spec.Image,
			Status: string(mc.GetStatus()),
		})
	}
	return result
}

// ContainerStatus is a JSON-serializable container status summary.
type ContainerStatus struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"`
}

// ---------------------------------------------------------------------------
// RA-TLS extension helpers
// ---------------------------------------------------------------------------

// writePlatformExtensions writes the platform-wide OID extensions to the
// extensions directory for the management API hostname.  These are read by
// ra-tls-caddy when issuing the platform RA-TLS certificate.
//
// Must be called with l.mu held (or at startup before concurrency).
func (l *Launcher) writePlatformExtensions() error {
	if l.cfg.ExtensionsDir == "" || l.cfg.PlatformHostname == "" {
		return nil
	}

	root := l.platformTree.Root()
	var cdHash [32]byte
	copy(cdHash[:], l.containerdHash)

	// Build the extensions list (without the quote — ra-tls-caddy adds that).
	exts := []pkix.Extension{
		oids.Extension(oids.PlatformConfigMerkleRoot, root[:]),
		oids.Extension(oids.RuntimeVersionHash, cdHash[:]),
		oids.Extension(oids.CombinedWorkloadsHash, l.combinedImgHash[:]),
	}
	if l.dekOrigin != "" {
		exts = append(exts, oids.Extension(oids.DataEncryptionKeyOrigin, []byte(l.dekOrigin)))
	}
	if l.hasAttestationServers {
		h := l.attestationServersHash
		exts = append(exts, oids.Extension(oids.AttestationServersHash, h[:]))
	}

	return extensions.Write(l.cfg.ExtensionsDir, l.cfg.PlatformHostname, exts)
}

// writeContainerExtensions writes the per-container OID extensions to the
// extensions directory.  These are read by ra-tls-caddy when issuing a
// per-container RA-TLS certificate.
//
// Must be called with l.mu held.
func (l *Launcher) writeContainerExtensions(containerName, hostname string) error {
	if l.cfg.ExtensionsDir == "" {
		return nil
	}

	tree, ok := l.containerTrees[containerName]
	if !ok {
		return fmt.Errorf("container %q has no Merkle tree", containerName)
	}

	spec, ok := l.specs[containerName]
	if !ok {
		return fmt.Errorf("container spec %q not found", containerName)
	}

	root := tree.Root()
	digest := l.imageDigests[containerName]
	volEnc := l.volumeEncryption[containerName]

	// Build the extensions list (without the quote — ra-tls-caddy adds that).
	exts := oids.ContainerExtensions(root, digest, spec.Image, volEnc)

	return extensions.Write(l.cfg.ExtensionsDir, hostname, exts)
}

func (l *Launcher) waitForShutdown(ctx context.Context) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		l.log.Info("received signal, shutting down", zap.String("signal", sig.String()))
	case <-ctx.Done():
		l.log.Info("context cancelled, shutting down")
	}

	// Graceful shutdown - stop all containers.
	l.mu.RLock()
	defer l.mu.RUnlock()

	l.mgr.StopAll(context.Background())
	l.log.Info("all containers stopped")
	return nil
}

// verifyPinnedDigest checks that the image reference includes a @sha256:
// digest pin and that the resolved digest matches.
func verifyPinnedDigest(imageRef string, resolvedDigest []byte) error {
	idx := -1
	for i := 0; i < len(imageRef); i++ {
		if imageRef[i] == '@' {
			idx = i
			break
		}
	}
	if idx < 0 || len(imageRef) < idx+8 || imageRef[idx:idx+8] != "@sha256:" {
		return fmt.Errorf("image %q is not digest-pinned (must contain @sha256:...)", imageRef)
	}
	pinnedHex := imageRef[idx+8:]
	pinnedBytes, err := hex.DecodeString(pinnedHex)
	if err != nil {
		return fmt.Errorf("image %q has invalid digest hex: %w", imageRef, err)
	}
	if len(pinnedBytes) != sha256.Size {
		return fmt.Errorf("image %q digest is not SHA-256 (got %d bytes)", imageRef, len(pinnedBytes))
	}

	if hex.EncodeToString(resolvedDigest) != hex.EncodeToString(pinnedBytes) {
		return fmt.Errorf("image %q: resolved digest %x does not match pinned %x",
			imageRef, resolvedDigest, pinnedBytes)
	}
	return nil
}

// detectTEEBackend auto-detects the Trusted Execution Environment from
// available hardware interfaces.  Returns "tdx" when /dev/tdx_guest exists,
// "sev-snp" when /dev/sev-guest exists, or "tdx" as default fallback.
func detectTEEBackend() string {
	if _, err := os.Stat("/dev/tdx_guest"); err == nil {
		return "tdx"
	}
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		return "sev-snp"
	}
	// Default to tdx — the most common deployment target.
	return "tdx"
}
