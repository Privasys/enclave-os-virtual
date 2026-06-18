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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"github.com/Privasys/enclave-os-virtual/internal/tpm"
	"github.com/Privasys/enclave-os-virtual/internal/vaultkey"
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
	// OID extension JSON files for Caddy's RA-TLS module. If empty, OID extensions
	// are not written and Caddy integration is disabled.
	ExtensionsDir string

	// MachineName is the instance machine name (e.g. "prod1").  Together
	// with Hostname it determines container RA-TLS hostnames:
	//   Container: <name>.<MachineName>.<Hostname>
	MachineName string

	// Hostname is the domain suffix for RA-TLS hostnames
	// (e.g. "example.com").
	Hostname string

	// PlatformHostname is the FQDN for the management API route in Caddy
	// (e.g. "v-fr-1.example.com").  Set by the caller via --platform-hostname.
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

	// ToolSpecMgmtURL, ToolSpecEnclaveID, ToolSpecEnclaveToken are used
	// to synthesise the per-container env vars TOOL_SPEC_URL +
	// TOOL_SPEC_TOKEN that the confidential-ai puller polls for the
	// fleet's MCP tool catalogue. When any of the three is empty the
	// env vars are not injected, and tool-using workloads will run with
	// an empty catalogue. Sourced from the manager's --mgmt-url /
	// --enclave-id / --enclave-token (i.e. /data/manager.env) — no
	// per-app config needed.
	ToolSpecMgmtURL      string
	ToolSpecEnclaveID    string
	ToolSpecEnclaveToken string

	// LoadToken, when non-empty, is injected as the per-container env
	// var LOAD_TOKEN. confidential-ai requires it as the Bearer
	// credential on /v1/models/{load,unload}; without it those
	// endpoints run in legacy-open mode and any sealed-session client
	// can unload the live model. Runtime secret: rides runtimeSpec.Env
	// (same channel as PRIVASYS_CONTAINER_TOKEN), never the attested
	// config Merkle tree. Sourced from the manager's --load-token
	// (i.e. /data/manager.env).
	LoadToken string
}

// ConfigAPISpec describes a post-load configuration endpoint that the
// runtime must call (or accept a call to) before unfreezing other
// paths. Sourced from a Dockerfile LABEL `org.privasys.config_api` (the
// container case) — these win because they are part of the
// measurement — with `privasys.json` as a fallback. When non-nil, the
// management API server returns HTTP 503 for every other (Method, Path)
// pair until a request matching this spec returns a 2xx.
type ConfigAPISpec struct {
	Method string `json:"method"` // e.g. "POST"
	Path   string `json:"path"`   // e.g. "/configure"
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

	// Volumes is a list of "host:container" mount paths.
	Volumes []string `json:"volumes,omitempty"`

	// Command overrides the container's default entrypoint.
	Command []string `json:"command,omitempty"`

	// Internal marks this container as not externally accessible.
	Internal bool `json:"internal,omitempty"`

	// HealthCheck defines how to verify the container is ready.
	HealthCheck *manifest.HealthCheck `json:"health_check,omitempty"`

	// Storage is the requested size for a per-container encrypted volume
	// (e.g. "1G", "500M"). If non-empty a LUKS2+AEAD logical volume of
	// this size is created on the "containers" VG and bind-mounted into
	// the container at /data.
	//
	// This field IS measured into the per-container Merkle tree — changing
	// the storage size changes the attested container identity.
	Storage string `json:"storage,omitempty"`

	// KeyHandle names the vault key holding (or reserved for) this
	// container's volume DEK, e.g.
	// "vault:apps.privasys.org/<app-id>/storage-kek/v1". When set, the
	// DEK is reconstructed from (or, on first boot, generated in-enclave
	// and filled into) the vault constellation — see internal/vaultkey.
	// The handle is not a secret; the platform never sees the DEK.
	// When empty and Storage is set, a throwaway DEK is generated
	// in-enclave (key_origin "generated"): the volume does not survive a
	// host reboot.
	KeyHandle string `json:"key_handle,omitempty"`

	// VaultEndpoints, VaultMrenclave and VaultAttestationServer address
	// and pin the vault constellation for KeyHandle resolution. Supplied
	// by the platform; untrusted (each vault is verified by attestation
	// at dial time, the MRENCLAVE pin and AS are part of what this VM
	// will accept, not secrets).
	VaultEndpoints          []string `json:"vault_endpoints,omitempty"`
	VaultMrenclave          string   `json:"vault_mrenclave,omitempty"`
	VaultAttestationServer  string   `json:"vault_attestation_server,omitempty"`

	// AppId is the platform-assigned app identity (apps.id, a UUID string). When
	// set, the manager stamps it (raw 16 bytes) at OID 3.6 on the vault client
	// identity, so an MR_APP-sealed key is bound to THIS app and a same-image peer
	// with a different app-id cannot unseal it (policies-plan.md). Empty keeps the
	// old MR_ENCLAVE behaviour (enclave + code digest only).
	AppId string `json:"app_id,omitempty"`

	// Hostname is the external FQDN for this container's Caddy route
	// and extension files. If set, it overrides the auto-derived
	// <name>.<machine_name>.<hostname> scheme. This should match the
	// gateway hostname (e.g. "myapp.apps.privasys.org").
	Hostname string `json:"hostname,omitempty"`

	// Devices is a list of host device paths to pass into the container
	// (e.g. "/dev/nvidia0"). Each path must exist on the host.
	Devices []string `json:"devices,omitempty"`

	// WaitReady, when true, causes Load() to block until the container's
	// health check endpoint returns 200.  This is intended for GPU/LLM
	// containers where the model takes several minutes to load and the
	// caller wants deployment to complete only when the service is ready.
	//
	// If HealthCheck is nil, this field is ignored.
	WaitReady bool `json:"wait_ready,omitempty"`

	// ConfigAPI, when non-nil, freezes all non-configure paths with HTTP
	// 503 until a request matching {Method, Path} returns 2xx. The flag
	// is in-process only; after a restart the container is frozen again.
	// The app's responsibility is to persist its config on the encrypted
	// volume and to re-deliver it via this endpoint after each restart.
	ConfigAPI *ConfigAPISpec `json:"config_api,omitempty"`
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
	if r.ConfigAPI != nil {
		if r.ConfigAPI.Path == "" {
			return fmt.Errorf("config_api.path is required")
		}
	}
	return nil
}

// toContainerSpec converts a LoadRequest to a manifest.Container spec
// that the container manager understands.
//
// Note: the vault addressing fields (KeyHandle, VaultEndpoints, ...)
// are deliberately NOT included here — they are deployment plumbing,
// not workload identity. The volume's key origin is attested
// separately via OID 3.4.
func (r *LoadRequest) toContainerSpec() manifest.Container {
	return manifest.Container{
		Name:        r.Name,
		Image:       r.Image,
		Port:        r.Port,
		Volumes:     r.Volumes,
		Command:     r.Command,
		Internal:    r.Internal,
		HealthCheck: r.HealthCheck,
		Storage:     r.Storage,
		Devices:     r.Devices,
	}
}

// parseAppID decodes a UUID string (with or without hyphens) into its raw 16
// bytes for the OID 3.6 app-id attestation extension. Returns nil for empty or
// malformed input, which leaves the vault identity in MR_ENCLAVE shape (enclave
// + code digest only) - the backward-compatible default before the platform
// starts sending app_id. See policies-plan.md.
func parseAppID(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return nil
	}
	return b
}

// runtimeEnv returns additional environment variables that should be
// injected at container creation time but NOT measured into attestation.
func (r *LoadRequest) runtimeEnv() map[string]string {
	return make(map[string]string)
}

// Launcher is the main workload orchestrator.
type Launcher struct {
	cfg Config
	log *zap.Logger
	mgr *container.Manager

	// caddyClient manages Caddy routes via the admin API.  Nil when
	// Caddy integration is disabled (no ExtensionsDir configured).
	caddyClient *caddy.Client

	// tpmExtender extends vTPM PCR 16 (RTMR[3]) with application-level
	// measurements on container load/unload. Nil-safe (no-ops when TPM
	// is unavailable).
	tpmExtender *tpm.Extender

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

	// attestationTokens holds optional Bearer tokens for each attestation
	// server URL.  Tokens are runtime secrets and are NOT hashed into the
	// Merkle tree — only the server URL list feeds OID 2.7.
	attestationTokens map[string]string

	// tokenSource provides dynamically refreshed tokens (OIDC bootstrap).
	// Takes precedence over attestationTokens when set.
	tokenSource TokenSource

	// appHostRouter, when non-nil, receives container Host→upstream
	// registrations so the manager API server can reverse-proxy app
	// traffic through the session-relay middleware.
	appHostRouter AppHostRouter

	// dekOrigin is the data-encryption key origin string
	// ("byok:<fingerprint>").  Empty when the data partition is not
	// encrypted.
	dekOrigin string

	// volumeEncryption tracks per-container volume encryption status.
	// Values: "byok:<fingerprint>" or "generated".  Absent when no volume.
	volumeEncryption map[string]string

	// persistentVolume marks containers whose encrypted volume is backed by
	// a vault key (the LoadRequest carried a KeyHandle). Such volumes are
	// LUKS-encrypted at rest with the DEK held in the vault constellation —
	// never on this box — so they MUST survive an unload/upgrade and be
	// reattached on the next load. Unload must NOT lvremove them (that would
	// destroy customer data on every stop). Ephemeral volumes (generated
	// in-enclave key, no handle) are removed on unload as before: their key
	// dies with the process, so a leftover LV would only block the next
	// load's reattach.
	persistentVolume map[string]bool

	// oidExts is the per-container set of X.509 attestation extensions
	// under 1.3.6.1.4.1.65230.3.5.* installed at Load time and updated
	// in-place via the SDK setAttestationExtension API. Map shape is
	// container-name → oid → raw value bytes (already base64-decoded).
	oidExts map[string]map[string][]byte

	// configAPI tracks the optional config-API decoration per container.
	// nil entries (or a missing key) mean the container is not frozen.
	configAPI map[string]*ConfigAPISpec

	// configured records whether the freeze gate has been opened for
	// each container. true when no ConfigAPI is set, or when a
	// matching successful call has been observed since (re)load.
	configured map[string]bool

	// billingFrozen tracks the host-driven billing freeze per container
	// (name → reason, e.g. "credits_exhausted"). A present entry means the
	// container's task is paused (cgroup freezer) and the manager returns 503
	// for its traffic. Independent of the config gate; set/cleared by the
	// management-service over the manager freeze endpoint. In-memory only —
	// re-asserted by the usage feed within one sweep after a restart.
	billingFrozen map[string]string

	// containerTokens maps container name → launcher-minted bearer
	// token. The token is injected into the container at start time as
	// PRIVASYS_CONTAINER_TOKEN and bound to the container's name (also
	// injected as PRIVASYS_CONTAINER_NAME). It is NOT an OIDC token —
	// it only serves to bind self-targeted manager API calls
	// (attestation-extensions, config-complete) to the calling
	// container's identity. Loopback-only enforcement in the manager.
	containerTokens map[string]string

	// Loaded container specs (mirrors what is running).
	specs map[string]manifest.Container

	// Runtime state.
	pulledImages map[string]client.Image

	// readyCh is closed by Run() once containerd is connected and l.mgr
	// is non-nil. Other components (notably the management API replay
	// path) call WaitReady() to avoid racing into Load() with a nil mgr.
	readyCh chan struct{}

	mu sync.RWMutex
}

// New creates a new Launcher with the given config.
func New(cfg Config, log *zap.Logger) *Launcher {
	l := &Launcher{
		cfg:               cfg,
		log:               log.Named("launcher"),
		containerTrees:    make(map[string]*merkle.Tree),
		imageDigests:      make(map[string][]byte),
		pulledImages:      make(map[string]client.Image),
		specs:             make(map[string]manifest.Container),
		volumeEncryption:  make(map[string]string),
		persistentVolume:  make(map[string]bool),
		oidExts:           make(map[string]map[string][]byte),
		configAPI:         make(map[string]*ConfigAPISpec),
		configured:        make(map[string]bool),
		billingFrozen:     make(map[string]string),
		containerTokens:   make(map[string]string),
		attestationTokens: make(map[string]string),
		readyCh:           make(chan struct{}),
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

	// Initialise TPM extender for RTMR[3] application measurements.
	l.tpmExtender = tpm.NewExtender(log)

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

	// Signal that l.mgr (and l.containerdHash) are now safe to read.
	// The management API's replay-from-registry path waits on this so it
	// doesn't dereference a nil l.mgr inside Load().
	close(l.readyCh)

	// 1b. Read DEK origin if the LUKS setup service wrote one.
	if l.cfg.DEKOriginFile != "" {
		if raw, err := os.ReadFile(l.cfg.DEKOriginFile); err == nil {
			origin := strings.TrimSpace(string(raw))
			switch {
			case strings.HasPrefix(origin, "byok:"):
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

		mgmtPort := l.cfg.ManagementPort
		if mgmtPort == "" {
			mgmtPort = "9443"
		}

		// Register the management API route in Caddy (named host route).
		// Kept for explicit logging and back-compat with old SNI values, but
		// the catch-all fallback below means an empty PlatformHostname is
		// fine — every TLS SNI now resolves to the management mux.
		if l.cfg.PlatformHostname != "" {
			if err := l.caddyClient.AddRoute(l.cfg.PlatformHostname, "localhost:"+mgmtPort); err != nil {
				return fmt.Errorf("launcher: failed to add management API Caddy route: %w", err)
			}
			l.log.Info("management API route registered in Caddy",
				zap.String("hostname", l.cfg.PlatformHostname),
				zap.String("upstream", "localhost:"+mgmtPort))
		}

		// Catch-all fallback so mgmt-service can connect by IP without
		// hitting Caddy's strict SNI host-matcher. The dispatcher in the
		// management mux is app-match-wins, so any SNI that doesn't match
		// a registered container app is routed to the platform API.
		if err := l.caddyClient.SetFallback("localhost:" + mgmtPort); err != nil {
			return fmt.Errorf("launcher: failed to set Caddy fallback: %w", err)
		}
		l.log.Info("management API catch-all fallback registered in Caddy",
			zap.String("upstream", "localhost:"+mgmtPort))
	}

	// 4. Wait for shutdown signal.
	return l.waitForShutdown(ctx)
}

// WaitReady blocks until Run() has connected to containerd and l.mgr is
// safe to use, or until ctx is done. Returns ctx.Err() if cancelled.
func (l *Launcher) WaitReady(ctx context.Context) error {
	select {
	case <-l.readyCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
// reloads the Caddy configuration so the RA-TLS module picks up the new CA, and
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

// TokenSource provides dynamic tokens for attestation servers.
// Used by the OIDC bootstrap manager to supply auto-refreshed tokens.
type TokenSource interface {
	Token(serverURL string) string
}

// AppHostRouter is implemented by the management API server. The launcher
// calls Register/Unregister so that container Host → loopback upstream
// mappings reach the same in-process router that owns the session-relay
// middleware. Caddy points every RA-TLS host (platform + container) at the
// manager port; the manager then dispatches by Host. See docs/ra-tls.md.
type AppHostRouter interface {
	RegisterAppHost(hostname, upstream string)
	UnregisterAppHost(hostname string)
}

// SetAppHostRouter wires the manager API server's host router. When set,
// container loads register their loopback upstream with it so traffic
// flows: Caddy → manager → container, instead of Caddy → container.
func (l *Launcher) SetAppHostRouter(r AppHostRouter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.appHostRouter = r
}

// SetTokenSource sets a dynamic token source that takes precedence over
// static tokens for attestation servers.
func (l *Launcher) SetTokenSource(ts TokenSource) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokenSource = ts
}

// AttestationServer represents an attestation server with an optional bearer
// token.  Mirrors the enclave-os-mini common::protocol::AttestationServer type.
type AttestationServer struct {
	URL   string `json:"url"`
	Token string `json:"token,omitempty"`
}

// SetAttestationServers replaces the attestation server list (URLs and
// optional bearer tokens) and recomputes the attestation hash + OID
// extensions so that the change is visible in subsequent RA-TLS certificates.
//
// Returns (server_count, hex-encoded hash of canonical URL list).
func (l *Launcher) SetAttestationServers(servers []AttestationServer) (int, string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Rebuild URL list and token map.
	urls := make([]string, 0, len(servers))
	tokens := make(map[string]string, len(servers))
	for _, s := range servers {
		urls = append(urls, s.URL)
		if s.Token != "" {
			tokens[s.URL] = s.Token
		}
	}
	l.cfg.AttestationServers = urls
	l.attestationTokens = tokens

	// Recompute hash.
	var hashHex string
	if len(urls) > 0 {
		sorted := make([]string, len(urls))
		copy(sorted, urls)
		sort.Strings(sorted)
		canonical := strings.Join(sorted, "\n")
		l.attestationServersHash = sha256.Sum256([]byte(canonical))
		l.hasAttestationServers = true
		hashHex = fmt.Sprintf("%x", l.attestationServersHash)
	} else {
		l.attestationServersHash = [32]byte{}
		l.hasAttestationServers = false
	}

	// Recompute Merkle tree + OID extensions so new certs reflect the change.
	l.recomputeAttestation()
	if err := l.writePlatformExtensions(); err != nil {
		l.log.Warn("failed to write platform extensions after attestation servers update", zap.Error(err))
	}

	l.log.Info("attestation servers updated",
		zap.Int("server_count", len(urls)),
		zap.String("hash", hashHex),
	)

	return len(urls), hashHex
}

// AttestationToken returns the bearer token for the given attestation server
// URL, or empty string if none is set.
//
// If a TokenSource is configured (via SetTokenSource), it takes precedence
// over the static attestationTokens map.
func (l *Launcher) AttestationToken(url string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.tokenSource != nil {
		if tok := l.tokenSource.Token(url); tok != "" {
			return tok
		}
	}
	return l.attestationTokens[url]
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

	// Digest-pinned disk:// refs survive in manager-apps.json across
	// image-disk rotations; when the pinned build's disk was detached,
	// re-pin to the newest attached disk of the same family so replay
	// self-heals instead of failing every boot. The rewritten (still
	// pinned) ref is what gets persisted and attested.
	if newRef, ok, fbErr := container.ResolveDiskFallback(req.Image); fbErr == nil && ok {
		l.log.Warn("pinned disk image missing; using same-family attached disk",
			zap.String("name", req.Name),
			zap.String("from", req.Image),
			zap.String("to", newRef),
		)
		req.Image = newRef
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Check for duplicate name.
	if _, exists := l.specs[req.Name]; exists {
		return nil, fmt.Errorf("launcher: container %q already loaded", req.Name)
	}

	spec := req.toContainerSpec()

	// Use the hostname from the deploy request for the Caddy route
	// and extension files (e.g. "myapp.apps.privasys.org").
	if req.Hostname != "" {
		spec.Hostname = req.Hostname
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

	// Check for duplicate host port. Containers share the host network
	// namespace, so two apps cannot both bind the same TCP port — if we
	// let a second Load through, the container would crash on bind and
	// the manager would be left with a STOPPED task and a dangling
	// in-memory spec. This bit us after an unattended VM restart where
	// the registry had two GPU apps both pinned to 8080.
	if req.Port > 0 {
		for _, s := range l.specs {
			if s.Port == req.Port {
				return nil, fmt.Errorf("launcher: host port %d already in use by %q", req.Port, s.Name)
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

	// Provision per-container encrypted volume if requested. With a
	// KeyHandle the DEK comes from (or, on first boot, is filled into)
	// the vault constellation, so the volume survives host reboots and
	// enclave upgrades without the platform ever seeing the key. Without
	// one, a throwaway in-enclave DEK is generated (volume dies with the
	// VM).
	var volEncryption string
	if req.Storage != "" {
		if l.volMgr == nil {
			return nil, fmt.Errorf("launcher: encrypted storage requested but no 'containers' VG available")
		}
		volumeKey := ""
		volOrigin := ""
		if req.KeyHandle != "" {
			keyHex, origin, err := vaultkey.ResolveOrProvision(ctx, l.log, vaultkey.Config{
				Endpoints:            req.VaultEndpoints,
				MrenclaveHex:         req.VaultMrenclave,
				AttestationServerURL: req.VaultAttestationServer,
				// The manager fetches the attestation-server bearer from
				// mgmt-service (it has no OIDC key); reuse the MGMT_URL +
				// ENCLAVE_ID + ENCLAVE_TOKEN it already holds for
				// runtime-status.
				MgmtURL:      l.cfg.ToolSpecMgmtURL,
				EnclaveID:    l.cfg.ToolSpecEnclaveID,
				EnclaveToken: l.cfg.ToolSpecEnclaveToken,
			}, req.KeyHandle, digest, parseAppID(req.AppId))
			if err != nil {
				return nil, fmt.Errorf("launcher: vault volume key: %w", err)
			}
			volumeKey = keyHex
			volOrigin = origin
		}
		vi, err := l.volMgr.Create(req.Name, req.Storage, volumeKey)
		if err != nil {
			return nil, fmt.Errorf("launcher: failed to create encrypted volume: %w", err)
		}
		volEncryption = vi.KeyOrigin
		if volOrigin != "" {
			// Attested key origin (OID 3.4): vault-backed, named handle.
			volEncryption = volOrigin
		}
		// Auto-inject the volume mount: /run/containers/<name>:/data
		spec.Volumes = append(spec.Volumes, vi.MountPath+":/data")
	}

	// Start container. Inject runtime env vars (vault token, manager
	// callback identity) into a copy of the spec — these are NOT stored
	// in l.specs and therefore NOT included in the attestation Merkle
	// tree.
	runtimeSpec := spec
	runtimeEnv := req.runtimeEnv()

	// Mint a per-container manager-callback token. Containers share
	// the host network namespace and reach the manager at
	// 127.0.0.1:9443; the token + name pair lets the manager bind
	// self-targeted calls (POST /api/v1/containers/{name}/...) to
	// the calling container's identity. The token is a runtime secret
	// (NOT in the attested spec).
	containerToken, err := mintContainerToken()
	if err != nil {
		// Never remove a vault-keyed (persistent) volume on cleanup — see below.
		if req.Storage != "" && l.volMgr != nil && req.KeyHandle == "" {
			_ = l.volMgr.Remove(req.Name)
		}
		return nil, fmt.Errorf("launcher: mint container token: %w", err)
	}
	if runtimeEnv == nil {
		runtimeEnv = make(map[string]string)
	}
	runtimeEnv["PRIVASYS_CONTAINER_NAME"] = req.Name
	runtimeEnv["PRIVASYS_CONTAINER_TOKEN"] = containerToken

	// PaaS port contract (12-factor): the management-service allocates a
	// unique port per app and routes Caddy -> localhost:req.Port. With host
	// networking the listen port IS the host port, so the app must bind the
	// port we hand it. Inject it as $PORT (platform value wins over any
	// app-declared PORT). Apps listen on os.Getenv("PORT"); see the
	// container build contract.
	if req.Port > 0 {
		runtimeEnv["PORT"] = fmt.Sprintf("%d", req.Port)
	}

	// Synthesise puller env vars when the manager itself knows where to
	// fetch tool specs from. Containers that don't care will ignore
	// these; confidential-ai picks them up via envOr("TOOL_SPEC_URL",...)
	// and starts polling the mgmt-service /api/v1/enclave/tool-spec
	// endpoint. Empty fallbacks intentionally — a missing piece (e.g.
	// pre-bootstrap manager.env) means the puller stays idle, which is
	// the same behaviour as before this wire-up.
	if l.cfg.ToolSpecMgmtURL != "" && l.cfg.ToolSpecEnclaveID != "" && l.cfg.ToolSpecEnclaveToken != "" {
		base := strings.TrimRight(l.cfg.ToolSpecMgmtURL, "/")
		runtimeEnv["TOOL_SPEC_URL"] = base + "/api/v1/enclave/tool-spec?enclave_id=" + l.cfg.ToolSpecEnclaveID
		runtimeEnv["TOOL_SPEC_TOKEN"] = l.cfg.ToolSpecEnclaveToken
		runtimeEnv["TOOL_SPEC_INTERVAL"] = "30s"
	}

	// Gate /v1/models/{load,unload}: confidential-ai requires LOAD_TOKEN
	// as Bearer auth when set; without it those endpoints are open to
	// any sealed-session client. Other workloads ignore the variable.
	if l.cfg.LoadToken != "" {
		runtimeEnv["LOAD_TOKEN"] = l.cfg.LoadToken
	}

	if len(runtimeEnv) > 0 {
		runtimeSpec.Env = make(map[string]string, len(runtimeEnv))
		for k, v := range runtimeEnv {
			runtimeSpec.Env[k] = v
		}
	}
	mc, err := l.mgr.Create(ctx, runtimeSpec, img)
	if err != nil {
		// Clean up the volume if container creation fails — but NEVER for a
		// vault-keyed volume. It holds customer data, is encrypted at rest,
		// and reattaches on the next load; lvremove'ing it here on a
		// transient failure (e.g. a stale containerd container) would destroy
		// that data. Ephemeral (no-handle) volumes are safe to remove.
		if req.Storage != "" && l.volMgr != nil && req.KeyHandle == "" {
			_ = l.volMgr.Remove(req.Name)
		}
		return nil, err
	}
	mc.ImageDigest = digest

	// Start health checks.
	// Use a background context: the request ctx is cancelled when the
	// HTTP handler returns, which would terminate the goroutine before
	// the first interval tick and leave the container stuck in "running"
	// state forever.
	l.mgr.StartHealthChecks(context.Background(), mc)

	// Record state.
	l.specs[req.Name] = spec
	l.pulledImages[req.Name] = img
	l.imageDigests[req.Name] = digest
	if volEncryption != "" {
		l.volumeEncryption[req.Name] = volEncryption
	}
	// A vault-keyed volume persists across unload/upgrade (see Unload).
	if req.KeyHandle != "" {
		l.persistentVolume[req.Name] = true
	}
	if req.ConfigAPI != nil {
		l.configAPI[req.Name] = req.ConfigAPI
		l.configured[req.Name] = false
	} else {
		l.configured[req.Name] = true
	}
	l.containerTokens[req.Name] = containerToken

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
			if err := l.writeContainerExtensions(req.Name, spec.Hostname, req.Port); err != nil {
				l.log.Warn("failed to write container extensions",
					zap.String("name", req.Name), zap.Error(err))
			}
			containerUpstream := fmt.Sprintf("localhost:%d", req.Port)
			// Route external TLS-terminated traffic to the manager so the
			// session-relay middleware can intercept sealed-CBOR requests
			// before they reach the container. Falls back to the container
			// upstream when no app-host router is wired (legacy path).
			caddyUpstream := containerUpstream
			if l.appHostRouter != nil {
				mgmtPort := l.cfg.ManagementPort
				if mgmtPort == "" {
					mgmtPort = "9443"
				}
				caddyUpstream = "localhost:" + mgmtPort
				l.appHostRouter.RegisterAppHost(spec.Hostname, containerUpstream)
			}
			if err := l.caddyClient.AddRoute(spec.Hostname, caddyUpstream); err != nil {
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

	// Tear down per-container encrypted volume if one was provisioned —
	// but NEVER for a vault-keyed (persistent) volume. Those hold customer
	// data, are LUKS-encrypted at rest, and have their DEK in the vault (not
	// on this box), so they must survive unload/upgrade and be reattached on
	// the next load. lvremove'ing one here would destroy customer data on
	// every stop/redeploy. The container manager has already closed the
	// dm-crypt mapping via Stop; leaving the encrypted LV in place is safe.
	if l.volumeEncryption[name] != "" && l.volMgr != nil {
		if l.persistentVolume[name] {
			l.log.Info("preserving vault-keyed volume across unload (data persists)",
				zap.String("container", name))
			if err := l.volMgr.Close(name); err != nil {
				l.log.Warn("failed to close persistent volume mapping",
					zap.String("container", name), zap.Error(err))
			}
		} else if err := l.volMgr.Remove(name); err != nil {
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
	delete(l.persistentVolume, name)
	delete(l.oidExts, name)
	delete(l.configAPI, name)
	delete(l.configured, name)
	delete(l.containerTokens, name)

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
			if l.appHostRouter != nil {
				l.appHostRouter.UnregisterAppHost(removedSpec.Hostname)
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

// TPMEvents returns the application event log for RTMR[3] replay verification.
func (l *Launcher) TPMEvents() []tpm.Event {
	return l.tpmExtender.Events()
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
		cs := ContainerStatus{
			Name:   mc.Name,
			Image:  mc.Spec.Image,
			Status: string(mc.GetStatus()),
		}
		progress := mc.GetPullProgress()
		if progress.TotalBytes > 0 {
			cs.PullProgress = &container.PullProgress{
				TotalBytes:      progress.TotalBytes,
				DownloadedBytes: progress.DownloadedBytes,
			}
		}
		result = append(result, cs)
	}
	return result
}

// ContainerStatus is a JSON-serializable container status summary.
type ContainerStatus struct {
	Name         string                 `json:"name"`
	Image        string                 `json:"image"`
	Status       string                 `json:"status"`
	PullProgress *container.PullProgress `json:"pull_progress,omitempty"`
}

// ---------------------------------------------------------------------------
// RA-TLS extension helpers
// ---------------------------------------------------------------------------

// writePlatformExtensions writes the platform-wide OID extensions to the
// extensions directory for the management API hostname.  These are read by
// Caddy's RA-TLS module when issuing the platform RA-TLS certificate.
//
// Must be called with l.mu held (or at startup before concurrency).
// imageProfilePath is the marker baked into the dm-verity-measured
// rootfs that records the image build flavor ("production" or "dev").
// Package variable so tests can point it at a fixture.
var imageProfilePath = "/etc/privasys/image-profile"

// imageProfile reads the baked image flavor. Returns "" when the marker
// is missing (images predating it); the OID 2.8 extension is then
// omitted and verifiers treat the image as legacy.
func imageProfile() string {
	b, err := os.ReadFile(imageProfilePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (l *Launcher) writePlatformExtensions() error {
	if l.cfg.ExtensionsDir == "" || l.cfg.PlatformHostname == "" {
		return nil
	}

	root := l.platformTree.Root()
	var cdHash [32]byte
	copy(cdHash[:], l.containerdHash)

	// Build the extensions list (without the quote - the RA-TLS module adds that).
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
	if p := imageProfile(); p != "" {
		exts = append(exts, oids.Extension(oids.ImageProfile, []byte(p)))
	}

	return extensions.Write(l.cfg.ExtensionsDir, l.cfg.PlatformHostname, exts, "")
}

// writeContainerExtensions writes the per-container OID extensions to the
// extensions directory. These are read by Caddy's RA-TLS module when
// issuing a per-container RA-TLS certificate. The upstream URL is included
// so it can pull dynamic OIDs from the container at cert time
// (the Virtual equivalent of enclave-os-mini's custom_oids() trait).
//
// Must be called with l.mu held.
func (l *Launcher) writeContainerExtensions(containerName, hostname string, port int) error {
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

	// Build the extensions list (without the quote - the RA-TLS module adds that).
	exts := oids.ContainerExtensions(root, digest, spec.Image, volEnc)

	// Per-app SDK-set X.509 attestation extensions (OIDs under
	// 1.3.6.1.4.1.65230.3.5.*). Sourced from the in-process oidExts
	// map (replayed at Load time and updated via the SDK
	// setAttestationExtension API).
	if oe := l.oidExts[containerName]; len(oe) > 0 {
		keys := make([]string, 0, len(oe))
		for k := range oe {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			oid, err := oids.ParseEnvVarOID(k)
			if err != nil {
				l.log.Warn("skipping oid extension with invalid OID",
					zap.String("container", containerName),
					zap.String("oid", k),
					zap.Error(err))
				continue
			}
			exts = append(exts, oids.Extension(oid, oe[k]))
		}
	}

	upstream := fmt.Sprintf("http://127.0.0.1:%d", port)
	return extensions.Write(l.cfg.ExtensionsDir, hostname, exts, upstream)
}

// AppHostnameToContainer returns the container name registered under
// the given external hostname (e.g. "myapp.apps.privasys.org" →
// "myapp"). Returns the empty string when no container matches.
func (l *Launcher) AppHostnameToContainer(hostname string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for name, spec := range l.specs {
		if strings.EqualFold(spec.Hostname, hostname) {
			return name
		}
	}
	return ""
}

// FreezeState describes whether the manager API server should hold a
// request for a given container. When ConfigAPI is non-nil and
// Configured is false, only requests matching ConfigAPI may pass — the
// rest receive HTTP 503.
type FreezeState struct {
	ConfigAPI  *ConfigAPISpec
	Configured bool
	// BillingFrozen is the host-driven billing freeze (credits exhausted),
	// independent of the config gate. When set, the container task is paused
	// and the manager returns 503 (BillingReason) for its traffic.
	BillingFrozen bool
	BillingReason string
}

// ContainerFreezeState reports the current freeze state for the given
// container. An unknown container returns the zero value (no freeze).
func (l *Launcher) ContainerFreezeState(name string) FreezeState {
	l.mu.RLock()
	defer l.mu.RUnlock()
	reason, billingFrozen := l.billingFrozen[name]
	return FreezeState{
		ConfigAPI:     l.configAPI[name],
		Configured:    l.configured[name],
		BillingFrozen: billingFrozen,
		BillingReason: reason,
	}
}

// SetBillingFrozen applies or lifts the host-driven billing freeze for a
// container. Freezing pauses the container task (cgroup freezer) so it stops
// consuming CPU while keeping its state, and makes the manager return 503 for
// its traffic; unfreezing resumes it. Idempotent — only pauses/resumes on a
// real transition. Errors roll the in-memory flag back so the next sweep retries.
func (l *Launcher) SetBillingFrozen(ctx context.Context, name string, frozen bool, reason string) error {
	l.mu.Lock()
	if _, ok := l.specs[name]; !ok {
		l.mu.Unlock()
		return fmt.Errorf("container %q not loaded", name)
	}
	prevReason, already := l.billingFrozen[name]
	if frozen == already {
		l.mu.Unlock()
		return nil // no transition
	}
	if frozen {
		l.billingFrozen[name] = reason
	} else {
		delete(l.billingFrozen, name)
	}
	mgr := l.mgr
	l.mu.Unlock()

	if mgr == nil {
		return fmt.Errorf("container runtime not ready")
	}
	var opErr error
	if frozen {
		opErr = mgr.Pause(ctx, name)
	} else {
		opErr = mgr.Resume(ctx, name)
	}
	if opErr != nil {
		l.mu.Lock()
		if frozen {
			delete(l.billingFrozen, name)
		} else if already {
			l.billingFrozen[name] = prevReason
		}
		l.mu.Unlock()
	}
	return opErr
}

// MarkConfigured flips the in-process freeze flag for the given
// container to true. The manager API server calls this after observing
// a 2xx response on a request matching the container's ConfigAPI.
// No-op when the container is not loaded or already configured.
func (l *Launcher) MarkConfigured(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.specs[name]; !ok {
		return
	}
	l.configured[name] = true
}

// LookupContainerByToken returns the container name that matches the
// given launcher-minted callback token, or empty string if no match.
// Used by the manager middleware to bind self-targeted manager API
// calls to a specific container identity (loopback only).
func (l *Launcher) LookupContainerByToken(token string) string {
	if token == "" {
		return ""
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for name, t := range l.containerTokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			return name
		}
	}
	return ""
}

// mintContainerToken returns a fresh 32-byte hex-encoded random token.
func mintContainerToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// SetAttestationExtension installs (or updates) a per-app X.509
// attestation extension under the 1.3.6.1.4.1.65230.3.5.* arc and
// rewrites the container's extensions file so the next RA-TLS cert
// reflects the new value. The OID is validated; the value is treated
// as opaque bytes (no hashing — the SDK is expected to pass either
// raw public values or pre-hashed digests).
func (l *Launcher) SetAttestationExtension(name, oid string, value []byte) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if _, err := oids.ParseEnvVarOID(oid); err != nil {
		return fmt.Errorf("oid: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	spec, ok := l.specs[name]
	if !ok {
		return fmt.Errorf("container %q not loaded", name)
	}
	if l.oidExts[name] == nil {
		l.oidExts[name] = make(map[string][]byte)
	}
	l.oidExts[name][oid] = value
	if l.caddyClient != nil && spec.Hostname != "" && !spec.Internal {
		if err := l.writeContainerExtensions(name, spec.Hostname, spec.Port); err != nil {
			return fmt.Errorf("rewrite extensions: %w", err)
		}
	}
	return nil
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
