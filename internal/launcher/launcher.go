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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
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
	"github.com/Privasys/enclave-os-virtual/internal/network"
	"github.com/Privasys/enclave-os-virtual/internal/oids"
	"github.com/Privasys/enclave-os-virtual/internal/sessionrelay"
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

	// KeyHandle names the vault key holding this container's volume DEK,
	// e.g. "apps.privasys.org/<app-id>/storage-kek/v1". When set, the DEK is
	// reconstructed from (or, on first boot, generated in-enclave and created
	// on) the vault constellation — see internal/vaultkey. The handle is not a
	// secret; the platform never sees the DEK. When empty and Storage is set, a
	// throwaway DEK is generated in-enclave (key_origin "generated"): the volume
	// does not survive a host reboot.
	KeyHandle string `json:"key_handle,omitempty"`

	// KeyCreationGrant is the platform-minted grant (JWT) the TEE presents to
	// create the key on first boot (scoped to apps.privasys.org/<app-id>, bound
	// to this TEE's attested app-id). Only needed on first boot; ignored once
	// the key exists.
	KeyCreationGrant string `json:"key_creation_grant,omitempty"`

	// VaultEndpoints, VaultMrenclave and VaultAttestationServer address
	// and pin the vault constellation for KeyHandle resolution. Supplied
	// by the platform; untrusted (each vault is verified by attestation
	// at dial time, the MRENCLAVE pin and AS are part of what this VM
	// will accept, not secrets).
	VaultEndpoints         []string `json:"vault_endpoints,omitempty"`
	VaultMrenclave         string   `json:"vault_mrenclave,omitempty"`
	VaultAttestationServer string   `json:"vault_attestation_server,omitempty"`

	// RegistrySecretHandle names a vault key holding the pull credential for a
	// PRIVATE image, e.g. "users/<sub>/registry-creds/<name>". When set, the
	// manager exports the credential from the constellation (the owner's key
	// policy must grant THIS manager measurement ExportKey) and uses it to pull
	// the image — so a customer's private image bytes and its pull token never
	// leave the TEE. Resolved against the same Vault* addressing above. Empty =
	// an anonymous (public) pull, the existing behaviour. Not a secret; never
	// measured (deployment plumbing, like the other vault addressing).
	RegistrySecretHandle string `json:"registry_secret_handle,omitempty"`

	// SessionRelayKeyHandle names the vault key holding the platform
	// session-relay identity key (enc_pub), e.g.
	// "apps.privasys.org/<app-id>/session-encpub/<meas>". When set, the
	// manager reconstructs it from (or, on first boot, generates + creates
	// on) the constellation under a NON-PROMOTABLE, platform-measurement-
	// pinned policy and installs it as the session-relay identity key, so
	// enc_pub is stable across same-measurement restarts and rotates only
	// on a platform upgrade (enc-pub-plan.md, Sc 2). Resolved against the
	// same Vault* addressing above, presenting this app's id (OID 3.6) and
	// image digest; the policy omits the image digest, so it survives app
	// upgrades. Empty keeps the legacy ephemeral key (restart forces
	// re-auth). Fail-safe: a resolve error keeps the ephemeral key.
	SessionRelayKeyHandle string `json:"session_relay_key_handle,omitempty"`

	// SessionRelayKeyGrant is the platform-minted grant (JWT) for creating
	// SessionRelayKeyHandle on first boot (non-promotable policy; scoped to
	// apps.privasys.org/<app-id>). Only needed on first boot; ignored once
	// the key exists.
	SessionRelayKeyGrant string `json:"session_relay_key_grant,omitempty"`

	// AppId is the platform-assigned app identity (apps.id, a UUID string). When
	// set, the manager stamps it (raw 16 bytes) at OID 3.6 on the vault client
	// identity, so an MR_APP-sealed key is bound to THIS app and a same-image peer
	// with a different app-id cannot unseal it (the MR_APP / promote-step-up design). Empty keeps the
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

	// Owners is the per-app owners team (platform OIDC subs), the
	// TRANSITIONAL fallback for the configure-authz gate: the manager
	// admits a configure caller whose verified sub is on this list when
	// the token carries no per-app config role yet. Primary authz is the
	// <audience>:app:<hex>:owner|admin role on the caller's token; this
	// list goes away once the IdP role backfill is verified. Persisted
	// with the registry entry like every other LoadRequest field.
	Owners []string `json:"owners,omitempty"`
}

// reservedHostPort is the platform's own host port (the management proxy /
// runtime-status feed). Containers run with host networking, so a container's
// listen port IS the host port; an app that binds 8080 collides with the
// platform and crash-loops co-located apps (this is what took down the KYC
// enclave). The management-service allocates a unique port per app from the
// 10000-32000 range and injects it as $PORT — apps must listen on that, never
// a fixed 8080.
const reservedHostPort = 8080

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
	if r.Port == reservedHostPort {
		return fmt.Errorf("port %d is reserved for the platform; the app must "+
			"listen on the injected $PORT (allocated from 10000-32000), not a fixed 8080", r.Port)
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
		HealthCheck: rewriteHealthCheckHost(r.HealthCheck, r.Port),
		Storage:     r.Storage,
		Devices:     r.Devices,
	}
}

// rewriteHealthCheckHost retargets a control-plane health check (sent as
// localhost:<port>, from the host-networking era) at the container's private
// bridge IP (#45). The manager probes from the host netns, so it must dial
// <container-ip>:<port>, not localhost. Returns a copy; nil in → nil out.
func rewriteHealthCheckHost(hc *manifest.HealthCheck, port int) *manifest.HealthCheck {
	if hc == nil || port <= 0 {
		return hc
	}
	ip := network.ContainerIP(port)
	repl := func(s string) string {
		s = strings.ReplaceAll(s, "127.0.0.1", ip)
		s = strings.ReplaceAll(s, "localhost", ip)
		return s
	}
	out := *hc
	out.HTTP = repl(out.HTTP)
	out.TCP = repl(out.TCP)
	return &out
}

// parseAppID decodes a UUID string (with or without hyphens) into its raw 16
// bytes for the OID 3.6 app-id attestation extension. Returns nil for empty or
// malformed input, which leaves the vault identity in MR_ENCLAVE shape (enclave
// + code digest only) - the backward-compatible default before the platform
// starts sending app_id. See the MR_APP / promote-step-up design.
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
	appIDs          map[string][]byte // container name → raw 16-byte app id (OID 3.6)
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

	// srKeyMu guards srKeyResolved, the set of Hosts whose session-relay
	// identity key (enc_pub) has been resolved + installed from the vault.
	// Keyed by Host so each app is resolved independently; an entry is added
	// only on a successful install, so a transient vault failure retries on
	// the next Load (enc-pub-plan.md, Sc 2).
	srKeyMu       sync.Mutex
	srKeyResolved map[string]bool

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
	// Guarded by freezeMu (NOT l.mu): Statuses() must stay readable while
	// Load holds l.mu across a multi-minute image import — the status
	// endpoint previously blocked for the whole load and the control
	// plane read the enclave as unreachable.
	configAPI map[string]*ConfigAPISpec

	// configured records whether the freeze gate has been opened for
	// each container. true when no ConfigAPI is set, or when a
	// matching successful call has been observed since (re)load.
	// Guarded by freezeMu.
	configured map[string]bool

	// configOwners is the per-container owners team from the load
	// envelope — the configure-authz gate's transitional sub-list
	// fallback (primary authz is the per-app config role on the caller's
	// token). Guarded by freezeMu, like configAPI.
	configOwners map[string][]string

	// freezeMu guards configAPI + configured. Always acquired AFTER l.mu
	// when both are held (writers inside Load/Unload); Statuses takes it
	// alone.
	freezeMu sync.RWMutex

	// failures records why a container load failed, keyed by name, so the
	// control plane sees status=failed + a reason instead of the container
	// silently vanishing from the status list (a failed pull removes the
	// containerd stub). Cleared on the next successful Load or an Unload.
	// Guarded by failMu (standalone).
	failMu   sync.Mutex
	failures map[string]string

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

	// desiredImages returns the image refs of EVERY app the manager intends
	// to run (its full registry), independent of load order. The image GC
	// (PruneImages, before each pull) must keep these, or a concurrent replay
	// — apps load in parallel goroutines — would prune a not-yet-loaded app's
	// cached image, forcing a re-pull that, on a full disk, hangs forever
	// (the 2026-07-09 m1-tdx-france self-inflicted wedge). Nil = keep only
	// currently-loaded specs (dev/test).
	desiredImages func() []string

	// readyCh is closed by Run() once containerd is connected and l.mgr
	// is non-nil. Other components (notably the management API replay
	// path) call WaitReady() to avoid racing into Load() with a nil mgr.
	readyCh chan struct{}

	mu sync.RWMutex
}

// SetDesiredImages wires a provider for the full set of image refs the manager
// intends to run (its registry). Used by the image GC so a concurrent replay
// never prunes an app's cached image before that app has loaded.
func (l *Launcher) SetDesiredImages(fn func() []string) {
	l.mu.Lock()
	l.desiredImages = fn
	l.mu.Unlock()
}

// New creates a new Launcher with the given config.
func New(cfg Config, log *zap.Logger) *Launcher {
	l := &Launcher{
		cfg:               cfg,
		log:               log.Named("launcher"),
		containerTrees:    make(map[string]*merkle.Tree),
		imageDigests:      make(map[string][]byte),
		appIDs:            make(map[string][]byte),
		pulledImages:      make(map[string]client.Image),
		specs:             make(map[string]manifest.Container),
		volumeEncryption:  make(map[string]string),
		persistentVolume:  make(map[string]bool),
		oidExts:           make(map[string]map[string][]byte),
		configAPI:         make(map[string]*ConfigAPISpec),
		configured:        make(map[string]bool),
		configOwners:      make(map[string][]string),
		failures:          make(map[string]string),
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

// MarkFailed sets a container's status to "failed" and records why. Load
// registers a "pulling" stub before the network pull; if Load later errors
// (e.g. the vault DEK reconstruction fails), the stub would otherwise stay
// "pulling" forever — or, when the failed pull removed the stub entirely,
// the container would vanish from status reports and the control plane
// would blindly auto-redeploy in a loop. The failure record keeps a
// synthetic failed entry (with the reason) in Statuses either way; prod
// enclaves expose no journal, so this is the operator's only error channel.
func (l *Launcher) MarkFailed(name, reason string) {
	l.failMu.Lock()
	l.failures[name] = reason
	l.failMu.Unlock()
	if l.mgr == nil {
		return
	}
	if mc, ok := l.mgr.Get(name); ok {
		mc.SetFailure(reason)
	}
}

// clearFailure drops a recorded load failure (on successful Load/Unload).
func (l *Launcher) clearFailure(name string) {
	l.failMu.Lock()
	delete(l.failures, name)
	l.failMu.Unlock()
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
	// SetSessionRelayIdentityKeySeed installs the vault-resolved
	// session-relay identity key (enc_pub) for an app's Host from its
	// 32-byte seed, so that app's enc_pub is stable across same-measurement
	// restarts (enc-pub-plan.md, Sc 2). The launcher resolves it on the
	// container Load that carries a session-relay handle and hands the
	// (host, seed) to the manager. Each app has its own enc_pub.
	SetSessionRelayIdentityKeySeed(host string, seed []byte) error

	// SetExpectedWorkloadDigest arms the per-app workload-digest wake for a
	// Host (enc-pub-plan.md, Sc 1): a silent-rebind voucher whose field-4
	// digest doesn't match this app's measurement is rejected, so an app
	// code/config change wakes the user. The launcher computes the digest
	// from the container's stamped OID values on Load.
	SetExpectedWorkloadDigest(host string, digest [32]byte)
}

// SetAppHostRouter wires the manager API server's host router. When set,
// container loads register their loopback upstream with it so traffic
// flows: Caddy → manager → container, instead of Caddy → container.
func (l *Launcher) SetAppHostRouter(r AppHostRouter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.appHostRouter = r
}

// resolveSessionRelayKey reconstructs (or, on first boot, provisions) THIS
// app's session-relay identity key (enc_pub) from the constellation and
// installs it on the manager under the app's Host, so the app's enc_pub is
// stable across same-measurement restarts and rotates only on a platform
// upgrade (enc-pub-plan.md, Sc 2).
//
// It reuses req's vault addressing + this app's attested identity (image
// digest + app-id): the key's policy pins the platform measurement and the
// app-id but OMITS the image digest, so it survives app-code upgrades.
// Resolved once per Host (each app independently); best-effort, so any
// failure keeps the host's ephemeral key and the worst case is today's
// behaviour (a restart forces a re-auth for that app).
func (l *Launcher) resolveSessionRelayKey(ctx context.Context, req LoadRequest, host string, imageDigest []byte) {
	if req.SessionRelayKeyHandle == "" || l.appHostRouter == nil || host == "" {
		return
	}
	l.srKeyMu.Lock()
	if l.srKeyResolved == nil {
		l.srKeyResolved = make(map[string]bool)
	}
	done := l.srKeyResolved[host]
	l.srKeyMu.Unlock()
	if done {
		return
	}

	seedHex, _, _, err := vaultkey.ResolveOrProvision(ctx, l.log, vaultkey.Config{
		Endpoints:            req.VaultEndpoints,
		MrenclaveHex:         req.VaultMrenclave,
		AttestationServerURL: req.VaultAttestationServer,
		MgmtURL:              l.cfg.ToolSpecMgmtURL,
		EnclaveID:            l.cfg.ToolSpecEnclaveID,
		EnclaveToken:         l.cfg.ToolSpecEnclaveToken,
	}, req.SessionRelayKeyHandle, req.SessionRelayKeyGrant, imageDigest, parseAppID(req.AppId))
	if err != nil {
		l.log.Warn("session-relay identity key: vault resolve failed; keeping ephemeral key (restarts force re-auth)",
			zap.String("host", host), zap.String("handle", req.SessionRelayKeyHandle), zap.Error(err))
		return
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		l.log.Warn("session-relay identity key: bad seed encoding; keeping ephemeral key", zap.Error(err))
		return
	}
	if err := l.appHostRouter.SetSessionRelayIdentityKeySeed(host, seed); err != nil {
		l.log.Warn("session-relay identity key: install failed; keeping ephemeral key", zap.Error(err))
		return
	}
	l.srKeyMu.Lock()
	l.srKeyResolved[host] = true
	l.srKeyMu.Unlock()
}

// armSessionRelayWorkloadDigest computes this container's workload digest
// (voucher field 4) from the SAME OID values stamped into its RA-TLS leaf and
// arms the manager's per-app check, so an app code/config change wakes the
// user (enc-pub-plan.md, Sc 1). The value encodings match the wallet's RA-TLS
// parser byte-for-byte (auth/wallet .../oid-digest.ts, native parser uses
// hex::encode for 3.1/3.2 and the raw UTF-8 string for 3.3/3.4), and the KAT
// (sessionrelay/workload_digest_test.go ↔ wallet jest) pins the serialisation.
//
// LOCKING: the caller (Load) already holds l.mu for writing. This reads the
// launcher maps directly and MUST NOT re-acquire l.mu — sync.RWMutex is not
// reentrant, so a writer taking the read lock blocks forever, wedging every
// subsequent Load/Unload behind the held write lock (it presents as the host
// silently refusing to bring up any app with a public hostname).
func (l *Launcher) armSessionRelayWorkloadDigest(containerName, host string) {
	if l.appHostRouter == nil || host == "" {
		return
	}
	// NB: l.mu is held for writing by the caller — do not RLock here.
	spec, ok := l.specs[containerName]
	imageDigest := l.imageDigests[containerName]
	volEnc := l.volumeEncryption[containerName]
	if !ok || len(imageDigest) == 0 {
		return
	}
	// Compute the config-merkle root (OID 3.1) directly from the spec — the
	// SAME computation oids.ContainerExtensions / recomputeAttestation use
	// (Container.ContainerMerkleTree). Do NOT read l.containerTrees here: on
	// Load it is only populated by recomputeAttestation, which runs before this
	// container is in containerList(), so the lookup misses and Sc 1 never arms.
	root := spec.ContainerMerkleTree(imageDigest).Root()
	// Match oids.ContainerExtensions: the leaf carries the image ref with any
	// @sha256:… suffix stripped (the digest is at OID 3.2).
	imageRef := spec.Image
	if i := strings.Index(imageRef, "@"); i >= 0 {
		imageRef = imageRef[:i]
	}
	digest := sessionrelay.WorkloadDigest(map[string]string{
		sessionrelay.WorkloadConfigMerkleRoot: hex.EncodeToString(root[:]),
		sessionrelay.WorkloadCodeHash:         hex.EncodeToString(imageDigest),
		sessionrelay.WorkloadImageRef:         imageRef,
		sessionrelay.WorkloadKeySource:        volEnc,
	})
	l.appHostRouter.SetExpectedWorkloadDigest(host, digest)
	l.log.Info("session-relay workload-digest wake armed",
		zap.String("host", host), zap.String("workload_digest", hex.EncodeToString(digest[:])))
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

	// For a private image, export the pull credential from the owner's vault
	// FIRST (the requested digest is known from the pinned ref, so we can stamp
	// this TEE's vault identity before the pull). The credential is reconstructed
	// in-TEE and used only to authenticate the pull; the host and the platform
	// never see it.
	var regAuth *container.RegistryAuth
	if req.RegistrySecretHandle != "" {
		reqDigest, derr := pinnedDigestBytes(req.Image)
		if derr != nil {
			return nil, fmt.Errorf("launcher: %w", derr)
		}
		credBytes, err := vaultkey.Export(ctx, l.log, vaultkey.Config{
			Endpoints:            req.VaultEndpoints,
			MrenclaveHex:         req.VaultMrenclave,
			AttestationServerURL: req.VaultAttestationServer,
			MgmtURL:              l.cfg.ToolSpecMgmtURL,
			EnclaveID:            l.cfg.ToolSpecEnclaveID,
			EnclaveToken:         l.cfg.ToolSpecEnclaveToken,
		}, req.RegistrySecretHandle, reqDigest, parseAppID(req.AppId))
		if err != nil {
			return nil, fmt.Errorf("launcher: registry credential: %w", err)
		}
		regAuth, err = parseRegistryAuth(credBytes)
		if err != nil {
			return nil, fmt.Errorf("launcher: registry credential: %w", err)
		}
		l.log.Info("private image: pull credential fetched from vault",
			zap.String("name", req.Name), zap.String("handle", req.RegistrySecretHandle))
	}

	// Reclaim disk BEFORE pulling: the containerd image store lives on the
	// small persistent /data PD, images from every previously-deployed app
	// version accumulate with no host to prune from, and a full store hangs
	// the pull at "pulling" forever (2026-07-09 m1-tdx-france wedge). Keep the
	// image about to be pulled, every currently-loaded container's image, AND
	// every image in the manager's registry (`desiredImages`) — the last is
	// essential because replay loads apps CONCURRENTLY, so pruning on only the
	// specs loaded so far would evict a sibling app's cached image mid-replay
	// and, on a full disk, that re-pull never completes. Best-effort — a
	// running image refuses delete and is skipped. (l.mu is held.)
	keep := map[string]bool{req.Image: true}
	for _, s := range l.specs {
		keep[s.Image] = true
	}
	if l.desiredImages != nil {
		for _, img := range l.desiredImages() {
			keep[img] = true
		}
	}
	if n, perr := l.mgr.PruneImages(ctx, keep); perr != nil {
		l.log.Warn("image prune before pull failed (continuing)", zap.Error(perr))
	} else if n > 0 {
		l.log.Info("pruned unused images before pull", zap.Int("removed", n))
	}

	// Pull image.
	l.log.Info("pulling image",
		zap.String("name", req.Name),
		zap.String("image", req.Image),
		zap.String("hostname", spec.Hostname),
	)
	img, digest, err := l.mgr.Pull(ctx, spec, regAuth)
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
		volReconstructed := false
		if req.KeyHandle != "" {
			keyHex, origin, reconstructed, err := vaultkey.ResolveOrProvision(ctx, l.log, vaultkey.Config{
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
			}, req.KeyHandle, req.KeyCreationGrant, digest, parseAppID(req.AppId))
			if err != nil {
				return nil, fmt.Errorf("launcher: vault volume key: %w", err)
			}
			volumeKey = keyHex
			volOrigin = origin
			volReconstructed = reconstructed
		}
		vi, err := l.volMgr.Create(req.Name, req.Storage, volumeKey, volReconstructed)
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
	// Manager callback URL. Under the per-container netns model (#45) the
	// container can no longer reach the manager at 127.0.0.1:9443 (that is now
	// its OWN private loopback); it reaches it at the bridge gateway. The SDK
	// reads PRIVASYS_MANAGER_URL and MUST be rebuilt into app images before this
	// runtime ships — an image with the old hard-coded 127.0.0.1:9443 fallback
	// will not reach the manager once it is in its own netns.
	runtimeEnv["PRIVASYS_MANAGER_URL"] = network.ManagerURL()
	// The platform-assigned app id (apps.id). Apps that authenticate to the vault
	// as themselves use it to ask the platform to delegate key ops to their TEE.
	if req.AppId != "" {
		runtimeEnv["PRIVASYS_APP_ID"] = req.AppId
	}
	// The verified image digest (hex SHA-256) — the same value attested at
	// OID 3.2. Lets an app stamp its own measurement into artifacts it signs
	// (e.g. the identity verifier's IVR) without a self-attestation
	// round-trip; clients can cross-check it against the RA-TLS leaf.
	runtimeEnv["PRIVASYS_IMAGE_DIGEST"] = hex.EncodeToString(digest)

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
	//
	// The readiness-timeout callback fully unloads a container that never
	// becomes healthy (frees its host port, drops its Caddy route + registry
	// entry), so an app that ignores $PORT can't linger and collide.
	name := req.Name
	l.mgr.StartHealthChecks(context.Background(), mc, func() {
		if err := l.Unload(context.Background(), name); err != nil {
			l.log.Warn("readiness-timeout unload failed",
				zap.String("name", name), zap.Error(err))
		}
	})

	// Record state.
	l.specs[req.Name] = spec
	l.pulledImages[req.Name] = img
	l.imageDigests[req.Name] = digest
	if appID := parseAppID(req.AppId); appID != nil {
		l.appIDs[req.Name] = appID
	}
	if volEncryption != "" {
		l.volumeEncryption[req.Name] = volEncryption
	}
	// A vault-keyed volume persists across unload/upgrade (see Unload).
	if req.KeyHandle != "" {
		l.persistentVolume[req.Name] = true
	}
	l.freezeMu.Lock()
	if req.ConfigAPI != nil {
		l.configAPI[req.Name] = req.ConfigAPI
		l.configured[req.Name] = false
	} else {
		l.configured[req.Name] = true
	}
	l.configOwners[req.Name] = req.Owners
	l.freezeMu.Unlock()
	l.clearFailure(req.Name)
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
			// The container now lives in its own netns on a private bridge IP
			// (bugs-and-fixes #45), so the manager reverse-proxies to
			// <container-ip>:<port> instead of localhost:<port>.
			containerUpstream := fmt.Sprintf("%s:%d", network.ContainerIP(req.Port), req.Port)
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
				// The manager now binds on the bridge gateway (not localhost),
				// so Caddy (host netns) reaches it at <gateway>:<mgmtPort>.
				caddyUpstream = network.GatewayIP + ":" + mgmtPort
				l.appHostRouter.RegisterAppHost(spec.Hostname, containerUpstream)
				// Resolve THIS app's session-relay identity key (enc_pub) and
				// install it under its Host, reusing the app's vault addressing +
				// attested identity. Best-effort: a failure keeps the host's
				// ephemeral key (enc-pub-plan.md, Sc 2).
				l.resolveSessionRelayKey(ctx, req, spec.Hostname, digest)
				// Arm the per-app workload-digest wake (Sc 1): a voucher whose
				// field-4 digest no longer matches this app's measurement is
				// rejected, so an app code/config change re-prompts the user.
				l.armSessionRelayWorkloadDigest(req.Name, spec.Hostname)
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

	// Capture the image before clearing state so we can reclaim its disk once
	// it is no longer referenced (unload = delete intent; this also frees the
	// previous version's image on every upgrade).
	unloadedImg := l.pulledImages[name]

	// Clean up state.
	delete(l.specs, name)
	delete(l.pulledImages, name)
	delete(l.imageDigests, name)
	delete(l.appIDs, name)
	delete(l.containerTrees, name)
	delete(l.volumeEncryption, name)
	delete(l.persistentVolume, name)
	delete(l.oidExts, name)
	l.freezeMu.Lock()
	delete(l.configAPI, name)
	delete(l.configured, name)
	delete(l.configOwners, name)
	l.freezeMu.Unlock()
	l.clearFailure(name)
	delete(l.containerTokens, name)

	// Garbage-collect the image if no other loaded container references it.
	// Frees disk on the enclave so old/abandoned images do not accumulate.
	if unloadedImg != nil && l.mgr != nil {
		ref := unloadedImg.Name()
		stillUsed := false
		for _, img := range l.pulledImages {
			if img != nil && img.Name() == ref {
				stillUsed = true
				break
			}
		}
		if !stillUsed {
			if err := l.mgr.RemoveImage(ctx, ref); err != nil {
				l.log.Warn("failed to remove unreferenced image", zap.String("image", ref), zap.Error(err))
			} else {
				l.log.Info("removed unreferenced image after unload", zap.String("container", name), zap.String("image", ref))
			}
		}
	}

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

// RotatePhase selects which half of an online KEK rotation to run.
type RotatePhase string

const (
	// RotatePhaseAdd adds the new key to a free LUKS keyslot. After it, BOTH
	// the old and new vault DEKs unlock the volume — the caller advances the
	// app's key-handle pointer here, while either still works.
	RotatePhaseAdd RotatePhase = "add"
	// RotatePhaseRetire kills the slot holding the old DEK, after the pointer
	// has been advanced to the new handle.
	RotatePhaseRetire RotatePhase = "retire"
)

// RotateRequest drives one phase of an online volume-key rotation. The vault
// addressing fields mirror LoadRequest's: deployment plumbing the platform
// re-supplies, untrusted (each vault is verified by attestation at dial time),
// never secret. See the key-rotation design.
type RotateRequest struct {
	Name      string      `json:"name"`
	Phase     RotatePhase `json:"phase"`
	OldHandle string      `json:"old_handle"`
	NewHandle string      `json:"new_handle"`

	// Vault addressing for the OLD handle (the constellation the volume's
	// current DEK lives on).
	VaultEndpoints         []string `json:"vault_endpoints,omitempty"`
	VaultMrenclave         string   `json:"vault_mrenclave,omitempty"`
	VaultAttestationServer string   `json:"vault_attestation_server,omitempty"`

	// Vault addressing for the NEW handle. Empty = same constellation as the old
	// (intra-constellation KEK rotation). Set to a DIFFERENT constellation to
	// migrate the volume key across constellations without re-encrypting data
	// (graceful vault rotation): the add phase reconstructs the old DEK from the
	// old constellation and provisions the new DEK on the new one, so both open
	// the volume across the pointer flip. See the enclave-upgrade plan, OPEN
	// DESIGN — graceful constellation migration.
	NewVaultEndpoints         []string `json:"new_vault_endpoints,omitempty"`
	NewVaultMrenclave         string   `json:"new_vault_mrenclave,omitempty"`
	NewVaultAttestationServer string   `json:"new_vault_attestation_server,omitempty"`

	// NewKeyCreationGrant is the grant the TEE presents to create the NEW
	// generation's key during the "add" phase.
	NewKeyCreationGrant string `json:"new_key_creation_grant,omitempty"`

	AppId string `json:"app_id,omitempty"`
}

// RotateVolumeKey performs one phase of a vault-key (KEK) rotation on a
// running, vault-backed container's encrypted volume. It re-wraps the LUKS2
// master key under a new vault generation; the data on disk never moves and the
// volume stays mounted (online). The two phases bracket the platform's
// key-handle pointer advance so a crash mid-rotation always leaves the volume
// openable (see the key-rotation design):
//
//	add    : reconstruct the OLD DEK + provision the NEW DEK from the
//	         constellation, then luksAddKey the new slot (both keys now open).
//	retire : reconstruct the OLD DEK and luksRemoveKey its slot (new only).
//
// The container must be loaded: rotation needs its live image digest to stamp
// the vault client identity (OID 3.2/3.6) so the constellation authorises this
// measurement to export the DEK.
func (l *Launcher) RotateVolumeKey(ctx context.Context, req RotateRequest) error {
	if l.volMgr == nil {
		return fmt.Errorf("launcher: rotate: no 'containers' VG; volume key rotation unavailable")
	}
	if req.Name == "" {
		return fmt.Errorf("launcher: rotate: name is required")
	}
	if req.OldHandle == "" {
		return fmt.Errorf("launcher: rotate: old_handle is required")
	}
	if req.Phase == RotatePhaseAdd && req.NewHandle == "" {
		return fmt.Errorf("launcher: rotate: new_handle is required for the add phase")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.persistentVolume[req.Name] {
		return fmt.Errorf("launcher: rotate: %q is not a loaded vault-backed app", req.Name)
	}
	digest := l.imageDigests[req.Name]
	if len(digest) == 0 {
		return fmt.Errorf("launcher: rotate: no image digest recorded for %q", req.Name)
	}
	appID := parseAppID(req.AppId)
	mkCfg := func(endpoints []string, mrenclave, attServer string) vaultkey.Config {
		return vaultkey.Config{
			Endpoints:            endpoints,
			MrenclaveHex:         mrenclave,
			AttestationServerURL: attServer,
			MgmtURL:              l.cfg.ToolSpecMgmtURL,
			EnclaveID:            l.cfg.ToolSpecEnclaveID,
			EnclaveToken:         l.cfg.ToolSpecEnclaveToken,
		}
	}
	oldCfg := mkCfg(req.VaultEndpoints, req.VaultMrenclave, req.VaultAttestationServer)
	// The new handle's constellation: distinct fields when migrating across
	// constellations, else the same set as the old (intra-constellation rotate).
	newEndpoints, newMre, newAtt := req.NewVaultEndpoints, req.NewVaultMrenclave, req.NewVaultAttestationServer
	if len(newEndpoints) == 0 {
		newEndpoints, newMre, newAtt = req.VaultEndpoints, req.VaultMrenclave, req.VaultAttestationServer
	}
	newCfg := mkCfg(newEndpoints, newMre, newAtt)

	switch req.Phase {
	case RotatePhaseAdd:
		oldDEK, _, _, err := vaultkey.ResolveOrProvision(ctx, l.log, oldCfg, req.OldHandle, "", digest, appID)
		if err != nil {
			return fmt.Errorf("launcher: rotate add: reconstruct old key: %w", err)
		}
		newDEK, newOrigin, _, err := vaultkey.ResolveOrProvision(ctx, l.log, newCfg, req.NewHandle, req.NewKeyCreationGrant, digest, appID)
		if err != nil {
			return fmt.Errorf("launcher: rotate add: provision new key: %w", err)
		}
		if err := l.volMgr.AddKey(req.Name, oldDEK, newDEK); err != nil {
			return fmt.Errorf("launcher: rotate add: %w", err)
		}
		// The new handle is now a live keyslot; reflect it as the volume's
		// attested key origin (OID 3.4) for the running app.
		l.volumeEncryption[req.Name] = newOrigin
		l.recomputeAttestation()
		if spec, ok := l.specs[req.Name]; ok && l.caddyClient != nil && spec.Hostname != "" && !spec.Internal {
			if err := l.writeContainerExtensions(req.Name, spec.Hostname, spec.Port); err != nil {
				l.log.Warn("rotate add: rewrite extensions failed", zap.String("name", req.Name), zap.Error(err))
			}
		}
		l.log.Info("volume key rotation: new slot added", zap.String("name", req.Name), zap.String("new_handle", req.NewHandle))
		return nil

	case RotatePhaseRetire:
		oldDEK, _, _, err := vaultkey.ResolveOrProvision(ctx, l.log, oldCfg, req.OldHandle, "", digest, appID)
		if err != nil {
			return fmt.Errorf("launcher: rotate retire: reconstruct old key: %w", err)
		}
		if err := l.volMgr.RemoveKey(req.Name, oldDEK); err != nil {
			return fmt.Errorf("launcher: rotate retire: %w", err)
		}
		l.log.Info("volume key rotation: old slot retired", zap.String("name", req.Name), zap.String("old_handle", req.OldHandle))
		return nil

	default:
		return fmt.Errorf("launcher: rotate: unknown phase %q", req.Phase)
	}
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
//
// Deliberately does NOT take l.mu: Load holds it across a multi-minute
// image import, and the status endpoint blocking for that long made the
// control plane read the enclave as unreachable. The container list and
// the freeze/failure maps each have their own locks.
func (l *Launcher) StatusReport() []ContainerStatus {
	mgr := l.mgr
	if mgr == nil {
		return nil
	}
	containers := mgr.List()
	l.freezeMu.RLock()
	defer l.freezeMu.RUnlock()
	l.failMu.Lock()
	defer l.failMu.Unlock()
	seen := make(map[string]bool, len(containers))
	result := make([]ContainerStatus, 0, len(containers))
	for _, mc := range containers {
		seen[mc.Name] = true
		cs := ContainerStatus{
			Name:           mc.Name,
			Image:          mc.Spec.Image,
			Status:         string(mc.GetStatus()),
			Error:          mc.GetFailure(),
			AwaitingConfig: l.configAPI[mc.Name] != nil && !l.configured[mc.Name],
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
	// A failed pull removes the containerd stub, so the container would
	// otherwise vanish from this report and the control plane would loop
	// on blind auto-redeploys. Surface a synthetic failed entry with the
	// recorded reason instead.
	for name, reason := range l.failures {
		if !seen[name] {
			result = append(result, ContainerStatus{
				Name:   name,
				Status: string(container.StatusFailed),
				Error:  reason,
			})
		}
	}
	return result
}

// ContainerStatus is a JSON-serializable container status summary.
type ContainerStatus struct {
	Name         string                  `json:"name"`
	Image        string                  `json:"image"`
	Status       string                  `json:"status"`
	PullProgress *container.PullProgress `json:"pull_progress,omitempty"`
	// Error carries the load-failure reason when Status is "failed" —
	// prod enclaves expose no journal, so this is the operator's only
	// error channel.
	Error string `json:"error,omitempty"`
	// AwaitingConfig is true when the container declares a configure gate and
	// has not yet been configured (the freeze gate returns 503 for all
	// non-configure traffic). Lets the control plane surface a "Frozen" state.
	AwaitingConfig bool `json:"awaiting_config,omitempty"`
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

	// The RA-TLS Caddy module fetches /.well-known/attestation-extensions from
	// this upstream; the container is on its private bridge IP now (#45).
	upstream := fmt.Sprintf("http://%s:%d", network.ContainerIP(port), port)
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
	// AppID and Owners feed the configure-authz gate: AppID (the platform
	// apps.id from the load envelope) composes the per-app config role the
	// caller's token must carry; Owners is the transitional sub-list
	// fallback. Both come from the persisted LoadRequest.
	AppID  string
	Owners []string
}

// ContainerFreezeState reports the current freeze state for the given
// container. An unknown container returns the zero value (no freeze).
func (l *Launcher) ContainerFreezeState(name string) FreezeState {
	l.mu.RLock()
	reason, billingFrozen := l.billingFrozen[name]
	appID := ""
	if raw := l.appIDs[name]; len(raw) > 0 {
		appID = hex.EncodeToString(raw) // undashed lowercase, the OID 3.6 / role encoding
	}
	l.mu.RUnlock()
	l.freezeMu.RLock()
	defer l.freezeMu.RUnlock()
	return FreezeState{
		ConfigAPI:     l.configAPI[name],
		Configured:    l.configured[name],
		BillingFrozen: billingFrozen,
		BillingReason: reason,
		AppID:         appID,
		Owners:        l.configOwners[name],
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
	l.freezeMu.Lock()
	l.configured[name] = true
	l.freezeMu.Unlock()
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

// MintVaultIdentity mints a one-shot RA-TLS vault client identity for the named
// container, bound to the vault's challenge nonce, and returns it PEM-encoded
// (cert + key). The manager calls this after authenticating the caller's
// container token, so the app id stamped is the one the platform assigned to
// that container — an app cannot mint another app's identity. This is the same
// identity the launcher mints for the per-app data key.
func (l *Launcher) MintVaultIdentity(name string, challenge, channelBinder []byte) (certPEM, keyPEM []byte, err error) {
	l.mu.RLock()
	digest := l.imageDigests[name]
	appID := l.appIDs[name]
	l.mu.RUnlock()
	if len(digest) == 0 {
		return nil, nil, fmt.Errorf("launcher: unknown container %q", name)
	}
	cert, err := vaultkey.MintIdentity(challenge, channelBinder, digest, appID)
	if err != nil {
		return nil, nil, err
	}
	return vaultkey.EncodeIdentityPEM(cert)
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
		// Reload Caddy so the RA-TLS module re-reads the extension file and
		// the NEXT leaf carries the new OID. Writing the file alone is not
		// enough — the module reads it when the route is added (at Load), so a
		// post-Load SetAttestationExtension (e.g. the identity-verifier
		// publishing its trust-anchor hash at /configure) never reached the
		// leaf. Same pattern as the CA-update path.
		if err := l.caddyClient.Reload(); err != nil {
			l.log.Warn("failed to reload Caddy after attestation-extension update (leaf updates on next route change)",
				zap.String("name", name), zap.String("oid", oid), zap.Error(err))
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

// pinnedDigestBytes extracts the 32-byte SHA-256 from a digest-pinned image
// reference ("...@sha256:<64hex>"). It is the requested digest, known before the
// pull, used both to verify the pull and to stamp this TEE's vault identity when
// fetching a private-registry credential.
func pinnedDigestBytes(imageRef string) ([]byte, error) {
	idx := strings.Index(imageRef, "@sha256:")
	if idx < 0 {
		return nil, fmt.Errorf("image %q is not digest-pinned (must contain @sha256:...)", imageRef)
	}
	pinnedBytes, err := hex.DecodeString(imageRef[idx+8:])
	if err != nil {
		return nil, fmt.Errorf("image %q has invalid digest hex: %w", imageRef, err)
	}
	if len(pinnedBytes) != sha256.Size {
		return nil, fmt.Errorf("image %q digest is not SHA-256 (got %d bytes)", imageRef, len(pinnedBytes))
	}
	return pinnedBytes, nil
}

// verifyPinnedDigest checks that the image reference includes a @sha256:
// digest pin and that the resolved digest matches.
func verifyPinnedDigest(imageRef string, resolvedDigest []byte) error {
	pinnedBytes, err := pinnedDigestBytes(imageRef)
	if err != nil {
		return err
	}
	if hex.EncodeToString(resolvedDigest) != hex.EncodeToString(pinnedBytes) {
		return fmt.Errorf("image %q: resolved digest %x does not match pinned %x",
			imageRef, resolvedDigest, pinnedBytes)
	}
	return nil
}

// parseRegistryAuth decodes a pull credential exported from the vault. The
// canonical shape is JSON {"username":"...","password":"..."} (the CLI's
// `registry add` writes this). For convenience a bare, non-JSON token is taken
// as the password with a conventional username, so a raw PAT also works.
func parseRegistryAuth(cred []byte) (*container.RegistryAuth, error) {
	cred = bytes.TrimSpace(cred)
	if len(cred) == 0 {
		return nil, fmt.Errorf("empty credential")
	}
	if cred[0] == '{' {
		var j struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(cred, &j); err != nil {
			return nil, fmt.Errorf("credential is not valid JSON: %w", err)
		}
		if j.Password == "" {
			return nil, fmt.Errorf("credential JSON has no password")
		}
		return &container.RegistryAuth{Username: j.Username, Password: j.Password}, nil
	}
	// Bare token: registries that take an identity token accept any username.
	return &container.RegistryAuth{Username: "x-access-token", Password: string(cred)}, nil
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
