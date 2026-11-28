// Command manager is the workload manager for Enclave OS (Virtual).
//
// It starts empty (no containers), serves a management API, and dynamically
// loads containers via authenticated API calls.
//
// All API requests are authenticated via OIDC bearer tokens. Caddy
// (with its RA-TLS module) handles external TLS termination;
// the management API listens on plain HTTP on localhost.
//
// Usage:
//
//	manager serve --ca-cert ca.crt --ca-key ca.key --hostname example.com
//
// manager version
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/enclaveauth"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
	"github.com/Privasys/enclave-os-virtual/internal/manager"
	"github.com/Privasys/enclave-os-virtual/internal/mgrname"
	"github.com/Privasys/enclave-os-virtual/internal/network"
	"github.com/Privasys/enclave-os-virtual/internal/pinned"
	"github.com/Privasys/enclave-os-virtual/internal/runtimestatus"
	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
	"github.com/Privasys/enclave-os-virtual/internal/tunnel"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("manager %s\n", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Enclave OS (Virtual)  Manager %s

Usage:
  manager <command> [flags]

Commands:
  serve     Start the workload launcher and management API
  version   Print version information
  help      Show this help message

Run 'manager serve --help' for serve flags.

Required flags for serve:
  --ca-cert               CA certificate for RA-TLS
  --ca-key                CA private key for RA-TLS
  --hostname              Domain suffix (e.g. example.com)
`, version)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)

	caCert := fs.String("ca-cert", "",
		"Path to the PEM-encoded CA certificate for platform attestation (required)")
	caKeyPath := fs.String("ca-key", "",
		"Path to the PEM-encoded intermediary CA private key for RA-TLS (required)")
	containerdSocket := fs.String("containerd-socket", "",
		"containerd socket path (default: /run/containerd/containerd.sock)")

	// Caddy / RA-TLS flags.
	caddyListen := fs.String("caddy-listen", ":443",
		"External HTTPS listen address for Caddy")
	extensionsDir := fs.String("extensions-dir", "/run/manager/extensions",
		"Directory for per-hostname RA-TLS OID extension files")
	// Caddy's own default storage (caddy.service sets XDG_DATA_HOME=/data/caddy),
	// so naming it explicitly moves nothing.
	directStorage := fs.String("direct-storage", "/data/caddy/caddy",
		"Storage root shared with Caddy for direct-domain certificates (on the encrypted /data volume); empty disables direct domains")
	proxyProtocolFrom := fs.String("proxy-protocol-from", "",
		"Bootstrap only: comma-separated addresses (CIDR or IP) of the platform gateways, whose PROXY protocol v2 header (the client of a direct splice) is honoured. The control plane normally pushes this list (PUT /api/v1/edge/proxy-protocol), which then replaces the flag")
	directCA := fs.String("direct-ca", "",
		"ACME directory for direct-domain certificates (empty: Let's Encrypt)")
	machineName := fs.String("machine-name", "",
		"Machine name for this instance (e.g. prod1); determines container RA-TLS hostnames: <name>.<machine-name>.<hostname>")
	hostname := fs.String("hostname", "",
		"Domain suffix for RA-TLS hostnames (required, e.g. example.com)")
	platformHostnameFlag := fs.String("platform-hostname", "",
		"Explicit FQDN for the platform management API Caddy route and extension file (e.g. v-fr-1.example.com). If empty and machine-name is set, derived as <machine-name>.<hostname>")

	// LUKS / data encryption.
	dekOriginFile := fs.String("dek-origin-file", "/run/luks/dek-origin",
		"Path to the DEK origin file (\"external\" or \"enclave-generated\", written by luks-setup)")

	logLevel := fs.String("log-level", "info",
		"Log level (debug, info, warn, error)")

	// Runtime-status push (optional). When all four are set, the manager
	// runs a background goroutine that POSTs nvidia-smi + proxy state
	// to <mgmt-url>/api/v1/enclave/runtime-status every push-interval.
	rsMgmtURL := fs.String("mgmt-url", "",
		"Management-service base URL for runtime-status push (e.g. https://api.developer.privasys.org)")
	rsEnclaveToken := fs.String("enclave-token", os.Getenv("ENCLAVE_TOKEN"),
		"Static bearer token for runtime-status push (env: ENCLAVE_TOKEN)")
	rsEnclaveID := fs.String("enclave-id", os.Getenv("ENCLAVE_ID"),
		"UUID identifying this enclave to the management-service (env: ENCLAVE_ID)")
	rsProxyURL := fs.String("proxy-url", "http://localhost:8080",
		"Local confidential-ai proxy URL for /v1/models/status feed; empty disables the proxy feed")
	rsInterval := fs.Duration("push-interval", 30*time.Second,
		"Interval between runtime-status pushes")
	tunnelGateways := fs.String("tunnel-gateways", os.Getenv("TUNNEL_GATEWAYS"),
		"Comma-separated gateway instances (host:port) to hold an outbound tunnel to, for hosts that allow no inbound "+
			"connections (env: TUNNEL_GATEWAYS). Empty disables tunnels: the enclave is reached directly.")
	tunnelServerName := fs.String("tunnel-server-name", os.Getenv("TUNNEL_SERVER_NAME"),
		"TLS server name presented to the gateways (env: TUNNEL_SERVER_NAME). Default: tunnel.<hostname>")
	isolationUserns := fs.Bool("isolation-userns", os.Getenv("PRIVASYS_ISOLATION_USERNS") == "true",
		"Run each container in a user namespace (container-root -> unprivileged host uid). SHARED multi-tenant VMs only; leave off on dedicated/GPU VMs. EXPERIMENTAL/UNVALIDATED — validate on m2-dev before prod (env: PRIVASYS_ISOLATION_USERNS)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// An Enclave OS image runs only with the trust settings compiled for its
	// measured profile (internal/pinned). The control plane is the one setting
	// read from /data/manager.env, outside the measurement, and it must be one
	// the profile allows.
	profile, pin, err := pinned.Current(pinned.ProfileFile)
	if err != nil {
		return err
	}
	if *rsMgmtURL, err = pin.ResolveMgmtURL(*rsMgmtURL, *rsEnclaveToken != ""); err != nil {
		return fmt.Errorf("refusing to start on a %s image: %w", profile, err)
	}

	// Validate required flags.
	if *caCert == "" {
		return fmt.Errorf("--ca-cert is required")
	}
	if *caKeyPath == "" {
		return fmt.Errorf("--ca-key is required")
	}
	if *hostname == "" {
		return fmt.Errorf("--hostname is required")
	}

	// Set up structured logger.
	log, err := newLogger(*logLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	defer func() { _ = log.Sync() }()

	log.Info("starting manager",
		zap.String("version", version),
		zap.String("image_profile", profile),
	)

	// Build OIDC config.
	oidcCfg := &auth.OIDCConfig{
		Issuer:         pin.Issuer,
		Audience:       pin.Audience,
		ManagerRole:    pin.ManagerRole,
		MonitoringRole: pin.MonitoringRole,
	}

	// Create the auth verifier.
	verifier, err := auth.NewVerifier(oidcCfg, log)
	if err != nil {
		return fmt.Errorf("failed to create auth verifier: %w", err)
	}
	log.Info("auth configured",
		zap.String("oidc_issuer", pin.Issuer),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Trusted clock: every security decision reads its time from here, never
	// from the host clock directly. Installed before anything can serve a
	// request; reads fail closed until its boot NTS fetch has succeeded. The
	// state (floor, flag, monitor config) lives on the encrypted /data volume.
	clock, err := trustedtime.New(trustedtime.Options{
		StatePath: "/data/manager-clock.json",
		EnclaveID: *rsEnclaveID,
		Log:       log,
	})
	if err != nil {
		return fmt.Errorf("failed to load the trusted clock: %w", err)
	}
	trustedtime.Install(clock)

	// Derive the management API hostname.
	var platformHostname string
	if *platformHostnameFlag != "" {
		platformHostname = *platformHostnameFlag
	} else if *machineName != "" {
		platformHostname = *machineName + "." + *hostname
	}
	// The control plane's name for this manager, from the enclave name it
	// registered under (registration sends the machine name). If an operator
	// renames the enclave, the control plane's name moves and this one does
	// not: compare this line with the enclave's manager hostname there.
	managerHostname := mgrname.ManagerHostname(*machineName, pin.AppDomain)
	if strings.EqualFold(managerHostname, platformHostname) {
		managerHostname = ""
	}
	if managerHostname != "" {
		log.Info("manager hostname carries the platform extensions",
			zap.String("manager_hostname", managerHostname), zap.String("machine_name", *machineName))
	} else {
		log.Warn("no manager hostname could be derived: its certificate will carry no platform extensions",
			zap.String("machine_name", *machineName), zap.String("app_domain", pin.AppDomain))
	}

	// Configure launcher.
	launcherCfg := launcher.Config{
		ContainerdSocket:  *containerdSocket,
		CaddyAdminAddr:    "localhost:2019",
		CaddyListenAddr:   *caddyListen,
		ExtensionsDir:     *extensionsDir,
		DirectStorage:     *directStorage,
		DirectCA:          *directCA,
		ProxyProtocolFrom: splitList(*proxyProtocolFrom),
		// The list the control plane pushes replaces the flag once present.
		ProxyProtocolStatePath: "/data/manager-proxy-protocol.json",
		ManagerHostname:        managerHostname,
		ImageProfile:           profile,
		PlatformHostname:       platformHostname,
		AppDomain:              pin.AppDomain,
		ManagementPort:         "9443",
		CACertPath:             *caCert,
		CAKeyPath:              *caKeyPath,
		AttestationServers:     []string{pin.AttestationServer},
		DEKOriginFile:          *dekOriginFile,
		MgmtURL:                *rsMgmtURL,
		EnclaveID:              *rsEnclaveID,
		EnclaveToken:           *rsEnclaveToken,
		IsolationUserns:        *isolationUserns,
		Issuer:                 pin.Issuer,
		Audience:               pin.Audience,
	}
	// Bring up the container bridge + egress NAT + manager-port guard before
	// any container is loaded or the management API binds (#45). Fatal on
	// failure: without it containers would come up with no connectivity.
	if err := network.Setup(log); err != nil {
		log.Fatal("failed to set up container network", zap.Error(err))
	}

	l := launcher.New(launcherCfg, log)

	// Configure management API server (plain HTTP). Binds on all interfaces so
	// one listener serves both the host (Caddy/probes at localhost:9443) and
	// containers (at the bridge gateway); network.Setup's iptables guard drops
	// :9443 on the external interface (#45).
	// Attested identity for our own calls to the control plane: a leaf issued
	// by this enclave's CA, quoted, and a signature per request. Without it
	// (no CA yet, or no enclave id) the calls fall back to the bearer, which
	// the control plane still accepts while the fleet migrates.
	var enclaveSigner *enclaveauth.Signer
	if signer, err := enclaveauth.New(*caCert, *caKeyPath, *rsEnclaveID); err != nil {
		log.Warn("attested control-plane auth unavailable, using the enclave credential",
			zap.Error(err))
	} else {
		enclaveSigner = signer
		log.Info("attested control-plane auth enabled", zap.String("enclave_id", *rsEnclaveID))
	}

	mgrCfg := manager.Config{
		Addr:             ":9443",
		PlatformHostname: platformHostname,
		ImageProfile:     profile,
		// /data is the per-VM LUKS-encrypted volume — keep the registry
		// here (entries may carry Env values flagged secret; volume keys
		// are never persisted). Set to empty to disable persistence.
		RegistryPath: "/data/manager-apps.json",
		// Same OIDC issuer used for bearer-token verification is also
		// the EncAuth IdP: the session-relay middleware uses it to
		// fetch the JWKS that signs silent-rebind vouchers.
		IdpIssuer: pin.Issuer,
		// Verifies the wallet's per-call proof (WIA + holder-key signature)
		// behind the free_for:["wallet"] exemption. The wallet provider is
		// the IdP, so derive the JWKS from the issuer unless overridden.
		WalletProviderJWKS: pin.WalletProviderJWKS(),
		// Settlement channel for paid attribute disclosures: reuses the
		// fleet mgmt URL + enclave bearer (same credential as check-in).
		// The same three also let the manager relay the tool spec on a
		// container's behalf, so that bearer stays inside the manager.
		MgmtBaseURL:   *rsMgmtURL,
		EnclaveToken:  *rsEnclaveToken,
		EnclaveID:     *rsEnclaveID,
		EnclaveSigner: enclaveSigner,
		// Owner-signed policy pins live beside the registry on /data.
		AppPolicyPath: "/data/manager-app-policy.json",
		// Resource-capability state (P2) lives beside the registry on /data.
		CapabilityStateDir: "/data/manager-capabilities",
		Clock:              clock,
	}
	srv := manager.New(mgrCfg, log, l, verifier)

	// Wire the host router so container loads register their loopback
	// upstreams with the manager. Caddy then routes every RA-TLS host
	// (platform + container) at the manager port and the manager
	// dispatches by Host, applying the session-relay middleware to all.
	l.SetAppHostRouter(srv)

	// Run launcher and management API concurrently.
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return l.Run(gctx)
	})

	g.Go(func() error {
		return srv.Start(gctx)
	})

	// Boot NTS fetch, and retries while the clock is failing closed.
	g.Go(func() error {
		return clock.Run(gctx)
	})

	// Issuing time for Caddy's RA-TLS module (its own process), on a root-only
	// Unix socket in the manager's runtime directory: trusted time when there
	// is one, the floor otherwise. Certificates and evidence are always
	// served; only verification decisions fail closed, so the management API
	// and the clock poll stay reachable while trusted time is unavailable.
	// A failure here is logged, not fatal: the module then falls back to its
	// last answer, or to the host clock before it ever had one.
	g.Go(func() error {
		if err := trustedtime.ServeLocal(gctx, trustedtime.DefaultLocalSocket, clock, log); err != nil {
			log.Error("issuing time local socket failed; RA-TLS falls back to its last answer or the host clock", zap.Error(err))
		}
		return nil
	})

	// Optional outbound tunnels to the platform gateways, for hosts that allow
	// no inbound connections. Streams land on the local Caddy listener.
	if *tunnelGateways != "" {
		serverName := *tunnelServerName
		if serverName == "" && *hostname != "" {
			serverName = "tunnel." + strings.TrimPrefix(*hostname, ".")
		}
		tc, err := tunnel.New(tunnel.Config{
			Gateways:   strings.Split(*tunnelGateways, ","),
			ServerName: serverName,
			Target:     loopbackTarget(*caddyListen),
			EnclaveID:  *rsEnclaveID,
			Signer:     signerOrNil(enclaveSigner),
		}, log)
		if err != nil {
			// Without its tunnel an egress-only enclave is unreachable: fail
			// loudly so the unit restarts and the cause is in the journal.
			return fmt.Errorf("egress tunnel: %w", err)
		}
		g.Go(func() error {
			return tc.Run(gctx)
		})
	}

	// Scheduled backups: the manager runs each app's schedule itself.
	g.Go(func() error {
		return l.RunBackupScheduler(gctx)
	})

	// Optional runtime-status push sender.
	if sender := runtimestatus.New(runtimestatus.Config{
		MgmtBaseURL:  *rsMgmtURL,
		EnclaveToken: *rsEnclaveToken,
		EnclaveID:    *rsEnclaveID,
		Signer:       signerOrNil(enclaveSigner),
		ProxyBaseURL: *rsProxyURL,
		// Per-container netns (#45): the AI container's fixed :8080 proxy
		// lives at its private bridge IP, resolved fresh per sample so the
		// feed follows redeploys. Loopback flag values are rewritten; an
		// explicit non-loopback --proxy-url passes through.
		ProxyURLFunc: func() string { return l.ResolveAIProxyURL(*rsProxyURL) },
		Interval:     *rsInterval,
	}, log); sender != nil {
		g.Go(func() error {
			return sender.Run(gctx)
		})
		// Backup job outcomes and the app's backup catalogue go to the
		// platform over the same authenticated channel.
		l.SetBackupReporter(func(ctx context.Context, r launcher.BackupReport) error {
			r.EnclaveID = sender.EnclaveID()
			return sender.Post(ctx, "/api/v1/enclave/backups", r)
		})
	} else if *rsMgmtURL != "" || *rsEnclaveID != "" {
		log.Warn("runtime-status push partially configured; need --mgmt-url and --enclave-id together")
	}

	if err := g.Wait(); err != nil {
		log.Error("shutdown with error", zap.Error(err))
		return err
	}

	log.Info("shutdown complete")
	return nil
}

func newLogger(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapLevel),
		Development: false,
		Encoding:    "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return cfg.Build()
}

// signerOrNil keeps a nil *Signer out of the interface field: a typed nil
// would satisfy the interface and then fail on every call.
// loopbackTarget turns Caddy's listen address (":443", "0.0.0.0:443") into
// the loopback address tunnel streams are delivered to.
func loopbackTarget(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return "127.0.0.1:443"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func signerOrNil(s *enclaveauth.Signer) enclaveauth.RequestSigner {
	if s == nil {
		return nil
	}
	return s
}

// splitList splits a comma-separated flag value, dropping empty entries.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
