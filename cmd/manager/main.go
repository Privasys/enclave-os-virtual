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
// manager serve --oidc-issuer https://auth.example.com
//
//	--hostname example.com
//
// manager version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
	"github.com/Privasys/enclave-os-virtual/internal/manager"
	"github.com/Privasys/enclave-os-virtual/internal/runtimestatus"
)

const version = "0.2.0"

// stringSliceFlag implements flag.Value for comma-separated string lists.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(val string) error {
	for _, v := range strings.Split(val, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			*s = append(*s, v)
		}
	}
	return nil
}

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
  --oidc-issuer           OIDC provider URL
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
	var attestationServers stringSliceFlag
	fs.Var(&attestationServers, "attestation-servers",
		"Comma-separated list of attestation server URLs for remote quote verification")
	containerdSocket := fs.String("containerd-socket", "",
		"containerd socket path (default: /run/containerd/containerd.sock)")

	// OIDC flags (required).
	oidcIssuer := fs.String("oidc-issuer", "",
		"OIDC issuer URL for bearer token verification (required, e.g. https://auth.example.com)")
	oidcAudience := fs.String("oidc-audience", "enclave-os-virtual",
		"Expected OIDC audience claim")
	oidcManagerRole := fs.String("oidc-manager-role", "privasys-platform:manager",
		"OIDC role required for mutating operations (load/unload)")
	oidcMonitoringRole := fs.String("oidc-monitoring-role", "privasys-platform:monitoring",
		"OIDC role for read-only access (healthz, readyz, status, metrics)")
	oidcRoleClaim := fs.String("oidc-role-claim", "roles",
		"JWT claim key containing roles (supports map or array formats)")

	// Caddy / RA-TLS flags.
	caddyListen := fs.String("caddy-listen", ":443",
		"External HTTPS listen address for Caddy")
	extensionsDir := fs.String("extensions-dir", "/run/manager/extensions",
		"Directory for per-hostname RA-TLS OID extension files")
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
	loadToken := fs.String("load-token", os.Getenv("LOAD_TOKEN"),
		"Bearer token injected into containers as LOAD_TOKEN to gate /v1/models/{load,unload}; empty leaves those endpoints unauthenticated (env: LOAD_TOKEN)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required flags.
	if *oidcIssuer == "" {
		return fmt.Errorf("--oidc-issuer is required")
	}
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
		zap.Int("attestation_servers", len(attestationServers)),
	)

	// Build OIDC config.
	oidcCfg := &auth.OIDCConfig{
		Issuer:         *oidcIssuer,
		Audience:       *oidcAudience,
		ManagerRole:    *oidcManagerRole,
		MonitoringRole: *oidcMonitoringRole,
		RoleClaim:      *oidcRoleClaim,
	}

	// Create the auth verifier.
	verifier, err := auth.NewVerifier(oidcCfg, log)
	if err != nil {
		return fmt.Errorf("failed to create auth verifier: %w", err)
	}
	log.Info("auth configured",
		zap.String("oidc_issuer", *oidcIssuer),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Derive the management API hostname.
	var platformHostname string
	if *platformHostnameFlag != "" {
		platformHostname = *platformHostnameFlag
	} else if *machineName != "" {
		platformHostname = *machineName + "." + *hostname
	}

	// Configure launcher.
	launcherCfg := launcher.Config{
		ContainerdSocket:   *containerdSocket,
		CaddyAdminAddr:     "localhost:2019",
		CaddyListenAddr:    *caddyListen,
		ExtensionsDir:      *extensionsDir,
		MachineName:        *machineName,
		Hostname:           *hostname,
		PlatformHostname:   platformHostname,
		ManagementPort:     "9443",
		CACertPath:         *caCert,
		CAKeyPath:          *caKeyPath,
		AttestationServers: []string(attestationServers),
		DEKOriginFile:      *dekOriginFile,
		// Wire tool-spec puller env injection. The launcher only
		// synthesises TOOL_SPEC_* env vars when ALL three are set —
		// pre-bootstrap (no enclave_id / token) leaves containers
		// running with an empty catalogue, same as before.
		ToolSpecMgmtURL:      *rsMgmtURL,
		ToolSpecEnclaveID:    *rsEnclaveID,
		ToolSpecEnclaveToken: *rsEnclaveToken,
		LoadToken:            *loadToken,
	}
	l := launcher.New(launcherCfg, log)

	// Configure management API server (plain HTTP, localhost only).
	mgrCfg := manager.Config{
		Addr:             "localhost:9443",
		PlatformHostname: platformHostname,
		// /data is the per-VM LUKS-encrypted volume — keep the registry
		// here (entries may carry Env values flagged secret; volume keys
		// are never persisted). Set to empty to disable persistence.
		RegistryPath: "/data/manager-apps.json",
		// Same OIDC issuer used for bearer-token verification is also
		// the EncAuth IdP: the session-relay middleware uses it to
		// fetch the JWKS that signs silent-rebind vouchers.
		IdpIssuer: *oidcIssuer,
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

	// Optional runtime-status push sender.
	if sender := runtimestatus.New(runtimestatus.Config{
		MgmtBaseURL:  *rsMgmtURL,
		EnclaveToken: *rsEnclaveToken,
		EnclaveID:    *rsEnclaveID,
		ProxyBaseURL: *rsProxyURL,
		Interval:     *rsInterval,
	}, log); sender != nil {
		g.Go(func() error {
			return sender.Run(gctx)
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
