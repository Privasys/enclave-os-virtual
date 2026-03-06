// Command manager is the workload manager for Enclave OS (Virtual).
//
// It starts empty (no containers), serves a management API, and dynamically
// loads containers via authenticated API calls.
//
// All API requests are authenticated via OIDC bearer tokens. Caddy
// (with the ra-tls-caddy module) handles external TLS termination;
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

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
	"github.com/Privasys/enclave-os-virtual/internal/manager"
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
	attestationBackend := fs.String("attestation-backend", "tdx",
		"TEE attestation backend: tdx or sev-snp (required)")
	containerdSocket := fs.String("containerd-socket", "",
		"containerd socket path (default: /run/containerd/containerd.sock)")

	// OIDC flags (required).
	oidcIssuer := fs.String("oidc-issuer", "",
		"OIDC issuer URL for bearer token verification (required, e.g. https://auth.example.com)")
	oidcAudience := fs.String("oidc-audience", "enclave-os-virtual",
		"Expected OIDC audience claim")
	oidcManagerRole := fs.String("oidc-manager-role", "enclave-os-virtual:manager",
		"OIDC role required for mutating operations (load/unload)")
	oidcMonitoringRole := fs.String("oidc-monitoring-role", "enclave-os-virtual:monitoring",
		"OIDC role for read-only access (healthz, readyz, status, metrics)")
	oidcRoleClaim := fs.String("oidc-role-claim", "urn:zitadel:iam:org:project:roles",
		"JWT claim key containing roles (supports map or array formats)")

	// Caddy / RA-TLS flags.
	caddyListen := fs.String("caddy-listen", ":443",
		"External HTTPS listen address for Caddy")
	extensionsDir := fs.String("extensions-dir", "/run/manager/extensions",
		"Directory for per-hostname RA-TLS OID extension files")
	machineName := fs.String("machine-name", "",
		"Machine name for this instance (e.g. prod1); determines all RA-TLS hostnames")
	hostname := fs.String("hostname", "",
		"Domain suffix for RA-TLS hostnames (required, e.g. example.com)")

	// LUKS / data encryption.
	dekOriginFile := fs.String("dek-origin-file", "/run/luks/dek-origin",
		"Path to the DEK origin file (\"external\" or \"enclave-generated\", written by luks-setup)")

	logLevel := fs.String("log-level", "info",
		"Log level (debug, info, warn, error)")

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
		zap.String("attestation_backend", *attestationBackend),
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

	// Derive the management API hostname: manager.<machine-name>.<hostname>
	var platformHostname string
	if *machineName != "" {
		platformHostname = "manager." + *machineName + "." + *hostname
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
		AttestationBackend: *attestationBackend,
		DEKOriginFile:      *dekOriginFile,
	}
	l := launcher.New(launcherCfg, log)

	// Configure management API server (plain HTTP, localhost only).
	mgrCfg := manager.Config{
		Addr: "localhost:9443",
	}
	srv := manager.New(mgrCfg, log, l, verifier)

	// Run launcher and management API concurrently.
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return l.Run(gctx)
	})

	g.Go(func() error {
		return srv.Start(gctx)
	})

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
