// Package agent provides the management API for Enclave OS Virtual.
//
// The API exposes endpoints for container lifecycle management (load,
// unload, status) and observability (health, readiness, metrics).
//
// # Authentication
//
// The API implements a two-phase authentication model:
//
//   - Operations JWT: Signed by the Privasys management key, always
//     accepted. This is the permanent break-glass credential.
//
//   - OIDC token: Accepted once an OIDC provider is
//     reachable. Requires the enclave-os-virtual:manager role for
//     mutating operations, or enclave-os-virtual:monitoring for read-only.
//
// Both token types can carry a "containers" claim restricting which
// images may be loaded/unloaded. If absent, all are permitted.
//
// # Endpoints
//
// GET    /healthz              - liveness probe (always 200)
// GET    /readyz               - readiness probe (200 when all containers healthy)
// GET    /api/v1/status        - JSON array of container statuses
// POST   /api/v1/containers    - load a container (JSON body: LoadRequest)
// DELETE /api/v1/containers/{name} - unload a container
// GET    /api/v1/tls           - current TLS certificate metadata
// PUT    /api/v1/tls           - rotate TLS certificate (cert+key PEM)
// GET    /metrics              - Prometheus metrics
package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

const (
	// DefaultAddr is the default listen address for the management API.
	DefaultAddr = ":9443"

	// shutdownTimeout is the maximum time to wait for the HTTP server to
	// drain connections during shutdown.
	shutdownTimeout = 5 * time.Second
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	// authResultKey is the context key for *auth.AuthResult.
	authResultKey contextKey = iota
)

// Prometheus metrics.
var (
	containerStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "enclave_os",
			Name:      "container_status",
			Help:      "Container status (1=running, 2=healthy, 3=unhealthy, 0=stopped).",
		},
		[]string{"name", "image"},
	)
	apiRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "enclave_os",
			Name:      "api_requests_total",
			Help:      "Total management API requests.",
		},
		[]string{"method", "path", "status"},
	)
	containersLoaded = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "enclave_os",
			Name:      "containers_loaded",
			Help:      "Number of currently loaded containers.",
		},
	)
)

func init() {
	prometheus.MustRegister(containerStatus, apiRequests, containersLoaded)
}

// Config holds the agent configuration.
type Config struct {
	// Addr is the listen address (default ":9443").
	Addr string

	// TLSCert is the path to the server certificate PEM.
	TLSCert string

	// TLSKey is the path to the server private key PEM.
	TLSKey string

	// CACert is the path to the CA certificate PEM for client
	// verification (mTLS).
	CACert string

	// MgmtCertPath is the path to the Privasys management certificate
	// used for verifying bootstrap JWTs.
	MgmtCertPath string
}

// certStore holds the current TLS certificate and supports atomic swaps
// for certificate rotation without server restart.
type certStore struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

func (cs *certStore) get() *tls.Certificate {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.cert
}

func (cs *certStore) set(cert *tls.Certificate) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.cert = cert
}

// Agent is the management API server.
type Agent struct {
	cfg      Config
	log      *zap.Logger
	launcher *launcher.Launcher
	verifier *auth.Verifier
	server   *http.Server
	certs    certStore
}

// New creates a new Agent.
func New(cfg Config, log *zap.Logger, l *launcher.Launcher, v *auth.Verifier) *Agent {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	return &Agent{
		cfg:      cfg,
		log:      log.Named("agent"),
		launcher: l,
		verifier: v,
	}
}

// Start starts the management API server. It blocks until the context is
// cancelled, then gracefully shuts down.
func (a *Agent) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Liveness probe — always unauthenticated (used by infra health checks).
	mux.HandleFunc("GET /healthz", a.handleHealthz)

	// Monitoring endpoints (require monitoring or manager role).
	mux.HandleFunc("GET /readyz", a.requireAuth(a.handleReadyz))
	mux.HandleFunc("GET /api/v1/status", a.requireAuth(a.handleStatus))
	mux.Handle("GET /metrics", a.requireAuth(a.handleMetrics))

	// TLS certificate management.
	mux.HandleFunc("GET /api/v1/tls", a.requireAuth(a.handleGetTLS))
	mux.HandleFunc("PUT /api/v1/tls", a.requireAuth(a.handleUpdateTLS))

	// Mutating endpoints (require manager role).
	mux.HandleFunc("POST /api/v1/containers", a.requireAuth(a.handleLoadContainer))
	mux.HandleFunc("DELETE /api/v1/containers/{name}", a.requireAuth(a.handleUnloadContainer))

	tlsCfg, err := a.tlsConfig()
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}

	a.server = &http.Server{
		Addr:      a.cfg.Addr,
		Handler:   a.metricsMiddleware(mux),
		TLSConfig: tlsCfg,
	}

	// Start serving in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		a.log.Info("management API listening",
			zap.String("addr", a.cfg.Addr),
			zap.Bool("tls", tlsCfg != nil),
			zap.Bool("bootstrap_auth", a.verifier != nil),
		)
		if tlsCfg != nil {
			errCh <- a.server.ListenAndServeTLS("", "")
		} else {
			// Fallback to plain HTTP (for development/testing only).
			a.log.Warn("running without TLS - development mode only")
			errCh <- a.server.ListenAndServe()
		}
	}()

	// Wait for context cancellation or server error.
	select {
	case <-ctx.Done():
		a.log.Info("shutting down management API")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return a.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// requireAuth wraps a handler with authentication. The caller must
// provide a valid bearer token (operations JWT or OIDC).
//
// On success the *auth.AuthResult is stored in the request context,
// accessible via authResultKey.
func (a *Agent) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.jsonError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			a.jsonError(w, http.StatusUnauthorized, "expected Bearer token")
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		if a.verifier == nil {
			a.jsonError(w, http.StatusInternalServerError, "auth not configured")
			return
		}

		result, err := a.verifier.Authenticate(token)
		if err != nil {
			a.log.Debug("authentication failed",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Error(err),
			)
			a.jsonError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		a.log.Debug("request authenticated",
			zap.String("source", result.Source),
			zap.String("role", result.Role),
			zap.String("subject", result.Subject),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
		)

		ctx := context.WithValue(r.Context(), authResultKey, result)
		next(w, r.WithContext(ctx))
	}
}

func (a *Agent) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (a *Agent) handleReadyz(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		a.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}

	statuses := a.launcher.StatusReport()

	// When no containers are loaded, we are ready (waiting for first load).
	if len(statuses) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready","containers":0}`))
		return
	}

	allHealthy := true
	for _, s := range statuses {
		if s.Status != "healthy" && s.Status != "running" {
			allHealthy = false
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if allHealthy {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not_ready"}`))
	}
}

func (a *Agent) handleStatus(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		a.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}

	statuses := a.launcher.StatusReport()

	// Update Prometheus gauges.
	containersLoaded.Set(float64(len(statuses)))
	for _, s := range statuses {
		var val float64
		switch s.Status {
		case "running":
			val = 1
		case "healthy":
			val = 2
		case "unhealthy":
			val = 3
		default:
			val = 0
		}
		containerStatus.WithLabelValues(s.Name, s.Image).Set(val)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(statuses)
}

// handleLoadContainer handles POST /api/v1/containers.
// Request body is a JSON launcher.LoadRequest.
func (a *Agent) handleLoadContainer(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)

	// Mutating operation requires manager-level access.
	if !result.HasManagerAccess() {
		a.jsonError(w, http.StatusForbidden, "manager role required for container operations")
		return
	}

	var req launcher.LoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// Enforce containers claim policy.
	if !result.IsContainerPermitted(req.Image) {
		a.log.Warn("container not permitted by token policy",
			zap.String("image", req.Image),
			zap.String("subject", result.Subject),
		)
		a.jsonError(w, http.StatusForbidden, "container image not permitted by token policy")
		return
	}

	a.log.Info("load container request",
		zap.String("name", req.Name),
		zap.String("image", req.Image),
		zap.Int("port", req.Port),
		zap.Bool("vault_token", req.VaultToken != ""),
		zap.String("auth_source", result.Source),
		zap.String("auth_subject", result.Subject),
	)

	digest, err := a.launcher.Load(r.Context(), req)
	if err != nil {
		a.log.Error("failed to load container",
			zap.String("name", req.Name),
			zap.Error(err),
		)
		a.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	containersLoaded.Set(float64(a.launcher.ContainerCount()))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"name":   req.Name,
		"image":  req.Image,
		"digest": fmt.Sprintf("%x", digest),
		"status": "running",
	})
}

// handleUnloadContainer handles DELETE /api/v1/containers/{name}.
func (a *Agent) handleUnloadContainer(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)

	// Mutating operation requires manager-level access.
	if !result.HasManagerAccess() {
		a.jsonError(w, http.StatusForbidden, "manager role required for container operations")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		a.jsonError(w, http.StatusBadRequest, "container name is required")
		return
	}

	// Enforce containers claim policy.
	if !result.IsUnloadPermitted(name) {
		a.log.Warn("container unload not permitted by token policy",
			zap.String("name", name),
			zap.String("subject", result.Subject),
		)
		a.jsonError(w, http.StatusForbidden, "container unload not permitted by token policy")
		return
	}

	a.log.Info("unload container request",
		zap.String("name", name),
		zap.String("auth_source", result.Source),
		zap.String("auth_subject", result.Subject),
	)

	if err := a.launcher.Unload(r.Context(), name); err != nil {
		a.log.Error("failed to unload container",
			zap.String("name", name),
			zap.Error(err),
		)
		a.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	containersLoaded.Set(float64(a.launcher.ContainerCount()))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":   name,
		"status": "unloaded",
	})
}

func (a *Agent) jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// handleMetrics serves Prometheus metrics with auth check.
func (a *Agent) handleMetrics(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		a.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}
	promhttp.Handler().ServeHTTP(w, r)
}

func (a *Agent) tlsConfig() (*tls.Config, error) {
	if a.cfg.TLSCert == "" || a.cfg.TLSKey == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(a.cfg.TLSCert, a.cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key: %w", err)
	}
	a.certs.set(&cert)

	cfg := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.certs.get(), nil
		},
		MinVersion: tls.VersionTLS13,
	}

	// If CA cert provided, enable mTLS.
	if a.cfg.CACert != "" {
		caCertPEM, err := os.ReadFile(a.cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertPEM) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	}

	return cfg, nil
}

// handleGetTLS returns metadata about the current TLS certificate.
func (a *Agent) handleGetTLS(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		a.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}

	cert := a.certs.get()
	if cert == nil || len(cert.Certificate) == 0 {
		a.jsonError(w, http.StatusNotFound, "no TLS certificate configured")
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		a.jsonError(w, http.StatusInternalServerError, "failed to parse certificate")
		return
	}

	fp := sha256.Sum256(x509Cert.Raw)

	info := map[string]interface{}{
		"subject":     x509Cert.Subject.CommonName,
		"issuer":      x509Cert.Issuer.CommonName,
		"dns_names":   x509Cert.DNSNames,
		"not_before":  x509Cert.NotBefore.Format(time.RFC3339),
		"not_after":   x509Cert.NotAfter.Format(time.RFC3339),
		"fingerprint": hex.EncodeToString(fp[:]),
		"serial":      x509Cert.SerialNumber.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}

// tlsUpdateRequest is the JSON body for PUT /api/v1/tls.
type tlsUpdateRequest struct {
	Cert string `json:"cert"` // PEM-encoded certificate (+ chain)
	Key  string `json:"key"`  // PEM-encoded private key
}

// handleUpdateTLS replaces the server TLS certificate at runtime.
// The new cert and key are validated, persisted to disk, and hot-swapped
// into the running TLS listener without restart.
func (a *Agent) handleUpdateTLS(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasManagerAccess() {
		a.jsonError(w, http.StatusForbidden, "manager role required")
		return
	}

	// Limit body to 1 MB.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req tlsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if req.Cert == "" || req.Key == "" {
		a.jsonError(w, http.StatusBadRequest, "cert and key fields are required")
		return
	}

	// Parse and validate the new certificate.
	newCert, err := tls.X509KeyPair([]byte(req.Cert), []byte(req.Key))
	if err != nil {
		a.jsonError(w, http.StatusBadRequest, "invalid cert/key pair: "+err.Error())
		return
	}

	x509Cert, err := x509.ParseCertificate(newCert.Certificate[0])
	if err != nil {
		a.jsonError(w, http.StatusBadRequest, "failed to parse certificate: "+err.Error())
		return
	}

	// Persist to disk so restarts pick up the new cert.
	if a.cfg.TLSCert != "" && a.cfg.TLSKey != "" {
		if err := atomicWrite(a.cfg.TLSCert, []byte(req.Cert)); err != nil {
			a.log.Error("failed to persist TLS cert", zap.Error(err))
			a.jsonError(w, http.StatusInternalServerError, "failed to persist certificate")
			return
		}
		if err := atomicWrite(a.cfg.TLSKey, []byte(req.Key)); err != nil {
			a.log.Error("failed to persist TLS key", zap.Error(err))
			a.jsonError(w, http.StatusInternalServerError, "failed to persist key")
			return
		}
	}

	// Hot-swap the certificate.
	a.certs.set(&newCert)

	fp := sha256.Sum256(x509Cert.Raw)

	a.log.Info("TLS certificate rotated",
		zap.String("subject", x509Cert.Subject.CommonName),
		zap.Strings("dns_names", x509Cert.DNSNames),
		zap.Time("not_after", x509Cert.NotAfter),
		zap.String("fingerprint", hex.EncodeToString(fp[:])),
		zap.String("auth_source", result.Source),
		zap.String("auth_subject", result.Subject),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"subject":     x509Cert.Subject.CommonName,
		"dns_names":   x509Cert.DNSNames,
		"not_after":   x509Cert.NotAfter.Format(time.RFC3339),
		"fingerprint": hex.EncodeToString(fp[:]),
		"status":      "rotated",
	})
}

// atomicWrite writes data to a file atomically by writing to a temp file
// first, then renaming.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func (a *Agent) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		apiRequests.WithLabelValues(
			r.Method,
			r.URL.Path,
			fmt.Sprintf("%d", rw.statusCode),
		).Inc()
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
