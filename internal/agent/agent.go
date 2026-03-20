// Package agent provides the management API for Enclave OS (Virtual).
//
// The API exposes endpoints for container lifecycle management (load,
// unload, status) and observability (health, readiness, metrics).
//
// # Authentication
//
// The API implements OIDC-based authentication. Requests must carry an
// OIDC bearer token with the privasys-platform:manager role for
// mutating operations, or privasys-platform:monitoring for read-only.
//
// Tokens can carry a "containers" claim restricting which
// images may be loaded/unloaded. If absent, all are permitted.
//
// # Transport
//
// The agent listens on plain HTTP on localhost only. External TLS
// termination is handled by Caddy with the ra-tls-caddy module,
// which reverse-proxies to this listener.
//
// # Endpoints
//
// GET    /healthz              - liveness probe (always 200)
// GET    /readyz               - readiness probe (200 when all containers healthy)
// GET    /api/v1/status        - JSON array of container statuses
// POST   /api/v1/containers    - load a container (JSON body: LoadRequest)
// DELETE /api/v1/containers/{name} - unload a container
// GET    /metrics              - Prometheus metrics
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	// Addr is the listen address (default "localhost:9443").
	// The agent listens on plain HTTP — TLS is handled by Caddy.
	Addr string
}

// Agent is the management API server.
type Agent struct {
	cfg      Config
	log      *zap.Logger
	launcher *launcher.Launcher
	verifier *auth.Verifier
	server   *http.Server
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

	// Mutating endpoints (require manager role).
	mux.HandleFunc("POST /api/v1/containers", a.requireAuth(a.handleLoadContainer))
	mux.HandleFunc("DELETE /api/v1/containers/{name}", a.requireAuth(a.handleUnloadContainer))

	a.server = &http.Server{
		Addr:    a.cfg.Addr,
		Handler: a.metricsMiddleware(mux),
	}

	// Start serving in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		a.log.Info("management API listening (plain HTTP, Caddy handles TLS)",
			zap.String("addr", a.cfg.Addr),
		)
		errCh <- a.server.ListenAndServe()
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
