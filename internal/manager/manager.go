// Package manager provides the management API for Enclave OS (Virtual).
//
// The API exposes endpoints for container lifecycle management (load,
// unload, status), TLS certificate rotation, and observability (health,
// readiness, metrics).
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
// The server listens on plain HTTP on localhost only. External TLS
// termination is handled by Caddy with the ra-tls-caddy module,
// which reverse-proxies to this listener.
//
// # Endpoints
//
// GET    /healthz                    - liveness probe (always 200)
// GET    /readyz                     - readiness probe (200 when all containers healthy)
// GET    /api/v1/status              - JSON array of container statuses
// GET    /api/v1/eventlog            - TCG2 event log for RTMR verification (base64)
// POST   /api/v1/containers          - load a container (JSON body: LoadRequest)
// DELETE /api/v1/containers/{name}   - unload a container
// PUT    /api/v1/tls                 - rotate the intermediary CA cert+key
// PUT    /api/v1/attestation-servers  - update attestation servers and tokens
// GET    /metrics                    - Prometheus metrics
package manager

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
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

// Config holds the management API server configuration.
type Config struct {
	// Addr is the listen address (default "localhost:9443").
	// The server listens on plain HTTP — TLS is handled by Caddy.
	Addr string
}

// Server is the management API server.
type Server struct {
	cfg      Config
	log      *zap.Logger
	launcher *launcher.Launcher
	verifier *auth.Verifier
	server   *http.Server
}

// New creates a new management API Server.
func New(cfg Config, log *zap.Logger, l *launcher.Launcher, v *auth.Verifier) *Server {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	return &Server{
		cfg:      cfg,
		log:      log.Named("manager"),
		launcher: l,
		verifier: v,
	}
}

// Start starts the management API server. It blocks until the context is
// cancelled, then gracefully shuts down.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Liveness probe — always unauthenticated (used by infra health checks).
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Monitoring endpoints (require monitoring or manager role).
	mux.HandleFunc("GET /readyz", s.requireAuth(s.handleReadyz))
	mux.HandleFunc("GET /api/v1/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("GET /api/v1/eventlog", s.requireAuth(s.handleEventLog))
	mux.Handle("GET /metrics", s.requireAuth(s.handleMetrics))

	// Mutating endpoints (require manager role).
	mux.HandleFunc("POST /api/v1/containers", s.requireAuth(s.handleLoadContainer))
	mux.HandleFunc("DELETE /api/v1/containers/{name}", s.requireAuth(s.handleUnloadContainer))

	// TLS certificate rotation (require manager role).
	mux.HandleFunc("PUT /api/v1/tls", s.requireAuth(s.handleUpdateTLS))

	// Attestation server management (require manager role).
	mux.HandleFunc("PUT /api/v1/attestation-servers", s.requireAuth(s.handleSetAttestationServers))

	s.server = &http.Server{
		Addr:    s.cfg.Addr,
		Handler: s.metricsMiddleware(mux),
	}

	// Start serving in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("management API listening (plain HTTP, Caddy handles TLS)",
			zap.String("addr", s.cfg.Addr),
		)
		errCh <- s.server.ListenAndServe()
	}()

	// Wait for context cancellation or server error.
	select {
	case <-ctx.Done():
		s.log.Info("shutting down management API")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return s.server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// requireAuth wraps a handler with authentication.
//
// On success the *auth.AuthResult is stored in the request context,
// accessible via authResultKey.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.jsonError(w, http.StatusUnauthorized, "missing Authorization header")
			return
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			s.jsonError(w, http.StatusUnauthorized, "expected Bearer token")
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		if s.verifier == nil {
			s.jsonError(w, http.StatusInternalServerError, "auth not configured")
			return
		}

		result, err := s.verifier.Authenticate(token)
		if err != nil {
			s.log.Debug("authentication failed",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Error(err),
			)
			s.jsonError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		s.log.Debug("request authenticated",
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

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		s.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}

	statuses := s.launcher.StatusReport()

	// When no containers are loaded, we are ready (waiting for first load).
	if len(statuses) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready","containers":0}`))
		return
	}

	allHealthy := true
	for _, st := range statuses {
		if st.Status != "healthy" && st.Status != "running" {
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

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		s.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}

	statuses := s.launcher.StatusReport()

	// Update Prometheus gauges.
	containersLoaded.Set(float64(len(statuses)))
	for _, st := range statuses {
		var val float64
		switch st.Status {
		case "running":
			val = 1
		case "healthy":
			val = 2
		case "unhealthy":
			val = 3
		default:
			val = 0
		}
		containerStatus.WithLabelValues(st.Name, st.Image).Set(val)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(statuses)
}

// handleEventLog handles GET /api/v1/eventlog.
// Returns the TCG2 crypto-agile event log (base64-encoded) for client-side
// RTMR replay and verification. The event log is measured by TDX firmware
// and its replay must reproduce the RTMR values in the TDX quote.
func (s *Server) handleEventLog(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		s.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}

	// Try vTPM event log first, then CCEL ACPI table.
	var data []byte
	var source string
	var err error

	data, err = os.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
	if err == nil && len(data) > 0 {
		source = "tpm0"
	} else {
		data, err = os.ReadFile("/sys/firmware/acpi/tables/data/CCEL")
		if err != nil {
			s.jsonError(w, http.StatusNotFound, "event log not available")
			return
		}
		source = "ccel"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := map[string]any{
		"raw":    base64.StdEncoding.EncodeToString(data),
		"source": source,
	}

	// Include application-level RTMR[3] events if any exist.
	if events := s.launcher.TPMEvents(); len(events) > 0 {
		resp["app_events"] = events
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// handleLoadContainer handles POST /api/v1/containers.
// Request body is a JSON launcher.LoadRequest.
func (s *Server) handleLoadContainer(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)

	// Mutating operation requires manager-level access.
	if !result.HasManagerAccess() {
		s.jsonError(w, http.StatusForbidden, "manager role required for container operations")
		return
	}

	var req launcher.LoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	// Enforce containers claim policy.
	if !result.IsContainerPermitted(req.Image) {
		s.log.Warn("container not permitted by token policy",
			zap.String("image", req.Image),
			zap.String("subject", result.Subject),
		)
		s.jsonError(w, http.StatusForbidden, "container image not permitted by token policy")
		return
	}

	s.log.Info("load container request",
		zap.String("name", req.Name),
		zap.String("image", req.Image),
		zap.Int("port", req.Port),
		zap.Bool("vault_token", req.VaultToken != ""),
		zap.String("storage", req.Storage),
		zap.Bool("storage_key", req.StorageKey != ""),
		zap.String("auth_source", result.Source),
		zap.String("auth_subject", result.Subject),
	)

	digest, err := s.launcher.Load(r.Context(), req)
	if err != nil {
		s.log.Error("failed to load container",
			zap.String("name", req.Name),
			zap.Error(err),
		)
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	containersLoaded.Set(float64(s.launcher.ContainerCount()))

	// If WaitReady is set and a health check is configured, poll the
	// container's health endpoint until it returns 200.  This makes
	// the HTTP response block until the workload (e.g. LLM model) is
	// fully loaded, so the management service can set deployment status
	// to "active" only when traffic can actually be served.
	status := "running"
	if req.WaitReady && req.HealthCheck != nil && req.HealthCheck.HTTP != "" {
		s.log.Info("waiting for container readiness",
			zap.String("name", req.Name),
			zap.String("health_url", req.HealthCheck.HTTP),
		)
		interval := 5 * time.Second
		if req.HealthCheck.IntervalSeconds > 0 {
			interval = time.Duration(req.HealthCheck.IntervalSeconds) * time.Second
		}
		timeout := 10 * time.Minute // generous default for LLM model loading
		deadline := time.Now().Add(timeout)
		hcClient := &http.Client{Timeout: 5 * time.Second}
		ready := false
		for time.Now().Before(deadline) {
			resp, err := hcClient.Get(req.HealthCheck.HTTP)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					ready = true
					break
				}
			}
			time.Sleep(interval)
		}
		if ready {
			status = "ready"
			s.log.Info("container is ready",
				zap.String("name", req.Name),
			)

			// Fetch the model digest from the container's /health
			// endpoint and record it so RA-TLS certs include OID 3.5.
			if resp, err := hcClient.Get(req.HealthCheck.HTTP); err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				var hr struct {
					ModelDigest string `json:"model_digest"`
				}
				if json.Unmarshal(body, &hr) == nil && hr.ModelDigest != "" {
					if digestBytes, err := hex.DecodeString(hr.ModelDigest); err == nil {
						if err := s.launcher.SetModelDigest(req.Name, digestBytes); err != nil {
							s.log.Warn("failed to set model digest",
								zap.String("name", req.Name), zap.Error(err))
						}
					}
				}
			}
		} else {
			status = "running" // model may still be loading
			s.log.Warn("container readiness timeout, returning anyway",
				zap.String("name", req.Name),
			)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"name":   req.Name,
		"image":  req.Image,
		"digest": fmt.Sprintf("%x", digest),
		"status": status,
	})
}

// handleUnloadContainer handles DELETE /api/v1/containers/{name}.
func (s *Server) handleUnloadContainer(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)

	// Mutating operation requires manager-level access.
	if !result.HasManagerAccess() {
		s.jsonError(w, http.StatusForbidden, "manager role required for container operations")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "container name is required")
		return
	}

	// Enforce containers claim policy.
	if !result.IsUnloadPermitted(name) {
		s.log.Warn("container unload not permitted by token policy",
			zap.String("name", name),
			zap.String("subject", result.Subject),
		)
		s.jsonError(w, http.StatusForbidden, "container unload not permitted by token policy")
		return
	}

	s.log.Info("unload container request",
		zap.String("name", name),
		zap.String("auth_source", result.Source),
		zap.String("auth_subject", result.Subject),
	)

	if err := s.launcher.Unload(r.Context(), name); err != nil {
		s.log.Error("failed to unload container",
			zap.String("name", name),
			zap.Error(err),
		)
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	containersLoaded.Set(float64(s.launcher.ContainerCount()))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":   name,
		"status": "unloaded",
	})
}

// tlsUpdateRequest is the request body for PUT /api/v1/tls.
type tlsUpdateRequest struct {
	CACert string `json:"ca_cert"` // PEM-encoded CA certificate
	CAKey  string `json:"ca_key"`  // PEM-encoded CA private key
}

// handleUpdateTLS handles PUT /api/v1/tls.
// It validates the new certificate, blocks CN changes, writes the files,
// reloads Caddy, and recomputes attestation.
func (s *Server) handleUpdateTLS(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)

	if !result.HasManagerAccess() {
		s.jsonError(w, http.StatusForbidden, "manager role required for TLS operations")
		return
	}

	var req tlsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.CACert == "" || req.CAKey == "" {
		s.jsonError(w, http.StatusBadRequest, "ca_cert and ca_key are required")
		return
	}

	// Parse the new certificate.
	newCert, err := parsePEMCertificate([]byte(req.CACert))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid ca_cert: "+err.Error())
		return
	}

	// Validate it's a CA certificate.
	if !newCert.IsCA {
		s.jsonError(w, http.StatusBadRequest, "ca_cert is not a CA certificate (BasicConstraints CA=true required)")
		return
	}

	// Validate the private key is parseable.
	keyBlock, _ := pem.Decode([]byte(req.CAKey))
	if keyBlock == nil {
		s.jsonError(w, http.StatusBadRequest, "ca_key is not valid PEM")
		return
	}

	// Read the current CA certificate to compare CNs.
	currentCertPath := s.launcher.CACertPath()
	if currentCertPath != "" {
		currentPEM, err := os.ReadFile(currentCertPath)
		if err == nil {
			currentCert, err := parsePEMCertificate(currentPEM)
			if err == nil {
				if newCert.Subject.CommonName != currentCert.Subject.CommonName {
					s.log.Warn("TLS update rejected: CN change",
						zap.String("current_cn", currentCert.Subject.CommonName),
						zap.String("new_cn", newCert.Subject.CommonName),
						zap.String("auth_subject", result.Subject),
					)
					s.jsonError(w, http.StatusBadRequest, fmt.Sprintf(
						"CN change not allowed: current %q, new %q — hostname is derived from the intermediary certificate CN",
						currentCert.Subject.CommonName, newCert.Subject.CommonName,
					))
					return
				}
			}
		}
	}

	s.log.Info("TLS certificate update request",
		zap.String("new_cn", newCert.Subject.CommonName),
		zap.Time("not_before", newCert.NotBefore),
		zap.Time("not_after", newCert.NotAfter),
		zap.String("auth_source", result.Source),
		zap.String("auth_subject", result.Subject),
	)

	// Delegate to launcher: write files, reload Caddy, recompute attestation.
	if err := s.launcher.ReloadCA([]byte(req.CACert), []byte(req.CAKey)); err != nil {
		s.log.Error("failed to reload CA", zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, "failed to update TLS certificates: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":     "updated",
		"cn":         newCert.Subject.CommonName,
		"not_before": newCert.NotBefore.Format(time.RFC3339),
		"not_after":  newCert.NotAfter.Format(time.RFC3339),
	})
}

// attestationServersRequest is the request body for PUT /api/v1/attestation-servers.
type attestationServersRequest struct {
	Servers []launcher.AttestationServer `json:"servers"`
}

// handleSetAttestationServers handles PUT /api/v1/attestation-servers.
// It replaces the attestation server list (URLs and optional bearer tokens)
// and triggers a recomputation of the Merkle tree and OID extensions so that
// the change is visible in subsequent RA-TLS certificates.
func (s *Server) handleSetAttestationServers(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)

	if !result.HasManagerAccess() {
		s.jsonError(w, http.StatusForbidden, "manager role required for attestation server operations")
		return
	}

	var req attestationServersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if len(req.Servers) == 0 {
		s.jsonError(w, http.StatusBadRequest, "servers array is required and must not be empty")
		return
	}

	s.log.Info("set attestation servers request",
		zap.Int("servers", len(req.Servers)),
		zap.String("auth_source", result.Source),
		zap.String("auth_subject", result.Subject),
	)

	count, hash := s.launcher.SetAttestationServers(req.Servers)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "attestation_servers_updated",
		"server_count": count,
		"hash":         hash,
	})
}

// parsePEMCertificate decodes a PEM block and parses the X.509 certificate.
func parsePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func (s *Server) jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// handleMetrics serves Prometheus metrics with auth check.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		s.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}
	promhttp.Handler().ServeHTTP(w, r)
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
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
