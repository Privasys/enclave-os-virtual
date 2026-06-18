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
// termination is handled by Caddy with its RA-TLS module,
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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
	"github.com/Privasys/enclave-os-virtual/internal/sessionrelay"
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

	// PlatformHostname is the FQDN routed to the management API itself.
	// Requests with a different Host header are reverse-proxied to the
	// matching app upstream registered via RegisterAppHost. This lets the
	// session-relay middleware (which is mounted on this server) apply
	// uniformly to platform and container traffic — see docs/ra-tls.md.
	PlatformHostname string

	// RegistryPath is the on-disk JSON file persisting every successful
	// container Load so the manager can replay them on restart.
	// Keep it on the per-VM LUKS-encrypted /data volume — entries may
	// contain Env values flagged secret. Volume keys are NOT persisted:
	// vault-backed volumes (KeyHandle) are re-resolved from the
	// constellation on replay. Empty disables persistence (dev/test
	// only).
	RegistryPath string

	// IdpIssuer is the OIDC issuer URL (e.g. "https://privasys.id")
	// used to discover the JWKS for EncAuth voucher verification.
	// When empty, the session-relay middleware accepts only legacy
	// FIDO2-bootstrapped sessions and silently ignores the optional
	// `encauth` field on /__privasys/session-bootstrap.
	IdpIssuer string
}

// Server is the management API server.
type Server struct {
	cfg      Config
	log      *zap.Logger
	launcher *launcher.Launcher
	verifier *auth.Verifier
	server   *http.Server
	// registry persists every successful Load so the manager can replay
	// them on restart. nil when Config.RegistryPath is empty.
	registry *registry
	// sessionRelay handles browser→enclave sealed-CBOR sessions: it owns
	// POST /__privasys/session-bootstrap and transparently unwraps any
	// request whose Content-Type is application/privasys-sealed+cbor
	// before the inner mux sees it (and re-wraps the response).
	sessionRelay *sessionrelay.Manager

	// appHosts maps container Hostname → loopback upstream (e.g.
	// "localhost:8080"). Populated by the launcher via RegisterAppHost.
	appHosts sync.Map // map[string]string

	// appProxy reverse-proxies non-platform Host requests to the upstream
	// looked up in appHosts. Wrapped by sessionRelay.Middleware so that
	// SDK clients can run sealed-CBOR sessions against any container host
	// without the container app having to implement the protocol itself.
	appProxy *httputil.ReverseProxy
}

// New creates a new management API Server.
func New(cfg Config, log *zap.Logger, l *launcher.Launcher, v *auth.Verifier) *Server {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	sr := sessionrelay.NewManager()
	if cfg.IdpIssuer != "" {
		resolver := &sessionrelay.HTTPJWKSResolver{Issuer: cfg.IdpIssuer}
		sr.SetEncAuthVerifier(&sessionrelay.DefaultEncAuthVerifier{Resolver: resolver})
	}
	s := &Server{
		cfg:          cfg,
		log:          log.Named("manager"),
		launcher:     l,
		verifier:     v,
		registry:     newRegistry(cfg.RegistryPath),
		sessionRelay: sr,
	}
	// No plaintext app bodies through intermediaries: when the gateway
	// terminated the public TLS leg it marks the request with
	// X-Privasys-Edge: terminate (and strips any client-supplied value).
	// Plaintext requests for app hosts on that leg are refused so a
	// front-end regression can never silently route user data through
	// the gateway in the clear. Untouched: RA-TLS/splice traffic (no
	// marker — TLS terminates here), the platform mux (token-authed
	// management API, not a user data plane), the bootstrap endpoint
	// (exempted inside the middleware), and well-known metadata.
	sr.SetRequireSealed(func(r *http.Request) bool {
		if r.Header.Get("X-Privasys-Edge") != "terminate" {
			return false
		}
		if _, ok := s.lookupAppHost(hostOnly(r.Host)); !ok {
			return false
		}
		// Liveness/readiness endpoints stay probeable in the clear:
		// they carry no user data and the chat front-end polls them
		// through the gateway before any sealed session exists
		// (reachability probe + model cold-start retry).
		if r.Method == http.MethodGet &&
			(r.URL.Path == "/healthz" || r.URL.Path == "/readiness") {
			return false
		}
		return !strings.HasPrefix(r.URL.Path, "/.well-known/")
	})
	s.appProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			host := hostOnly(pr.In.Host)
			upstream, _ := s.lookupAppHost(host)
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = upstream
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		// Stream SSE / chunked bodies promptly (e.g. /v1/chat/completions).
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Warn("app proxy error",
				zap.String("host", hostOnly(r.Host)),
				zap.String("path", r.URL.Path),
				zap.Error(err))
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return s
}

// RegisterAppHost wires a container hostname to its loopback upstream
// (e.g. "localhost:8080"). Subsequent requests reaching the manager with
// Host == hostname are reverse-proxied there, after passing through the
// session-relay middleware. Idempotent.
func (s *Server) RegisterAppHost(hostname, upstream string) {
	hostname = strings.ToLower(hostname)
	s.appHosts.Store(hostname, upstream)
	s.log.Info("app host registered",
		zap.String("hostname", hostname),
		zap.String("upstream", upstream))
}

// UnregisterAppHost removes a container hostname mapping. Safe to call
// for unknown hostnames.
func (s *Server) UnregisterAppHost(hostname string) {
	hostname = strings.ToLower(hostname)
	s.appHosts.Delete(hostname)
	s.log.Info("app host unregistered", zap.String("hostname", hostname))
}

func (s *Server) lookupAppHost(hostname string) (string, bool) {
	v, ok := s.appHosts.Load(strings.ToLower(hostname))
	if !ok {
		return "", false
	}
	return v.(string), true
}

func hostOnly(h string) string {
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// Start starts the management API server. It blocks until the context is
// cancelled, then gracefully shuts down.
func (s *Server) Start(ctx context.Context) error {
	// Replay persisted apps before opening the listener so they begin
	// pulling/starting immediately. Each Load is async (the launcher
	// returns once the container record is registered as "pulling"),
	// so this loop is fast even for large images.
	if err := s.replayRegistry(ctx); err != nil {
		s.log.Warn("registry replay failed", zap.Error(err))
	}

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

	// Host-driven billing freeze (credits exhausted): pause/resume the
	// container without tearing it down. Manager-role only.
	mux.HandleFunc("POST /api/v1/containers/{name}/freeze", s.requireAuth(s.handleFreezeContainer))

	// SDK setAttestationExtension: container apps call this to install
	// (or update) a per-app X.509 extension under
	// 1.3.6.1.4.1.65230.3.5.*. The new value is reflected in the next
	// RA-TLS cert and forwarded upstream to mgmt-service so it can be
	// replayed across enclave restarts. Authenticated via the container
	// app token (manager role required for this enclave's manager API).
	mux.HandleFunc("POST /api/v1/containers/{name}/attestation-extensions",
		s.requireContainerSelf(s.handleSetAttestationExtension))

	// SDK setConfigComplete: container apps call this from their
	// configure handler after persisting and attesting their
	// configuration. Lifts the manager's freeze gate so subsequent
	// requests on any path are forwarded normally. Idempotent.
	mux.HandleFunc("POST /api/v1/containers/{name}/config-complete",
		s.requireContainerSelf(s.handleSetConfigComplete))

	// TLS certificate rotation (require manager role).
	mux.HandleFunc("PUT /api/v1/tls", s.requireAuth(s.handleUpdateTLS))

	// Attestation server management (require manager role).
	mux.HandleFunc("PUT /api/v1/attestation-servers", s.requireAuth(s.handleSetAttestationServers))

	// Dispatch by Host header so the session-relay middleware can apply
	// uniformly to both the platform API and every container app. Caddy
	// reverse-proxies all RA-TLS hosts (platform + apps) to this manager
	// and now also installs a catch-all fallback for any unknown SNI.
	//
	// App-match-wins: if the Host matches a registered container app, the
	// request goes to that app's loopback upstream; everything else (the
	// configured PlatformHostname AND any unknown SNI from the catch-all
	// fallback, e.g. mgmt-service connecting by IP) hits the platform mux.
	dispatcher := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostOnly(r.Host)
		if _, ok := s.lookupAppHost(host); ok {
			// Freeze gate: if the container declared a config_api at
			// load time and has not yet been configured, serve only
			// requests matching that endpoint and return 503 for
			// everything else. The flag flips to true on the first
			// 2xx response from the configure path.
			containerName := s.launcher.AppHostnameToContainer(host)
			if containerName != "" {
				st := s.launcher.ContainerFreezeState(containerName)
				// Billing freeze (credits exhausted): the container task is
				// paused, so reject all of its traffic with 503 + reason.
				// Attestation is served outside this app-host path, so the
				// chain stays verifiable.
				if st.BillingFrozen {
					w.Header().Set("Retry-After", "30")
					s.jsonError(w, http.StatusServiceUnavailable, "app paused: "+st.BillingReason)
					return
				}
				if st.ConfigAPI != nil && !st.Configured {
					if !matchesConfigAPI(st.ConfigAPI, r) {
						w.Header().Set("Retry-After", "5")
						s.jsonError(w, http.StatusServiceUnavailable, "container is awaiting initial configuration")
						return
					}
					// Wrap the writer so we can flip the flag on 2xx.
					rw := &statusRecorder{ResponseWriter: w}
					s.appProxy.ServeHTTP(rw, r)
					if rw.status >= 200 && rw.status < 300 {
						s.launcher.MarkConfigured(containerName)
						s.log.Info("container configured (freeze lifted)",
							zap.String("container", containerName))
					}
					return
				}
			}
			s.appProxy.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	s.server = &http.Server{
		Addr:    s.cfg.Addr,
		Handler: s.metricsMiddleware(s.sessionRelay.Middleware(dispatcher)),
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

// requireContainerSelf wraps a handler that may only be called by a
// container running inside this enclave, targeting itself. The caller
// MUST come from a loopback address (the manager and all containers
// share the host network namespace) and MUST present the
// launcher-minted PRIVASYS_CONTAINER_TOKEN as a Bearer token whose
// matching container name equals the {name} path parameter.
//
// This is NOT OIDC authentication \u2014 it only binds an in-enclave
// self-targeted call to the calling container's identity so that
// container A cannot install OID extensions or lift the freeze gate
// of container B.
func (s *Server) requireContainerSelf(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Loopback only \u2014 the only legitimate caller is a container
		// in the same host network namespace.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !isLoopbackHost(host) {
			s.log.Debug("requireContainerSelf: non-loopback caller rejected",
				zap.String("remote", r.RemoteAddr))
			s.jsonError(w, http.StatusForbidden, "this endpoint is reachable only from inside the enclave")
			return
		}
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			s.jsonError(w, http.StatusUnauthorized, "expected Bearer PRIVASYS_CONTAINER_TOKEN")
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		boundName := s.launcher.LookupContainerByToken(token)
		if boundName == "" {
			s.jsonError(w, http.StatusUnauthorized, "invalid container token")
			return
		}
		pathName := r.PathValue("name")
		if pathName == "" || pathName != boundName {
			s.log.Warn("requireContainerSelf: container attempted to act on another container",
				zap.String("token_bound_to", boundName),
				zap.String("requested", pathName))
			s.jsonError(w, http.StatusForbidden, "container token does not match {name} in path")
			return
		}
		next(w, r)
	}
}

// isLoopbackHost returns true for any IPv4/IPv6 loopback address.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Caddy / proxies might send "localhost"; the only entries we
		// expect on RemoteAddr are bare IPs from net.Listen, but be
		// defensive.
		return host == "localhost"
	}
	return ip.IsLoopback()
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
		zap.String("storage", req.Storage),
		zap.String("key_handle", req.KeyHandle),
		zap.String("auth_source", result.Source),
		zap.String("auth_subject", result.Subject),
	)

	// Run Load asynchronously: image pull + container start can take
	// minutes (large images, cold containerd cache). The management
	// service polls GET /api/v1/status to track progress and health,
	// so the HTTP handler returns 202 immediately after kicking off
	// the load goroutine. container.Pull registers a "pulling" stub
	// before the network call so the container is visible in status
	// queries right away.
	go func() {
		// Use Background ctx: r.Context() is cancelled when this
		// handler returns, which would abort the pull mid-flight.
		//
		// Replace-on-reload: Load rejects an already-loaded name, so a
		// re-deploy with a new image or port would otherwise be a silent
		// no-op (the management-service treats "already loaded" as success).
		// Unload first so the new spec actually applies. This is a no-op when
		// nothing is loaded, and it PRESERVES vault-keyed volumes (Unload
		// closes, never removes, them — the new Load re-attaches the data).
		// Boot replay (replayRegistry) calls launcher.Load directly, so it is
		// unaffected.
		if err := s.launcher.Unload(context.Background(), req.Name); err != nil &&
			!strings.Contains(err.Error(), "not loaded") {
			s.log.Warn("pre-load unload failed (continuing with load)",
				zap.String("name", req.Name), zap.Error(err))
		}
		if _, err := s.launcher.Load(context.Background(), req); err != nil {
			s.log.Error("async load failed",
				zap.String("name", req.Name),
				zap.Error(err),
			)
			return
		}
		// Persist for replay-on-restart only after a successful Load.
		if err := s.registry.Save(req); err != nil {
			s.log.Warn("registry save failed (container is running but won't auto-restart)",
				zap.String("name", req.Name),
				zap.Error(err),
			)
		}
		containersLoaded.Set(float64(s.launcher.ContainerCount()))
	}()

	// WaitReady is deprecated. Container health transitions are tracked
	// asynchronously by the background health check goroutine and exposed
	// via GET /api/v1/status. The management service polls that endpoint
	// to detect readiness instead of blocking the deploy HTTP call.
	if req.WaitReady {
		s.log.Info("ignoring deprecated WaitReady flag, returning immediately",
			zap.String("name", req.Name),
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"name":   req.Name,
		"image":  req.Image,
		"status": "loading",
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

	if err := s.registry.Remove(name); err != nil {
		s.log.Warn("registry remove failed (container is gone but stale entry remains)",
			zap.String("name", name),
			zap.Error(err),
		)
	}

	containersLoaded.Set(float64(s.launcher.ContainerCount()))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":   name,
		"status": "unloaded",
	})
}

// handleFreezeContainer handles POST /api/v1/containers/{name}/freeze. The
// management-service applies or lifts the host-driven billing freeze (credits
// exhausted): a frozen container is paused (cgroup freezer) and its traffic is
// 503'd; unfreezing resumes it. Manager-role only, idempotent.
func (s *Server) handleFreezeContainer(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasManagerAccess() {
		s.jsonError(w, http.StatusForbidden, "manager role required for container operations")
		return
	}
	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "container name is required")
		return
	}
	var req struct {
		Frozen bool   `json:"frozen"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Frozen && req.Reason == "" {
		req.Reason = "credits_exhausted"
	}
	if err := s.launcher.SetBillingFrozen(r.Context(), name, req.Frozen, req.Reason); err != nil {
		s.log.Error("failed to set billing freeze",
			zap.String("name", name), zap.Bool("frozen", req.Frozen), zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("billing freeze updated",
		zap.String("name", name), zap.Bool("frozen", req.Frozen), zap.String("reason", req.Reason))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "frozen": req.Frozen})
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

// handleSetAttestationExtension handles
// POST /api/v1/containers/{name}/attestation-extensions.
// Body: {"oid":"1.3.6.1.4.1.65230.3.5.<n>", "value_b64":"..."}.
// Installs the extension in-process so the next RA-TLS cert reflects
// it, and emits an event for the management service to persist for
// replay across enclave restarts.
func (s *Server) handleSetAttestationExtension(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "container name is required")
		return
	}
	var req struct {
		OID      string `json:"oid"`
		ValueB64 string `json:"value_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.OID == "" || req.ValueB64 == "" {
		s.jsonError(w, http.StatusBadRequest, "oid and value_b64 are required")
		return
	}
	value, err := base64.StdEncoding.DecodeString(req.ValueB64)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "value_b64 is not valid base64: "+err.Error())
		return
	}
	if err := s.launcher.SetAttestationExtension(name, req.OID, value); err != nil {
		s.jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleSetConfigComplete handles
// POST /api/v1/containers/{name}/config-complete.
// No body required. Flips the in-process freeze flag so the
// manager forwards subsequent requests on any path. Idempotent —
// returns 200 even when the container is already configured.
func (s *Server) handleSetConfigComplete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "container name is required")
		return
	}
	st := s.launcher.ContainerFreezeState(name)
	if st.ConfigAPI == nil {
		// Container did not declare a config_api at load time;
		// nothing to unfreeze. Treat as success so callers can
		// invoke the API unconditionally.
		s.log.Info("config-complete called on container without config_api (no-op)",
			zap.String("container", name))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "frozen": "false"})
		return
	}
	s.launcher.MarkConfigured(name)
	s.log.Info("container configured via setConfigComplete (freeze lifted)",
		zap.String("container", name))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

// statusRecorder is a minimal http.ResponseWriter wrapper used by the
// freeze gate to detect a 2xx response from the configure endpoint
// without disturbing the body stream (the proxy may use chunked or SSE
// transfer; we deliberately do not buffer it).
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.status = http.StatusOK
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// matchesConfigAPI reports whether the inbound request matches the
// container's declared configure endpoint. Method match is
// case-insensitive; path is matched literally (no globs).
func matchesConfigAPI(spec *launcher.ConfigAPISpec, r *http.Request) bool {
	if spec == nil {
		return false
	}
	if !strings.EqualFold(spec.Method, r.Method) {
		return false
	}
	return r.URL.Path == spec.Path
}

// replayRegistry re-issues launcher.Load for every entry persisted in
// the registry. This runs once at Server.Start before the HTTP listener
// opens so apps begin pulling/starting immediately on a manager
// restart, without waiting for the management-service reconciler to
// notice. Each Load is invoked in its own goroutine so a single slow
// pull does not block startup. Errors are logged but never propagated:
// the manager must come up even if some apps fail to relaunch (the
// reconciler will catch up).
func (s *Server) replayRegistry(ctx context.Context) error {
	if s.registry == nil {
		return nil
	}
	entries, err := s.registry.List()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	s.log.Info("replaying persisted apps",
		zap.Int("count", len(entries)),
		zap.String("path", s.cfg.RegistryPath),
	)

	// Deduplicate by host port: two entries on the same port would
	// race at container start and only one can bind. Keep the first
	// occurrence in registry order and skip the rest with a warning.
	// This prevents the post-reboot lockup we hit when a stale app
	// (e.g. an e2e benchmark) was still pinned to the same port as
	// the production app.
	seenPort := make(map[int]string, len(entries))
	deduped := make([]launcher.LoadRequest, 0, len(entries))
	for _, e := range entries {
		if e.Port > 0 {
			if owner, ok := seenPort[e.Port]; ok {
				s.log.Warn("registry replay: skipping port collision",
					zap.String("name", e.Name),
					zap.String("conflicts_with", owner),
					zap.Int("port", e.Port),
				)
				continue
			}
			seenPort[e.Port] = e.Name
		}
		deduped = append(deduped, e)
	}

	for _, e := range deduped {
		req := e
		go func() {
			// Wait until launcher.Run() has connected to containerd —
			// otherwise launcher.Load() panics dereferencing a nil
			// l.mgr. Server.Start runs in parallel with launcher.Run,
			// so on a fresh start we typically wait a few hundred
			// milliseconds here.
			waitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := s.launcher.WaitReady(waitCtx); err != nil {
				s.log.Warn("replay aborted: launcher not ready",
					zap.String("name", req.Name),
					zap.Error(err),
				)
				return
			}
			s.log.Info("replaying load",
				zap.String("name", req.Name),
				zap.String("image", req.Image),
			)
			if _, err := s.launcher.Load(context.Background(), req); err != nil {
				s.log.Warn("replay load failed",
					zap.String("name", req.Name),
					zap.Error(err),
				)
			}
		}()
	}
	return nil
}
