package manager

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/sessionrelay"
	"github.com/Privasys/enclave-os-virtual/internal/surfaces"
)

// The clear leg. A request that reaches an app in plaintext on the
// gateway-terminated leg (X-Privasys-Edge: terminate) is only let through
// when the app declared the route as a static or public surface
// (internal/surfaces). Whatever is let through is served anonymous by
// construction, so that a developer mistake cannot turn a public route into
// a channel for account data past the gateway:
//
//   - request headers are reduced to an allow-list (plus the route's declared
//     ones); a credential that still arrived is dropped AND counted, so the
//     developer sees on dev that a bearer or cookie crossed the gateway;
//   - response headers are reduced to an allow-list, so an app cannot plant a
//     cookie on its origin (which the browser would then send on every later
//     request) or leak an identity in a header;
//   - no identity is ever asserted (X-Privasys-Sub stays absent, the spend
//     gate sees no token), and X-Privasys-Transport: public tells the app
//     which leg it is on;
//   - a per-client token bucket bounds the rate, since a trusted certificate
//     on an unauthenticated route is otherwise a free denial-of-service
//     surface;
//   - no Upgrade, and OPTIONS is answered here when the app opened CORS.
//
// The declaration is measured (it rides the image's manifest label), so a
// verifier reads off the image exactly which routes an app serves in the
// clear, and the launcher refuses an image that declares a priced or a
// configure route public.

// TransportHeader tells the app which leg a request arrived on. Only the
// runtime sets it; any inbound value is stripped on every path.
//
//   - "sealed":   unsealed by the session relay from a sealed session;
//   - "attested": TLS ended at the enclave (RA-TLS direct, mutual RA-TLS);
//   - "public":   plaintext on the gateway-terminated leg, on a declared
//     static or public surface. Anonymous; the gateway read it.
//   - "direct":   plaintext on a direct adopter name: TLS ended here with a
//     publicly trusted certificate, so nobody but the enclave read it, but
//     the client verified no attestation. Same rules as "public" otherwise.
const TransportHeader = sessionrelay.TransportHeader

const (
	TransportSealed   = sessionrelay.TransportSealed
	TransportAttested = "attested"
	TransportPublic   = "public"
	TransportDirect   = "direct"
)

// edgeHeader is the gateway's trusted marker that it terminated TLS on
// this leg (and stripped any client-supplied value).
const edgeHeader = "X-Privasys-Edge"

var (
	publicRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "enclave_os",
			Name:      "public_requests_total",
			Help:      "Requests served in the clear on a declared surface, by host and outcome.",
		},
		[]string{"host", "outcome"},
	)
	publicCredentialsSeen = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "enclave_os",
			Name:      "public_credentials_seen_total",
			Help:      "Requests on a public surface that arrived with a credential header (dropped before the app).",
		},
		[]string{"host"},
	)
)

func init() {
	prometheus.MustRegister(publicRequests, publicCredentialsSeen)
}

// publicRequestAllow are the request headers that survive on a public or
// static route. Everything else is deleted before the app sees the request;
// a route may add its own (a webhook signature) through its declaration.
var publicRequestAllow = canonical(map[string]bool{
	"Accept":            true,
	"Accept-Encoding":   true,
	"Accept-Language":   true,
	"Cache-Control":     true,
	"Content-Type":      true,
	"Content-Length":    true,
	"If-None-Match":     true,
	"If-Modified-Since": true,
	"Range":             true,
	"User-Agent":        true,
	"Origin":            true,
	"X-Forwarded-Proto": true,
	"X-Forwarded-Host":  true,
	// Hop-by-hop headers the proxy manages itself.
	"Connection": true, "Transfer-Encoding": true, "Te": true,
})

// publicResponseAllow are the response headers that survive on a public or
// static route. Set-Cookie is deliberately absent: with no cookie ever set on
// the app origin there is nothing for a browser to send back past the
// gateway. The CORS set is added by the runtime itself.
var publicResponseAllow = canonical(map[string]bool{
	"Content-Type":        true,
	"Content-Length":      true,
	"Content-Encoding":    true,
	"Content-Disposition": true,
	"Content-Range":       true,
	"Accept-Ranges":       true,
	"Cache-Control":       true,
	"Expires":             true,
	"ETag":                true,
	"Last-Modified":       true,
	"Location":            true,
	"Retry-After":         true,
	"Vary":                true,
	"Date":                true,
	"Transfer-Encoding":   true,
})

// canonical rekeys an allow-list by canonical header name, so "ETag" and
// "Etag" are one entry.
func canonical(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}

// credentialHeaders are counted when they arrive on a public route: each one
// is a credential the gateway has already seen.
var credentialHeaders = []string{"Authorization", "Cookie", "X-App-Auth", "X-Privasys-Spend", "X-Privasys-Spend-Proof"}

// SetSurfaces records what a Host serves in the clear on the
// gateway-terminated leg (implements launcher.AppHostRouter). nil clears it.
func (s *Server) SetSurfaces(hostname string, surf *surfaces.Surfaces) {
	hostname = strings.ToLower(hostname)
	if surf.Empty() {
		s.surfaces.Delete(hostname)
		s.publicLimiter.forget(hostname)
		return
	}
	s.surfaces.Store(hostname, surf)
}

// SetStaticUnsealedPrefixes is the pre-manifest declaration: static prefixes
// only. Kept for the launcher.AppHostRouter contract of older callers and
// the tests; new code calls SetSurfaces.
func (s *Server) SetStaticUnsealedPrefixes(hostname string, prefixes []string) {
	if len(prefixes) == 0 {
		s.SetSurfaces(hostname, nil)
		return
	}
	cp := make([]string, len(prefixes))
	copy(cp, prefixes)
	s.SetSurfaces(hostname, &surfaces.Surfaces{Static: cp})
}

func (s *Server) surfacesOf(hostname string) *surfaces.Surfaces {
	v, ok := s.surfaces.Load(strings.ToLower(hostname))
	if !ok {
		return nil
	}
	return v.(*surfaces.Surfaces)
}

// isStaticUnsealedPath reports whether path is one of host's declared static
// prefixes (GET/HEAD shell). The data plane is never static.
func (s *Server) isStaticUnsealedPath(hostname, path string) bool {
	return s.surfacesOf(hostname).IsStatic(path)
}

// clearAllowed reports whether a plaintext request on the gateway-terminated
// leg is on a declared surface and may be served: a static GET/HEAD, a
// declared public route, or a CORS preflight for a public path when the app
// opened CORS.
func (s *Server) clearAllowed(r *http.Request) bool {
	surf := s.surfacesOf(hostOnly(r.Host))
	if surf == nil {
		return false
	}
	if r.Method == http.MethodOptions {
		return surf.OpenCORS() && len(surf.PublicMethods(r.URL.Path)) > 0
	}
	return surf.Covers(r.Method, r.URL.Path)
}

// isEdgeTerminated reports whether the gateway terminated TLS on this leg.
func isEdgeTerminated(r *http.Request) bool {
	return r.Header.Get(edgeHeader) == "terminate"
}

// isDirectLeg reports whether the request arrived on a direct adopter name
// with the publicly trusted certificate. Caddy's privasys_attest handler sets
// the marker from the connection (and overwrites a client's), so a direct
// request can never pass as RA-TLS.
func isDirectLeg(r *http.Request) bool {
	return r.Header.Get(edgeHeader) == "direct"
}

// isClearLeg reports whether the client did not verify the enclave: the
// gateway-terminated leg or a direct name. Both get the same rules: sealed
// bodies, or a declared static or public surface.
func isClearLeg(r *http.Request) bool {
	return isEdgeTerminated(r) || isDirectLeg(r)
}

// clearTransport is the transport stamp of a plaintext request on a clear leg.
func clearTransport(r *http.Request) string {
	if isDirectLeg(r) {
		return TransportDirect
	}
	return TransportPublic
}

// servePublic applies the clear-leg treatment to a request the predicate let
// through, and returns the writer the rest of the chain must use. ok is
// false when the request was answered here (preflight, refusal, rate limit).
func (s *Server) servePublic(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, bool) {
	host := hostOnly(r.Host)
	// Read before the header scrub below removes the leg marker.
	transport := clearTransport(r)
	surf := s.surfacesOf(host)
	if surf == nil {
		// Let through by the predicate on its own exemptions (/healthz,
		// /readiness, /.well-known/*) with nothing declared: same
		// anonymous treatment, default limits, no CORS.
		surf = &surfaces.Surfaces{}
	}
	path := r.URL.Path
	_, isPublicRoute := surf.PublicRoute(r.Method, path)
	isPreflight := r.Method == http.MethodOptions

	// A WebSocket or any other upgrade is never public: the sealed mux is the
	// only browser socket, and there is no anonymous version of it.
	if r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		s.jsonError(w, http.StatusForbidden, "no upgrade on a public route")
		publicRequests.WithLabelValues(host, "refused").Inc()
		return nil, false
	}

	client := clientAddress(r)
	if !s.publicLimiter.allow(host, client, surf.RPS(), surf.Burst()) {
		w.Header().Set("Retry-After", "1")
		s.jsonError(w, http.StatusTooManyRequests, "too many requests on a public route")
		publicRequests.WithLabelValues(host, "limited").Inc()
		return nil, false
	}

	if isPreflight {
		// Only reached when the app opened CORS and a public route covers
		// the path (clearAllowed). No credentials, ever.
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", strings.Join(surf.PublicMethods(path), ", "))
		allowHeaders := append([]string{"Accept", "Content-Type"}, surf.PublicHeaders(path)...)
		h.Set("Access-Control-Allow-Headers", strings.Join(allowHeaders, ", "))
		h.Set("Access-Control-Max-Age", "600")
		h.Set(TransportHeader, transport)
		w.WriteHeader(http.StatusNoContent)
		publicRequests.WithLabelValues(host, "preflight").Inc()
		return nil, false
	}

	// Anonymous by construction: keep the allow-list plus the route's own
	// headers, drop everything else, and count a credential that arrived.
	allowed := func(name string) bool {
		if publicRequestAllow[name] {
			return true
		}
		for _, h := range surf.PublicHeaders(path) {
			if h == name {
				return true
			}
		}
		return false
	}
	seenCredential := false
	for _, h := range credentialHeaders {
		if r.Header.Get(h) != "" {
			seenCredential = true
			break
		}
	}
	for name := range r.Header {
		if !allowed(name) {
			r.Header.Del(name)
		}
	}
	// The app gets the client address but not the full chain.
	if client != "" {
		r.Header.Set("X-Forwarded-For", client)
	}
	r.Header.Set(TransportHeader, transport)
	if seenCredential {
		publicCredentialsSeen.WithLabelValues(host).Inc()
		s.publicLimiter.noteCredential(host)
		s.log.Warn("a credential arrived on a public route; dropped before the app",
			zap.String("transport", transport),
			zap.String("host", host), zap.String("method", r.Method), zap.String("path", path))
	}

	pw := &publicResponseWriter{
		ResponseWriter: w,
		cors:           isPublicRoute && surf.OpenCORS(),
		static:         !isPublicRoute,
		transport:      transport,
	}
	start := time.Now()
	s.log.Info("public request",
		zap.String("host", host), zap.String("method", r.Method), zap.String("path", path),
		zap.String("client", client))
	return &timedPublicWriter{publicResponseWriter: pw, s: s, host: host, method: r.Method, path: path, start: start}, true
}

// clientAddress is the client the gateway saw: the last X-Forwarded-For
// entry, which the gateway's reverse proxy appends and a client cannot
// unset. Without one (an RA-TLS-direct test client), the connection's own
// address.
func clientAddress(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
			return last
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// publicResponseWriter reduces an app's response headers to the allow-list
// and adds the runtime's own markers before the headers go out.
type publicResponseWriter struct {
	http.ResponseWriter
	cors        bool
	static      bool
	transport   string // TransportPublic or TransportDirect
	wroteHeader bool
	status      int
}

func (w *publicResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
	h := w.ResponseWriter.Header()
	for name := range h {
		if !publicResponseAllow[name] {
			h.Del(name)
		}
	}
	transport := w.transport
	if transport == "" {
		transport = TransportPublic
	}
	h.Set(TransportHeader, transport)
	if w.cors {
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", "Content-Type, ETag, Last-Modified, Retry-After, "+TransportHeader)
	}
	if w.static {
		h.Set("Referrer-Policy", "same-origin")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *publicResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *publicResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	// The writer underneath may only expose Flush through Unwrap (the
	// metrics wrapper does), which ResponseController follows.
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// No Unwrap on purpose: a public writer must never be hijacked for an
// upgrade (servePublic refuses upgrades before this writer exists).

// timedPublicWriter records the outcome once the app has answered.
type timedPublicWriter struct {
	*publicResponseWriter
	s                  *Server
	host, method, path string
	start              time.Time
	done               bool
}

func (w *timedPublicWriter) WriteHeader(code int) {
	w.publicResponseWriter.WriteHeader(code)
	w.record()
}

func (w *timedPublicWriter) Write(p []byte) (int, error) {
	n, err := w.publicResponseWriter.Write(p)
	w.record()
	return n, err
}

func (w *timedPublicWriter) record() {
	if w.done {
		return
	}
	w.done = true
	outcome := fmt.Sprintf("%dxx", w.status/100)
	publicRequests.WithLabelValues(w.host, outcome).Inc()
	w.s.log.Info("public response",
		zap.String("host", w.host), zap.String("method", w.method), zap.String("path", w.path),
		zap.Int("status", w.status), zap.Duration("duration", time.Since(w.start)))
}

// publicLimiter is a per-(host, client) token bucket. Buckets idle for a
// while are swept so the map cannot grow with the number of clients seen.
type publicLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	creds   map[string]uint64
	lastGC  time.Time
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const limiterGCInterval = time.Minute
const limiterIdle = 5 * time.Minute

func newPublicLimiter() *publicLimiter {
	return &publicLimiter{buckets: map[string]*bucket{}, creds: map[string]uint64{}, now: time.Now}
}

func (l *publicLimiter) allow(host, client string, rps float64, burst int) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastGC) >= limiterGCInterval {
		for k, b := range l.buckets {
			if now.Sub(b.last) > limiterIdle {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	key := host + "|" + client
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: float64(burst), last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rps
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *publicLimiter) forget(host string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.buckets {
		if strings.HasPrefix(k, host+"|") {
			delete(l.buckets, k)
		}
	}
	delete(l.creds, host)
}

func (l *publicLimiter) noteCredential(host string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.creds[host]++
	l.mu.Unlock()
}

// PublicCredentialsSeen reports, per app host, how many requests on a public
// surface arrived with a credential since the manager started. The control
// plane shows it to the developer: each one is a credential the gateway read.
func (s *Server) PublicCredentialsSeen() map[string]uint64 {
	if s.publicLimiter == nil {
		return nil
	}
	s.publicLimiter.mu.Lock()
	defer s.publicLimiter.mu.Unlock()
	out := make(map[string]uint64, len(s.publicLimiter.creds))
	for h, n := range s.publicLimiter.creds {
		out[h] = n
	}
	return out
}

// Surfaces reports, per app host, the declared surfaces (for the containers
// status the control plane reads).
func (s *Server) SurfacesSummary(hostname string) string {
	return s.surfacesOf(hostname).Summary()
}
