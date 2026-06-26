// Package caddy provides a client for the Caddy admin API, used to
// dynamically add and remove reverse-proxy routes with RA-TLS termination
// for containers managed by Enclave OS (Virtual).
//
// Architecture:
//
//	Client (RA-TLS) → Caddy (:443) → Container (localhost:PORT)
//	Operator (RA-TLS) → Caddy (:443) → Manager API (localhost:PORT)
//
// Caddy is the sole TLS terminator. Its RA-TLS module (caddy/ratls/)
// generates certificates with hardware attestation evidence (TDX/SGX
// quotes) and per-hostname OID extensions loaded from the extensions
// directory.
//
// This client manages Caddy's JSON config via the admin API:
//   - POST /load with the full config after every route change
//   - Routes are maintained in memory and serialised on each update
package caddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Config holds the static Caddy configuration that does not change
// between route additions/removals.
type Config struct {
	// AdminAddr is the Caddy admin API address.
	// Defaults to "localhost:2019".  Use "unix//path/to/socket" for
	// Unix domain sockets.
	AdminAddr string

	// ListenAddr is the external HTTPS listen address (e.g. ":443").
	ListenAddr string

	// Backend is the TEE attestation backend ("tdx" or "sev-snp").
	Backend string

	// CACertPath is the intermediary CA certificate for RA-TLS.
	CACertPath string

	// CAKeyPath is the intermediary CA private key.
	CAKeyPath string

	// ExtensionsDir is the directory where the manager writes per-hostname
	// OID extension files (<hostname>.json).
	ExtensionsDir string
}

// route is an internal representation of a Caddy reverse-proxy route.
type route struct {
	Hostname string
	Upstream string // "localhost:PORT"
}

// Client manages Caddy routes via the admin API.
type Client struct {
	cfg    Config
	log    *zap.Logger
	client *http.Client

	mu       sync.Mutex
	routes   map[string]route // hostname → route
	fallback string           // catch-all upstream ("" = no fallback); see SetFallback
}

// NewClient creates a new Caddy admin API client.
func NewClient(cfg Config, log *zap.Logger) *Client {
	if cfg.AdminAddr == "" {
		cfg.AdminAddr = "localhost:2019"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":443"
	}

	httpClient := &http.Client{}

	// Support Unix domain sockets.
	if len(cfg.AdminAddr) > 5 && cfg.AdminAddr[:5] == "unix/" {
		socketPath := cfg.AdminAddr[4:] // strip "unix"
		httpClient.Transport = &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		}
	}

	return &Client{
		cfg:    cfg,
		log:    log.Named("caddy"),
		client: httpClient,
		routes: make(map[string]route),
	}
}

// AddRoute registers a reverse-proxy route for the given hostname,
// forwarding traffic to the upstream address (e.g. "localhost:8080").
// The route is protected by RA-TLS via the ra_tls issuer.
func (c *Client) AddRoute(hostname, upstream string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.routes[hostname] = route{
		Hostname: hostname,
		Upstream: upstream,
	}

	c.log.Info("adding Caddy route",
		zap.String("hostname", hostname),
		zap.String("upstream", upstream))

	return c.reload()
}

// RemoveRoute removes the reverse-proxy route for the given hostname.
func (c *Client) RemoveRoute(hostname string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.routes[hostname]; !ok {
		return fmt.Errorf("caddy: no route for hostname %q", hostname)
	}

	delete(c.routes, hostname)

	c.log.Info("removing Caddy route",
		zap.String("hostname", hostname))

	return c.reload()
}

// RouteCount returns the number of active routes.
func (c *Client) RouteCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.routes)
}

// SetFallback registers a catch-all reverse-proxy upstream emitted as the
// LAST route in the generated Caddy config (no host matcher). It lets the
// management API answer for any TLS SNI value, which the platform relies on
// now that the legacy `enclaves.host` SNI is gone — mgmt-service connects
// to the enclave by IP and sends an arbitrary SNI; the RA-TLS issuer mints a
// fresh cert for whatever SNI it sees, and this fallback ensures the request
// is then routed to the management mux.
//
// Pass an empty string to clear the fallback.
func (c *Client) SetFallback(upstream string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fallback = upstream
	c.log.Info("setting Caddy fallback upstream",
		zap.String("upstream", upstream))
	return c.reload()
}

// Reload forces a full Caddy config reload. This is used after updating
// the CA certificate/key so the RA-TLS module picks up the new files.
func (c *Client) Reload() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reload()
}

// ---------------------------------------------------------------------------
// Caddy JSON config generation
// ---------------------------------------------------------------------------

// reload posts the full Caddy config to the admin API.  Must be called
// with c.mu held.
//
// Transport errors (admin endpoint not yet listening on :2019) are
// retried for a bounded window: caddy.service and manager.service start
// concurrently, and the systemd "started" state does not guarantee the
// admin socket is already bound. Without this, the manager's first route
// registration at boot loses the race and returns a fatal error, killing
// the manager (it self-heals on the systemd restart, but with a multi-
// second gap that flakes e2e runs and drops runtime-status pushes). A
// non-200 response is a real config error and is returned immediately.
func (c *Client) reload() error {
	cfg := c.buildConfig()

	body, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("caddy: failed to marshal config: %w", err)
	}

	url := c.adminURL("/load")

	const (
		adminReadyTimeout = 30 * time.Second
		retryInterval     = 500 * time.Millisecond
	)
	deadline := time.Now().Add(adminReadyTimeout)

	for attempt := 1; ; attempt++ {
		resp, err := c.client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			// A transport error means the admin endpoint isn't reachable
			// yet (boot ordering race, or Caddy mid-restart). Retry until
			// the deadline before treating it as fatal.
			if time.Now().Before(deadline) {
				c.log.Debug("Caddy admin not ready, retrying /load",
					zap.Int("attempt", attempt),
					zap.Error(err))
				time.Sleep(retryInterval)
				continue
			}
			return fmt.Errorf("caddy: failed to POST /load after %s: %w", adminReadyTimeout, err)
		}

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("caddy: /load returned %d: %s", resp.StatusCode, string(respBody))
		}
		resp.Body.Close()

		c.log.Debug("Caddy config reloaded",
			zap.Int("routes", len(c.routes)),
			zap.Int("attempts", attempt))

		return nil
	}
}

// buildConfig generates the full Caddy JSON config from the current routes.
func (c *Client) buildConfig() map[string]any {
	// Build sorted route list for deterministic output.
	hostnames := make([]string, 0, len(c.routes))
	for h := range c.routes {
		hostnames = append(hostnames, h)
	}
	sort.Strings(hostnames)

	routes := make([]map[string]any, 0, len(c.routes)+1)
	for _, h := range hostnames {
		r := c.routes[h]
		routes = append(routes, map[string]any{
			"match": []map[string]any{
				{"host": []string{r.Hostname}},
			},
			"handle": []map[string]any{
				{
					"handler":   "reverse_proxy",
					"upstreams": []map[string]any{{"dial": r.Upstream}},
					// flush_interval: -1 forces Caddy to flush every
					// upstream write to the client immediately. Caddy
					// auto-detects text/event-stream and does this on its
					// own, but we set it explicitly so any non-SSE
					// streaming response (chunked JSONL, raw bytes from
					// confidential-ai's /v1/completions, etc.) also gets
					// per-write cadence. Removing buffering here is what
					// makes vLLM token-by-token chat actually feel
					// token-by-token in the browser.
					"flush_interval": -1,
					"transport": map[string]any{
						"protocol":                "http",
						"response_header_timeout": "15m",
						"read_timeout":            "15m",
						"write_timeout":           "15m",
					},
				},
			},
		})
	}

	// Catch-all fallback emitted LAST. Caddy evaluates routes in order and
	// stops at the first match; a route with no `match` clause matches
	// everything.
	if c.fallback != "" {
		routes = append(routes, map[string]any{
			"handle": []map[string]any{
				{
					"handler":        "reverse_proxy",
					"upstreams":      []map[string]any{{"dial": c.fallback}},
					"flush_interval": -1,
					"transport": map[string]any{
						"protocol":                "http",
						"response_header_timeout": "15m",
						"read_timeout":            "15m",
						"write_timeout":           "15m",
					},
				},
			},
		})
	}

	// Build the RA-TLS cert getter config. The cert getter module handles
	// both deterministic and challenge-response attestation, with its own
	// internal cache for non-challenge connections. Using get_certificate
	// exclusively (without issuers) ensures that challenge-response
	// connections bypass certmagic's cert cache and always receive a fresh
	// certificate bound to the client's nonce.
	certGetter := map[string]any{
		"via":          "ra_tls",
		"backend":      c.cfg.Backend,
		"ca_cert_path": c.cfg.CACertPath,
		"ca_key_path":  c.cfg.CAKeyPath,
	}
	if c.cfg.ExtensionsDir != "" {
		certGetter["extensions_dir"] = c.cfg.ExtensionsDir
	}

	return map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen": []string{c.cfg.ListenAddr},
						"routes": routes,
						// Disable Caddy's auto-HTTPS machinery: we never want
						// Caddy to derive cert identifiers from route hosts and
						// fall through to ACME / on-demand permission checks.
						// All certs come from the RA-TLS get_certificate
						// module below.
						"automatic_https": map[string]any{
							"disable": true,
						},
						// Empty connection policy ([{}]) matches every
						// ClientHello, including empty-SNI handshakes from Go
						// HTTP clients dialing https://IP:port (Go strips
						// IP-literal SNI per RFC 6066). Without this the http
						// server has no policy to apply when SNI is missing
						// and rejects with TLS alert 80 before invoking the
						// cert getter.
						"tls_connection_policies": []map[string]any{{}},
					},
				},
			},
			"tls": map[string]any{
				"automation": map[string]any{
					"policies": []map[string]any{
						{
							"get_certificate": []map[string]any{certGetter},
						},
					},
				},
			},
		},
	}
}

// adminURL returns the full URL to the Caddy admin API endpoint.
func (c *Client) adminURL(path string) string {
	if len(c.cfg.AdminAddr) > 5 && c.cfg.AdminAddr[:5] == "unix/" {
		return "http://caddy" + path // host is ignored for Unix sockets
	}
	return "http://" + c.cfg.AdminAddr + path
}
