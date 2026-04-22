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

	mu     sync.Mutex
	routes map[string]route // hostname → route
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
func (c *Client) reload() error {
	cfg := c.buildConfig()

	body, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("caddy: failed to marshal config: %w", err)
	}

	url := c.adminURL("/load")
	resp, err := c.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("caddy: failed to POST /load: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy: /load returned %d: %s", resp.StatusCode, string(respBody))
	}

	c.log.Debug("Caddy config reloaded",
		zap.Int("routes", len(c.routes)))

	return nil
}

// buildConfig generates the full Caddy JSON config from the current routes.
func (c *Client) buildConfig() map[string]any {
	// Build sorted route list for deterministic output.
	hostnames := make([]string, 0, len(c.routes))
	for h := range c.routes {
		hostnames = append(hostnames, h)
	}
	sort.Strings(hostnames)

	routes := make([]map[string]any, 0, len(c.routes))
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
