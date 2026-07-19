package caddy

import (
	"testing"

	"go.uber.org/zap"
)

func srv0Of(t *testing.T, c *Client) map[string]any {
	t.Helper()
	cfg := c.buildConfig()
	apps := cfg["apps"].(map[string]any)
	http := apps["http"].(map[string]any)
	servers := http["servers"].(map[string]any)
	return servers["srv0"].(map[string]any)
}

// TestBuildConfigStrictSNIHostOnlyWithMutual locks in the fix for the ingress
// mutual-RA-TLS regression: adding a client-auth connection policy makes Caddy
// auto-enable StrictSNIHost, which 421s the arbitrary-SNI management API. We
// must disable it explicitly whenever any host is mutual, and leave it untouched
// otherwise.
func TestBuildConfigStrictSNIHostOnlyWithMutual(t *testing.T) {
	c := &Client{cfg: Config{ListenAddr: ":443"}, log: zap.NewNop(), routes: map[string]route{}}

	// Server-auth only: no strict_sni_host key, single catch-all policy.
	c.routes["a.example"] = route{Hostname: "a.example", Upstream: "localhost:8000"}
	srv0 := srv0Of(t, c)
	if _, ok := srv0["strict_sni_host"]; ok {
		t.Fatal("strict_sni_host must be absent when no host is mutual")
	}
	if pols := srv0["tls_connection_policies"].([]map[string]any); len(pols) != 1 {
		t.Fatalf("want 1 connection policy (catch-all), got %d", len(pols))
	}

	// Add a mutual host: strict_sni_host must be explicitly false, and there
	// must be an SNI-matched client-auth policy plus the trailing catch-all.
	c.routes["b.example"] = route{Hostname: "b.example", Upstream: "localhost:8001", MutualAuth: true}
	srv0 = srv0Of(t, c)
	v, ok := srv0["strict_sni_host"]
	if !ok {
		t.Fatal("strict_sni_host must be set when a mutual host exists")
	}
	if b, _ := v.(bool); b {
		t.Fatal("strict_sni_host must be false (else the management API 421s)")
	}
	pols := srv0["tls_connection_policies"].([]map[string]any)
	if len(pols) != 2 {
		t.Fatalf("want 2 connection policies (mutual + catch-all), got %d", len(pols))
	}
	first := pols[0]
	if _, hasMatch := first["match"]; !hasMatch {
		t.Fatal("mutual policy must carry an SNI match")
	}
	ca, ok := first["client_authentication"].(map[string]any)
	if !ok || ca["mode"] != "require" {
		t.Fatalf("mutual policy must require a client cert, got %v", first["client_authentication"])
	}
	if len(pols[1]) != 0 {
		t.Fatal("last policy must be the empty catch-all")
	}
}

// TestBuildConfigMutualRouteHasPeerHandler proves the privasys_peer_headers
// handler is inserted ahead of the reverse proxy for a mutual host, and absent
// for a server-auth host.
func TestBuildConfigMutualRouteHasPeerHandler(t *testing.T) {
	c := &Client{cfg: Config{ListenAddr: ":443"}, log: zap.NewNop(), routes: map[string]route{}}
	c.routes["m.example"] = route{Hostname: "m.example", Upstream: "localhost:9000", MutualAuth: true}
	c.routes["s.example"] = route{Hostname: "s.example", Upstream: "localhost:9001"}
	srv0 := srv0Of(t, c)
	routes := srv0["routes"].([]map[string]any)

	handlerFor := func(host string) []string {
		for _, r := range routes {
			m := r["match"].([]map[string]any)
			if hs, _ := m[0]["host"].([]string); len(hs) > 0 && hs[0] == host {
				var names []string
				for _, h := range r["handle"].([]map[string]any) {
					names = append(names, h["handler"].(string))
				}
				return names
			}
		}
		return nil
	}

	if got := handlerFor("m.example"); len(got) != 2 || got[0] != "privasys_peer_headers" || got[1] != "reverse_proxy" {
		t.Fatalf("mutual route handlers = %v, want [privasys_peer_headers reverse_proxy]", got)
	}
	if got := handlerFor("s.example"); len(got) != 1 || got[0] != "reverse_proxy" {
		t.Fatalf("server-auth route handlers = %v, want [reverse_proxy]", got)
	}
}
