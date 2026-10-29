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
	// "request", never "require". A mutual host still serves clients that
	// speak RA-TLS but cannot hold a TEE-bound certificate — the wallet and
	// the CLI both do — and "require" rejects those at the TLS layer, which
	// locked users out of Drive's login entirely on 2026-07-28. Asking for a
	// certificate lets the manager decide per connection: verified peer, or
	// anonymous with the peer headers scrubbed.
	ca, ok := first["client_authentication"].(map[string]any)
	if !ok || ca["mode"] != "request" {
		t.Fatalf("mutual policy must REQUEST (not require) a client cert, got %v", first["client_authentication"])
	}
	if len(pols[1]) != 0 {
		t.Fatal("last policy must be the empty catch-all")
	}
	// The mutual policy MUST also be keyed on the RA-TLS ALPN. A mutual host
	// can serve browsers on the same hostname (chat's sealed session and
	// Drive's embeddings both address confidential-ai), and those arrive from
	// the gateway's terminate leg with no client certificate. An SNI-only match
	// would demand one and make the app unreachable from the web the moment
	// allowed_callers is set, so this is a regression guard, not a style check.
	m, ok := first["match"].(map[string]any)
	if !ok {
		t.Fatalf("mutual policy match must be a map, got %T", first["match"])
	}
	alpn, ok := m["privasys_alpn"].([]string)
	if !ok || len(alpn) != 1 || alpn[0] != ratlsALPN {
		t.Fatalf("mutual policy must match the RA-TLS ALPN so browser (terminated) connections fall through to the catch-all; got %v", m["privasys_alpn"])
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

	if got := handlerFor("m.example"); len(got) != 3 || got[0] != "privasys_attest" || got[1] != "privasys_peer_headers" || got[2] != "reverse_proxy" {
		t.Fatalf("mutual route handlers = %v, want [privasys_attest privasys_peer_headers reverse_proxy]", got)
	}
	if got := handlerFor("s.example"); len(got) != 2 || got[0] != "privasys_attest" || got[1] != "reverse_proxy" {
		t.Fatalf("server-auth route handlers = %v, want [privasys_attest reverse_proxy]", got)
	}
}

// A direct adopter name rides the app's route with the Host rewritten to the
// app hostname, gets an ACME issuer policy (so Caddy answers acme-tls/1 from
// the shared storage) but is never listed for automation, and the storage
// root is the one shared with the manager.
func TestBuildConfigDirectAliases(t *testing.T) {
	c := &Client{cfg: Config{
		ListenAddr:      ":443",
		DirectStorage:   "/data/caddy",
		DirectIssuerDir: "acme-v02.api.letsencrypt.org-directory",
		DirectCA:        "https://acme-v02.api.letsencrypt.org/directory",
	}, log: zap.NewNop(), routes: map[string]route{}}
	c.routes["app.apps.example.org"] = route{
		Hostname: "app.apps.example.org", Upstream: "10.0.0.1:9443",
		Aliases: []string{"shop.example.com"},
	}
	cfg := c.buildConfig()

	if st, _ := cfg["storage"].(map[string]any); st["root"] != "/data/caddy" {
		t.Fatalf("storage = %v, want the shared root", cfg["storage"])
	}
	routes := srv0Of(t, c)["routes"].([]map[string]any)
	var alias map[string]any
	for _, r := range routes {
		m := r["match"].([]map[string]any)
		if hosts := m[0]["host"].([]string); len(hosts) == 1 && hosts[0] == "shop.example.com" {
			alias = r
		}
	}
	if alias == nil {
		t.Fatal("no route for the direct name")
	}
	var rewritten bool
	for _, h := range alias["handle"].([]map[string]any) {
		if h["handler"] == "reverse_proxy" {
			set := h["headers"].(map[string]any)["request"].(map[string]any)["set"].(map[string]any)
			rewritten = set["Host"].([]string)[0] == "app.apps.example.org"
		}
	}
	if !rewritten {
		t.Fatal("the direct route must rewrite Host to the app hostname")
	}

	pols := cfg["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]map[string]any)
	if len(pols) != 2 {
		t.Fatalf("want a direct policy and the catch-all, got %d", len(pols))
	}
	if subj := pols[0]["subjects"].([]string); len(subj) != 1 || subj[0] != "shop.example.com" {
		t.Fatalf("direct policy subjects = %v", subj)
	}
	if _, ok := pols[0]["issuers"]; !ok {
		t.Fatal("the direct policy needs the ACME issuer for the challenge lookup")
	}
	if _, ok := cfg["apps"].(map[string]any)["tls"].(map[string]any)["certificates"]; ok {
		t.Fatal("Caddy must never automate direct names itself")
	}
	getter := pols[1]["get_certificate"].([]map[string]any)[0]
	if getter["direct_storage"] != "/data/caddy" || getter["direct_issuer_key"] == "" {
		t.Fatalf("the getter is not told where direct certificates live: %v", getter)
	}
}

// The PROXY protocol wrapper is present only with a gateway list, trusts
// only those addresses, and keeps the tls wrapper after it.
func TestBuildConfigProxyProtocol(t *testing.T) {
	c := &Client{cfg: Config{ListenAddr: ":443"}, log: zap.NewNop(), routes: map[string]route{}}
	if _, ok := srv0Of(t, c)["listener_wrappers"]; ok {
		t.Fatal("no gateway list, no wrapper")
	}
	c.cfg.ProxyProtocolFrom = []string{"34.155.7.30", "10.0.0.0/8", "nonsense", "2001:db8::1"}
	ws := srv0Of(t, c)["listener_wrappers"].([]map[string]any)
	if len(ws) != 2 || ws[0]["wrapper"] != "proxy_protocol" || ws[1]["wrapper"] != "tls" {
		t.Fatalf("wrappers = %v", ws)
	}
	allow := ws[0]["allow"].([]string)
	want := []string{"34.155.7.30/32", "10.0.0.0/8", "2001:db8::1/128"}
	if len(allow) != len(want) {
		t.Fatalf("allow = %v, want %v", allow, want)
	}
	for i := range want {
		if allow[i] != want[i] {
			t.Fatalf("allow = %v, want %v", allow, want)
		}
	}
	if ws[0]["fallback_policy"] != "IGNORE" {
		t.Fatal("anyone else's header must be ignored, and headerless connections pass")
	}
}

// The pushed list is exactly what Caddy trusts for a PROXY header, a
// connection without a header is still accepted (IGNORE fallback, and the
// allowed sources may omit it), and an empty list removes the wrapper.
func TestSetProxyProtocolFromDrivesTheWrapper(t *testing.T) {
	c := &Client{cfg: Config{ListenAddr: ":443"}, log: zap.NewNop(), routes: map[string]route{}}
	c.routes["a.example"] = route{Hostname: "a.example", Upstream: "localhost:8000"}
	// No admin endpoint in the test: set the config the way the setter does.
	c.cfg.ProxyProtocolFrom = proxyProtocolCIDRs([]string{"203.0.113.10", "198.51.100.0/24", "nonsense"})
	if got := c.ProxyProtocolFrom(); len(got) != 2 || got[0] != "203.0.113.10/32" || got[1] != "198.51.100.0/24" {
		t.Fatalf("trusted = %v", got)
	}
	ws, ok := srv0Of(t, c)["listener_wrappers"].([]map[string]any)
	if !ok || len(ws) != 2 || ws[0]["wrapper"] != "proxy_protocol" || ws[1]["wrapper"] != "tls" {
		t.Fatalf("listener wrappers = %v", srv0Of(t, c)["listener_wrappers"])
	}
	allow := ws[0]["allow"].([]string)
	if len(allow) != 2 || allow[0] != "203.0.113.10/32" {
		t.Fatalf("allow = %v, want exactly the pushed list", allow)
	}
	if ws[0]["fallback_policy"] != "IGNORE" {
		t.Fatalf("fallback = %v: anyone else, and a connection without a header, must still be served", ws[0]["fallback_policy"])
	}
	c.cfg.ProxyProtocolFrom = proxyProtocolCIDRs(nil)
	if _, ok := srv0Of(t, c)["listener_wrappers"]; ok {
		t.Fatal("an empty list must remove the wrapper")
	}
}
