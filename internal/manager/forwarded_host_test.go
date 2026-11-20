// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package manager

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

// A direct adopter name reaches the container with its X-Forwarded-Host
// intact, through the same Rewrite the manager's app proxy runs.
func TestDirectAliasKeepsForwardedHost(t *testing.T) {
	var got http.Header
	var gotHost string
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotHost = r.Header.Clone(), r.Host
	}))
	defer app.Close()
	upstream, _ := url.Parse(app.URL)

	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.Out.URL.Scheme = "http"
		pr.Out.URL.Host = upstream.Host
		pr.Out.Host = pr.In.Host
		pr.SetXForwarded()
		restoreDirectForwardedHost(pr)
	}}

	send := func(edge, fwd string) (http.Header, string) {
		req := httptest.NewRequest(http.MethodGet, "http://platform-monitoring.apps.privasys.org/", nil)
		if edge != "" {
			req.Header.Set(edgeHeader, edge)
		}
		if fwd != "" {
			req.Header.Set("X-Forwarded-Host", fwd)
		}
		proxy.ServeHTTP(httptest.NewRecorder(), req)
		return got, gotHost
	}

	h, host := send("direct", "support.privasys.org")
	if h.Get("X-Forwarded-Host") != "support.privasys.org" || host != "platform-monitoring.apps.privasys.org" {
		t.Fatalf("direct alias: X-Forwarded-Host %q, Host %q", h.Get("X-Forwarded-Host"), host)
	}

	// Any other leg: the header is what SetXForwarded writes, the Host.
	if h, _ := send("", "support.privasys.org"); h.Get("X-Forwarded-Host") != "platform-monitoring.apps.privasys.org" {
		t.Fatalf("non-direct leg kept a client X-Forwarded-Host: %q", h.Get("X-Forwarded-Host"))
	}
	// A malformed or multi-valued name is not passed on.
	for _, bad := range []string{"a.example, b.example", "evil.example/path", "bad..name", "éx.example"} {
		if h, _ := send("direct", bad); h.Get("X-Forwarded-Host") != "platform-monitoring.apps.privasys.org" {
			t.Fatalf("direct leg passed %q on as %q", bad, h.Get("X-Forwarded-Host"))
		}
	}
	// A port is kept, as Caddy forwards it.
	if h, _ := send("direct", "support.privasys.org:443"); h.Get("X-Forwarded-Host") != "support.privasys.org:443" {
		t.Fatalf("port dropped: %q", h.Get("X-Forwarded-Host"))
	}
}
