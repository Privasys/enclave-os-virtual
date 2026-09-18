package manager

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The request counter's labels must stay bounded whatever paths and
// methods clients send: each distinct label set is a permanent series.
func TestRequestCounterLabelsAreBounded(t *testing.T) {
	apiRequests.Reset()
	t.Cleanup(apiRequests.Reset)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {})
	// Shaped like the real dispatcher: app hosts are labelled "app", the
	// rest go through the mux and take its matched pattern.
	dispatcher := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "app.example" {
			setRouteLabel(r, "app")
			return
		}
		mux.ServeHTTP(w, r)
		setRouteLabel(r, r.Pattern)
	})
	h := (&Server{}).metricsMiddleware(dispatcher)

	send := func(method, host, path string) {
		req := httptest.NewRequest(method, path, nil)
		req.Host = host
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	for i := 0; i < 200; i++ {
		send(http.MethodGet, "manager.example", fmt.Sprintf("/random-%d", i))
		send(http.MethodGet, "app.example", fmt.Sprintf("/files/%d", i))
		send(fmt.Sprintf("M%d", i), "manager.example", "/healthz")
	}
	send(http.MethodGet, "manager.example", "/healthz")

	// Expected series: GET other 404, GET app 200, OTHER other (405 or 404),
	// GET "GET /healthz" 200. A handful, not hundreds.
	if n := testutil.CollectAndCount(apiRequests); n > 5 {
		t.Fatalf("%d series after 601 requests with distinct paths and methods, want a bounded handful", n)
	}
	if v := testutil.ToFloat64(apiRequests.WithLabelValues("GET", "GET /healthz", "200")); v != 1 {
		t.Fatalf("matched route counted %v times under its pattern, want 1", v)
	}
	if v := testutil.ToFloat64(apiRequests.WithLabelValues("GET", "app", "200")); v != 200 {
		t.Fatalf("app traffic counted %v times under \"app\", want 200", v)
	}
}
