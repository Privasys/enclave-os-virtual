package manager

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// An app that declares no resources never receives a holder path: the
// enclave OS answers 404 itself, whatever the bearer, and the request is
// reported handled so the dispatcher never proxies it.
func TestHolderPathsNeverReachAnAppWithoutResources(t *testing.T) {
	s := &Server{log: zap.NewNop(), holderResourcesOf: func(string) (string, int) { return "cai", 0 }}
	for _, p := range []string{
		holderFilesPath,
		holderFilesPath + "?path=x",
		holderFilesPath + "/sub",
		holderCapabilitiesPath,
		holderCapabilitiesPath + "/abc",
		"/x/../" + strings.TrimPrefix(holderFilesPath, "/"),
	} {
		for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPost} {
			req := httptest.NewRequest(m, "https://cai.apps.privasys.org"+p, nil)
			req.Header.Set("Authorization", "Bearer platform-token")
			rec := httptest.NewRecorder()
			if !s.serveEnclaveHolderPaths(rec, req, "cai.apps.privasys.org") {
				t.Fatalf("%s %s: not handled, so it would reach the app", m, p)
			}
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s %s: status %d, want 404", m, p, rec.Code)
			}
		}
	}
	// An unknown host is answered the same way.
	s.holderResourcesOf = func(string) (string, int) { return "", 0 }
	rec := httptest.NewRecorder()
	if !s.serveEnclaveHolderPaths(rec, httptest.NewRequest(http.MethodGet, "https://x"+holderFilesPath, nil), "x") || rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host: handled/status %d, want 404", rec.Code)
	}
}

// Any other path is left to the app.
func TestOtherPathsAreTheApps(t *testing.T) {
	s := &Server{log: zap.NewNop(), holderResourcesOf: func(string) (string, int) { return "cai", 0 }}
	for _, p := range []string{"/", "/v1/messages", "/__privasys/v1/holdersX", "/__privasys/v1/capabilitiesX"} {
		if s.serveEnclaveHolderPaths(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://cai"+p, nil), "cai") {
			t.Fatalf("%s: taken from the app", p)
		}
	}
}
