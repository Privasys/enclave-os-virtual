package manager

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// The relay forwards the app's batch with the enclave's credential and the
// app id from the load envelope, never the app's own, and returns the
// control plane's answer as is.
func TestRelayUsage(t *testing.T) {
	var got struct {
		path, appID, auth, body string
	}
	mgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.path, got.appID, got.auth, got.body = r.URL.RequestURI(), r.Header.Get(appIDHeader), r.Header.Get("Authorization"), string(b)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Only", "1")
		_, _ = w.Write([]byte(`{"frozen":true}`))
	}))
	defer mgmt.Close()
	log := zap.NewNop()
	s := New(Config{MgmtBaseURL: mgmt.URL, EnclaveToken: "enclave-cred"}, log, launcher.New(launcher.Config{}, log), nil)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/containers/cai/usage", strings.NewReader(`{"requests":[]}`))
	r.Header.Set(appIDHeader, "forged-by-the-app")
	r.Header.Set("Authorization", "Bearer container-token")
	w := httptest.NewRecorder()
	s.relayUsageFor(w, r, "cai", "00112233445566778899aabbccddeeff", http.MethodPost, "/api/v1/enclave/usage", []byte(`{"requests":[]}`))

	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"frozen":true}` {
		t.Fatalf("relayed answer = %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Upstream-Only") != "" {
		t.Fatal("upstream headers leaked to the app")
	}
	if got.path != "/api/v1/enclave/usage" || got.body != `{"requests":[]}` {
		t.Fatalf("upstream got %q %q", got.path, got.body)
	}
	if got.appID != "00112233445566778899aabbccddeeff" {
		t.Fatalf("app id sent upstream = %q, want the envelope's", got.appID)
	}
	if got.auth != "Bearer enclave-cred" {
		t.Fatalf("upstream credential = %q, want the enclave's", got.auth)
	}
}

// A container without an app id cannot be billed to anyone, so nothing is
// relayed; nor when the enclave has no control-plane credential.
func TestRelayUsageRefuses(t *testing.T) {
	called := false
	mgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer mgmt.Close()
	log := zap.NewNop()
	s := New(Config{MgmtBaseURL: mgmt.URL, EnclaveToken: "enclave-cred"}, log, launcher.New(launcher.Config{}, log), nil)
	w := httptest.NewRecorder()
	s.relayUsageFor(w, httptest.NewRequest(http.MethodPost, "/x", nil), "cai", "", http.MethodPost, "/api/v1/enclave/usage", nil)
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("no app id: %d, upstream called=%v", w.Code, called)
	}

	s2 := New(Config{}, log, launcher.New(launcher.Config{}, log), nil)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/containers/cai/billable-caller?sub=x", nil)
	r.SetPathValue("name", "cai")
	w = httptest.NewRecorder()
	s2.handleBillableCaller(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured enclave: %d", w.Code)
	}
}
