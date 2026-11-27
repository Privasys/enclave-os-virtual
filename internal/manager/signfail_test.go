package manager

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

type failingSigner struct{}

func (failingSigner) Sign(*http.Request, []byte) error { return errors.New("no quote right now") }

// When the attested signature cannot be made, the usage relay and the tool
// spec relay refuse (503) instead of sending the bare enclave credential:
// the upstream is never called.
func TestRelaysFailClosedWhenSigningFails(t *testing.T) {
	called := false
	mgmt := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer mgmt.Close()
	log := zap.NewNop()
	s := New(Config{MgmtBaseURL: mgmt.URL, EnclaveID: "e", EnclaveToken: "enclave-cred", EnclaveSigner: failingSigner{}}, log, launcher.New(launcher.Config{}, log), nil)

	w := httptest.NewRecorder()
	s.relayUsageFor(w, httptest.NewRequest(http.MethodPost, "/x", nil), "cai", "00112233445566778899aabbccddeeff", http.MethodPost, "/api/v1/enclave/usage", []byte(`{}`))
	if w.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("usage: %d, upstream called=%v", w.Code, called)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/containers/cai/tool-spec", nil)
	r.SetPathValue("name", "cai")
	w = httptest.NewRecorder()
	s.handleToolSpec(w, r)
	if w.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("tool spec: %d, upstream called=%v", w.Code, called)
	}
}
