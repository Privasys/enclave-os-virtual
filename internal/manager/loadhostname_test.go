package manager

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// The load route refuses a hostname that is not one concrete name under the
// app domain with 400, before the load starts, so the control plane sees why
// (the launcher refuses it again inside the load).
func TestLoadRouteRefusesAPatternHostname(t *testing.T) {
	l := launcher.New(launcher.Config{ManagerHostname: "m6-dev-mgr.apps.test.privasys.org", AppDomain: "apps.test.privasys.org"}, zap.NewNop())
	s := &Server{log: zap.NewNop(), launcher: l}
	for _, h := range []string{"*.apps.test.privasys.org", "34.155.1.2", "m6-dev-mgr.apps.test.privasys.org", "a.b.apps.test.privasys.org"} {
		body := `{"name":"x","image":"example.invalid/x@sha256:` + strings.Repeat("0", 64) + `","port":10001,"hostname":"` + h + `"}`
		r := withRole(httptest.NewRequest(http.MethodPost, "/api/v1/containers", strings.NewReader(body)), "manager")
		w := httptest.NewRecorder()
		s.handleLoadContainer(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("hostname %q: status %d, want 400 (%s)", h, w.Code, w.Body.String())
		}
	}
}
