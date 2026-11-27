package manager

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/apifees"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// Reading the fee ring needs monitoring access; acknowledging (which drops
// events for good) needs the manager role, which only the control plane has.
func TestFeeAckNeedsTheManagerRole(t *testing.T) {
	log := zap.NewNop()
	s := New(Config{}, log, launcher.New(launcher.Config{}, log), nil)
	s.apiFees = apifees.Open("", log)
	s.apiFees.Record("app", "f", "sub", 1)
	ackURL := "/api/v1/api-fees?ack=99&epoch=" + s.apiFees.Epoch()

	w := httptest.NewRecorder()
	s.handleAPIFees(w, withRole(httptest.NewRequest(http.MethodGet, ackURL, nil), "monitoring"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("monitoring ack: %d", w.Code)
	}
	if got := s.apiFees.Pull(nil, ""); len(got) != 1 {
		t.Fatalf("a refused ack trimmed: %d left", len(got))
	}
	w = httptest.NewRecorder()
	s.handleAPIFees(w, withRole(httptest.NewRequest(http.MethodGet, "/api/v1/api-fees", nil), "monitoring"))
	if w.Code != http.StatusOK {
		t.Fatalf("monitoring read: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleAPIFees(w, withRole(httptest.NewRequest(http.MethodGet, ackURL, nil), "manager"))
	if w.Code != http.StatusOK || len(s.apiFees.Pull(nil, "")) != 0 {
		t.Fatalf("manager ack: %d", w.Code)
	}
}
