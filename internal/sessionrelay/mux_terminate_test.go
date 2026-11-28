package sessionrelay

import (
	"net/http/httptest"
	"testing"

	"github.com/Privasys/enclave-os-virtual/internal/edge"
)

func TestOnClearLeg(t *testing.T) {
	r := httptest.NewRequest("GET", "/__privasys/ws-mux", nil)
	if edge.Says(r.Header, "terminate", "direct") {
		t.Fatal("no marker read as a clear leg")
	}
	for _, v := range []string{"Terminate", "direct", " DIRECT "} {
		r := httptest.NewRequest("GET", "/__privasys/ws-mux", nil)
		r.Header.Add("X-Privasys-Edge", v)
		if !edge.Says(r.Header, "terminate", "direct") {
			t.Errorf("%q was not seen as a clear leg", v)
		}
	}
}
