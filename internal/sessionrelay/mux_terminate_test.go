package sessionrelay

import (
	"net/http/httptest"
	"testing"
)

func TestOnClearLeg(t *testing.T) {
	r := httptest.NewRequest("GET", "/__privasys/ws-mux", nil)
	if onClearLeg(r) {
		t.Fatal("no marker read as a clear leg")
	}
	for _, v := range []string{"Terminate", "direct", " DIRECT "} {
		r := httptest.NewRequest("GET", "/__privasys/ws-mux", nil)
		r.Header.Add("X-Privasys-Edge", v)
		if !onClearLeg(r) {
			t.Errorf("%q was not seen as a clear leg", v)
		}
	}
}
