package ratls

import (
	"net/http"
	"testing"
)

func TestConnectionCannotNameRuntimeHeaders(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"X-Privasys-Edge", ""},
		{"keep-alive, x-privasys-edge", "keep-alive"},
		{"Upgrade, X-Privasys-Attestation, X-Forwarded-For", "Upgrade"},
		{"close", "close"},
		{" X-Privasys-Edge ,\tForwarded, X-Custom", "X-Custom"},
	} {
		h := http.Header{}
		h.Set("Connection", c.in)
		keepRuntimeHeaders(h)
		if got := h.Get("Connection"); got != c.want {
			t.Errorf("Connection %q became %q, want %q", c.in, got, c.want)
		}
	}
	h := http.Header{}
	h.Add("Connection", "keep-alive")
	h.Add("Connection", "X-Privasys-Edge")
	keepRuntimeHeaders(h)
	if got := h.Values("Connection"); len(got) != 1 || got[0] != "keep-alive" {
		t.Errorf("two Connection lines became %q", got)
	}
}
