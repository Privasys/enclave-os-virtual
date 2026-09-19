package attrbilling

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func settlerFor(t *testing.T, status int) *Settler {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return New(Config{MgmtBaseURL: srv.URL, EnclaveToken: "t"}, zap.NewNop())
}

// Only a 2xx grants the claim. Every other outcome refuses the disclosure:
// the host carries this call, so a gate that proceeded on failure could be
// switched off by dropping it.
func TestClaimFailsClosed(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		status int
		want   ClaimResult
	}{
		{"granted", http.StatusOK, ClaimGranted},
		{"already delivered", http.StatusConflict, ClaimDelivered},
		{"endpoint absent", http.StatusNotFound, ClaimUnavailable},
		{"credential rejected", http.StatusUnauthorized, ClaimUnavailable},
		{"server error", http.StatusInternalServerError, ClaimUnavailable},
	}
	for _, c := range cases {
		if got := settlerFor(t, c.status).Claim(ctx, "jti-1"); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}

	down := httptest.NewServer(http.NotFoundHandler())
	url := down.URL
	down.Close()
	s := New(Config{MgmtBaseURL: url, EnclaveToken: "t"}, zap.NewNop())
	if got := s.Claim(ctx, "jti-1"); got != ClaimUnavailable {
		t.Errorf("unreachable: got %d", got)
	}

	var none *Settler
	if got := none.Claim(ctx, "jti-1"); got != ClaimUnavailable {
		t.Errorf("no settler: got %d", got)
	}
}
