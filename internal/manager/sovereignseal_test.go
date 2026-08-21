package manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// Route through a mux so PathValue("name") is populated as in production.
// requireContainerSelf is exercised by its own callers' tests; here the
// handler itself is under test via the sovereignSealFn seam.
func sealRequest(t *testing.T, s *Server, name string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/containers/{name}/sovereign-seal", s.handleSovereignSeal)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/containers/"+name+"/sovereign-seal", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestHandleSovereignSeal(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	digest := bytes.Repeat([]byte{0xd1}, 32)
	s := &Server{log: zap.NewNop()}
	s.sovereignSealFn = func(name string) ([]byte, []byte, error) {
		if name != "app" {
			return nil, nil, errors.New("launcher: unknown container")
		}
		return key, digest, nil
	}

	rec := sealRequest(t, s, "app")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if resp["seal_key"] != "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a" {
		t.Fatalf("seal_key %q", resp["seal_key"])
	}
	if resp["image_digest"] != "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1" {
		t.Fatalf("image_digest %q", resp["image_digest"])
	}
	if resp["version"] != "privasys-sovereign-seal/v1" {
		t.Fatalf("version %q", resp["version"])
	}

	// A refusal (unknown container / no vault-backed volume) surfaces as a
	// 409 with the launcher's error, never a 500.
	rec = sealRequest(t, s, "ghost")
	if rec.Code != http.StatusConflict {
		t.Fatalf("refusal status %d: %s", rec.Code, rec.Body.String())
	}
}
