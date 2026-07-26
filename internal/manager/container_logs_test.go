package manager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
)

func logsRequest(t *testing.T, s *Server, target, role string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req = req.WithContext(context.WithValue(req.Context(), authResultKey,
		&auth.AuthResult{Source: "oidc", Role: role}))
	// Route through a mux so PathValue("name") is populated as in production.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/containers/{name}/logs", s.handleContainerLogs)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestHandleContainerLogs proves the tail endpoint: role gate, name
// validation, ring concatenation (rotated file first), tail_bytes clamping,
// and 404 when nothing was ever captured.
func TestHandleContainerLogs(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name string, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("stderr.log.1", "older ")
	writeFile("stderr.log", "newer")

	s := &Server{log: zap.NewNop()}
	s.logPathsFn = func(name, stream string) []string {
		if name != "drive" {
			return []string{filepath.Join(dir, "absent", stream+".log")}
		}
		return []string{
			filepath.Join(dir, stream+".log.1"),
			filepath.Join(dir, stream+".log"),
		}
	}

	// Happy path: rotated + active concatenated in order.
	rec := logsRequest(t, s, "/api/v1/containers/drive/logs?stream=stderr", "monitoring")
	if rec.Code != http.StatusOK || rec.Body.String() != "older newer" {
		t.Fatalf("got %d %q, want 200 %q", rec.Code, rec.Body.String(), "older newer")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type %q", ct)
	}

	// tail_bytes trims from the front.
	rec = logsRequest(t, s, "/api/v1/containers/drive/logs?stream=stderr&tail_bytes=5", "manager")
	if rec.Code != http.StatusOK || rec.Body.String() != "newer" {
		t.Fatalf("tail: got %d %q, want 200 %q", rec.Code, rec.Body.String(), "newer")
	}

	// Default stream is stderr.
	rec = logsRequest(t, s, "/api/v1/containers/drive/logs", "monitoring")
	if rec.Code != http.StatusOK || rec.Body.String() != "older newer" {
		t.Fatalf("default stream: got %d %q", rec.Code, rec.Body.String())
	}

	// No captured files at all -> 404.
	rec = logsRequest(t, s, "/api/v1/containers/ghost/logs", "monitoring")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing logs: got %d, want 404", rec.Code)
	}

	// Bad stream and bad tail_bytes -> 400.
	for _, target := range []string{
		"/api/v1/containers/drive/logs?stream=journal",
		"/api/v1/containers/drive/logs?tail_bytes=-1",
		"/api/v1/containers/drive/logs?tail_bytes=x",
	} {
		if rec = logsRequest(t, s, target, "monitoring"); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", target, rec.Code)
		}
	}

	// Path-escaping names are rejected before touching the filesystem.
	rec = logsRequest(t, s, "/api/v1/containers/"+`..%2Fother`+"/logs", "monitoring")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal name: got %d, want 400", rec.Code)
	}

	// A role with no monitoring access is refused.
	rec = logsRequest(t, s, "/api/v1/containers/drive/logs", "none")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("role gate: got %d, want 403", rec.Code)
	}
}
