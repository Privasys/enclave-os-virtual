package manager

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/container"
)

// Container log tailing: GET /api/v1/containers/{name}/logs.
//
// The shim-spawned logging binary keeps a size-capped ring of each task's
// stdout/stderr on the encrypted /data (see internal/container.TaskLogPaths).
// This endpoint returns the tail of one stream as text/plain. It is the ONLY
// way off the host for captured container output: the files never leave /data
// otherwise, and this handler sits behind the manager bearer auth like every
// other diagnostic. Being part of the measured host image, its existence is
// visible to anyone verifying the enclave's attestation.

const (
	defaultTailBytes = 64 << 10
	maxTailBytes     = 1 << 20
)

func (s *Server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasMonitoringAccess() {
		s.jsonError(w, http.StatusForbidden, "monitoring role required")
		return
	}

	name := r.PathValue("name")
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		s.jsonError(w, http.StatusBadRequest, "invalid container name")
		return
	}

	stream := r.URL.Query().Get("stream")
	if stream == "" {
		stream = "stderr"
	}
	if stream != "stdout" && stream != "stderr" {
		s.jsonError(w, http.StatusBadRequest, "stream must be stdout or stderr")
		return
	}

	tail := int64(defaultTailBytes)
	if v := r.URL.Query().Get("tail_bytes"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			s.jsonError(w, http.StatusBadRequest, "tail_bytes must be a positive integer")
			return
		}
		tail = min(n, maxTailBytes)
	}

	data, found := tailFiles(s.containerLogPaths(name, stream), tail)
	if !found {
		s.jsonError(w, http.StatusNotFound,
			"no captured logs for this container (host image without the container logger, or the container has not started since the logger was enabled)")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(data)
}

// containerLogPaths resolves the ring files for one stream, oldest first.
// Overridable in tests (the production path root is a fixed /data constant).
func (s *Server) containerLogPaths(name, stream string) []string {
	if s.logPathsFn != nil {
		return s.logPathsFn(name, stream)
	}
	return container.TaskLogPaths(name, stream)
}

// tailFiles reads the given files in order, concatenates them, and returns
// the last max bytes. found is false when none of the files exist — distinct
// from existing-but-empty, which returns an empty tail.
func tailFiles(paths []string, max int64) (data []byte, found bool) {
	var buf []byte
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		found = true
		buf = append(buf, b...)
		// Trim as we go so two capped ring files never balloon the buffer.
		if int64(len(buf)) > max {
			buf = buf[int64(len(buf))-max:]
		}
	}
	return buf, found
}
