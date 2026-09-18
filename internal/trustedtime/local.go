package trustedtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// DefaultLocalSocket is where the manager serves trusted time to the other
// processes of the VM (Caddy's RA-TLS module runs as its own process). A Unix
// socket in the manager's runtime directory, not a TCP port: nothing Caddy
// proxies can reach it, and containers do not see the host's /run.
const DefaultLocalSocket = "/run/manager/clock.sock"

// LocalPath is the one route on the local socket.
const LocalPath = "/now"

// localReply is the body of GET /now.
type localReply struct {
	UnixMs int64  `json:"unix_ms,omitempty"`
	Error  string `json:"error,omitempty"`
}

// LocalHandler answers GET /now with the trusted time in Unix milliseconds, or
// 503 when there is none (the caller must then fail closed).
func LocalHandler(src Source) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != LocalPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		t, err := src.Now()
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(localReply{Error: err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(localReply{UnixMs: t.UnixMilli()})
	})
}

// ServeLocal serves LocalHandler on a Unix socket at path (mode 0600, so only
// root processes can connect) until ctx is done.
func ServeLocal(ctx context.Context, path string, src Source, log *zap.Logger) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_ = os.Remove(path) // a stale socket from a previous run
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{Handler: LocalHandler(src), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if log != nil {
		log.Info("trusted time served on local socket", zap.String("path", path))
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
