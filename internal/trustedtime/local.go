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

// DefaultLocalSocket is where the manager serves the issuing time to the other
// processes of the VM (Caddy's RA-TLS module runs as its own process). A Unix
// socket in the manager's runtime directory, not a TCP port: nothing Caddy
// proxies can reach it, and containers do not see the host's /run.
const DefaultLocalSocket = "/run/manager/clock.sock"

// LocalPath is the one route on the local socket.
const LocalPath = "/now"

// Issuer answers the time to stamp on what the runtime issues (Clock
// implements it with IssueTime).
type Issuer interface {
	IssueTime() (t time.Time, trusted bool)
}

// localReply is the body of GET /now. Trusted says whether UnixMs is trusted
// time or the floor fallback used while trusted time is unavailable.
type localReply struct {
	UnixMs  int64 `json:"unix_ms"`
	Trusted bool  `json:"trusted"`
}

// LocalHandler answers GET /now with the issuing time in Unix milliseconds.
// It always answers: issuing a certificate or a quote time is not a
// verification decision, and refusing it would only make the enclave
// unreachable (see Clock.IssueTime).
func LocalHandler(src Issuer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != LocalPath {
			http.NotFound(w, r)
			return
		}
		t, trusted := src.IssueTime()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(localReply{UnixMs: t.UnixMilli(), Trusted: trusted})
	})
}

// ServeLocal serves LocalHandler on a Unix socket at path (mode 0600, so only
// root processes can connect) until ctx is done.
func ServeLocal(ctx context.Context, path string, src Issuer, log *zap.Logger) error {
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
		log.Info("issuing time served on local socket", zap.String("path", path))
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
