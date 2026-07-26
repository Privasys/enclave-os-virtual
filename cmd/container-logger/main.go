// Command container-logger is the containerd v2 logging binary for container
// tasks (cio.BinaryIO). The SHIM spawns one instance per task and hands it the
// stdout/stderr FIFOs as fds 3/4, so the drain is owned by the shim's child —
// it survives manager restarts, unlike a manager-side pipe (cio.WithStdio).
//
// Its one hard invariant is that it NEVER stops reading the FIFOs: every
// failure path (bad args, unwritable log dir, disk full) degrades to draining
// into a discard or drop-mode sink, exactly like the cio.NullIO it replaces.
// A logging problem must never become a container wedge (bugs-and-fixes #50).
//
// Output goes to a per-container two-file ring under the log dir
// (<dir>/<namespace>/<id>/{stdout,stderr}.log plus .1 predecessors), each file
// capped, each line timestamped. The manager serves the tail via
// GET /api/v1/containers/{name}/logs.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/runtime/v2/logging"

	"github.com/Privasys/enclave-os-virtual/internal/container/logring"
)

const (
	defaultDir      = "/data/log/containers"
	defaultMaxBytes = int64(4 << 20) // per file; ×2 files ×2 streams = ≤16 MiB per container
)

func main() {
	logging.Run(run)
}

func run(_ context.Context, cfg *logging.Config, ready func() error) error {
	dir, maxBytes := parseArgs(os.Args[1:])

	// Resolve the sinks first, degrading to discard on ANY problem. The
	// container must start and keep running regardless of what happens here.
	var stdout, stderr io.Writer = io.Discard, io.Discard
	var rings []*logring.Writer
	ns, id := sanitize(cfg.Namespace), sanitize(cfg.ID)
	if ns != "" && id != "" {
		base := filepath.Join(dir, ns, id)
		if err := os.MkdirAll(base, 0o700); err == nil {
			ow := logring.New(filepath.Join(base, "stdout.log"), maxBytes)
			ew := logring.New(filepath.Join(base, "stderr.log"), maxBytes)
			rings = append(rings, ow, ew)
			stdout = logring.NewLineStamper(ow, time.Now)
			stderr = logring.NewLineStamper(ew, time.Now)
			// Attach markers: a restart boundary is otherwise invisible in an
			// append-mode ring.
			fmt.Fprintf(stdout, "[container-logger] attached to %s/%s\n", ns, id)
			fmt.Fprintf(stderr, "[container-logger] attached to %s/%s\n", ns, id)
		}
	}

	// Signal the shim that the container may start. An error here means the
	// wait pipe is broken; keep draining anyway — the task may already run.
	_ = ready()

	var wg sync.WaitGroup
	drain := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		if src == nil {
			return
		}
		buf := make([]byte, 64<<10)
		// The dst side never returns an error (Discard / logring contract),
		// so this copy ends only at FIFO EOF: the container exiting.
		_, _ = io.CopyBuffer(dst, src, buf)
	}
	wg.Add(2)
	go drain(stdout, cfg.Stdout)
	go drain(stderr, cfg.Stderr)
	wg.Wait()

	for _, r := range rings {
		r.Close()
	}
	return nil
}

// parseArgs decodes the flat "key value" argument pairs the shim builds from
// the binary:// URI query (see containerd NewBinaryCmd). Unknown keys and
// malformed values fall back to defaults — never an exit.
func parseArgs(args []string) (dir string, maxBytes int64) {
	dir, maxBytes = defaultDir, defaultMaxBytes
	for i := 0; i+1 < len(args); i += 2 {
		switch strings.TrimPrefix(args[i], "-") {
		case "dir":
			if filepath.IsAbs(args[i+1]) {
				dir = args[i+1]
			}
		case "max-bytes":
			if v, err := strconv.ParseInt(args[i+1], 10, 64); err == nil && v > 0 {
				maxBytes = v
			}
		}
	}
	return dir, maxBytes
}

// sanitize returns s if it is safe to use as a single path element, else "".
// containerd IDs are already restricted, but the log path must not depend on
// that being true forever.
func sanitize(s string) string {
	if s == "" || s == "." || s == ".." ||
		strings.ContainsAny(s, `/\`) || strings.Contains(s, "..") {
		return ""
	}
	return s
}
