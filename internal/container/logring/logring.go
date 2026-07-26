// Package logring provides a size-capped, never-blocking file sink for
// container stdout/stderr.
//
// It exists to make container logging safe on an enclave host (bugs-and-fixes
// #50): any drain that can block — a manager-side pipe, an unrotated file on a
// filling disk — eventually fills the task FIFO and wedges every writer inside
// the container. The Writer here inverts the failure mode: it ALWAYS accepts
// and acknowledges the bytes, and when the filesystem misbehaves (full,
// read-only, missing) it drops them instead of blocking. Losing log lines is
// acceptable; wedging a model server mid-load is not.
//
// Capping is a two-file ring: the active file plus one rotated predecessor
// (path and path+".1"), so at most 2×max bytes per stream are ever on disk and
// the most recent output is always retained.
package logring

import (
	"bytes"
	"io"
	"os"
	"time"
)

// retryInterval is how long the Writer stays in drop mode after a filesystem
// error before it attempts to reopen. It bounds the syscall cost of logging
// against a persistently broken filesystem (e.g. ENOSPC) to one open attempt
// per interval instead of one per write.
const retryInterval = 5 * time.Second

// Writer is a size-capped append writer that never blocks and never returns
// an error: Write always reports len(p) consumed so an io.Copy draining a
// task FIFO keeps draining no matter what happens on disk.
//
// Not safe for concurrent use; each stream gets its own Writer.
type Writer struct {
	path string
	max  int64

	f       *os.File
	size    int64
	dropped int64
	retryAt time.Time

	// now is the clock, overridable in tests.
	now func() time.Time
}

// New returns a Writer capping the active file at max bytes, with one rotated
// predecessor at path+".1". The file is opened lazily in append mode, so a
// restarted logger continues after the pre-restart tail instead of erasing it.
func New(path string, max int64) *Writer {
	return &Writer{path: path, max: max, now: time.Now}
}

// Write implements io.Writer. It never blocks beyond the underlying write
// syscall and never surfaces an error; bytes that cannot be persisted are
// counted in Dropped and discarded.
func (w *Writer) Write(p []byte) (int, error) {
	n := len(p)
	// A single write larger than the cap keeps only its tail; the head could
	// never survive the next rotation anyway.
	if int64(len(p)) > w.max {
		w.dropped += int64(len(p)) - w.max
		p = p[int64(len(p))-w.max:]
	}
	if w.f == nil && !w.reopen() {
		w.dropped += int64(len(p))
		return n, nil
	}
	if w.size+int64(len(p)) > w.max {
		w.rotate()
		if w.f == nil {
			w.dropped += int64(len(p))
			return n, nil
		}
	}
	m, err := w.f.Write(p)
	w.size += int64(m)
	if err != nil {
		w.dropped += int64(len(p) - m)
		w.fail()
	}
	return n, nil
}

// Dropped returns the number of bytes discarded because the filesystem could
// not take them.
func (w *Writer) Dropped() int64 { return w.dropped }

// Close closes the active file. Further writes reopen it.
func (w *Writer) Close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// reopen opens the active file in append mode, honouring the retry backoff.
// Returns false when the Writer is (still) in drop mode.
func (w *Writer) reopen() bool {
	if !w.retryAt.IsZero() && w.now().Before(w.retryAt) {
		return false
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		w.retryAt = w.now().Add(retryInterval)
		return false
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		w.retryAt = w.now().Add(retryInterval)
		return false
	}
	w.f, w.size, w.retryAt = f, st.Size(), time.Time{}
	if w.size >= w.max {
		w.rotate()
	}
	return w.f != nil
}

// rotate moves the active file to path+".1" and starts a fresh one. On any
// failure the Writer enters drop mode rather than letting the file grow
// unbounded.
func (w *Writer) rotate() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil {
		// Rename can fail where remove+truncate still works (or the file may
		// simply be gone); fall back to truncating in place so the cap holds.
		os.Remove(w.path)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		w.retryAt = w.now().Add(retryInterval)
		return
	}
	w.f, w.size = f, 0
}

// fail closes the active file and enters drop mode until the retry interval
// elapses.
func (w *Writer) fail() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	w.retryAt = w.now().Add(retryInterval)
}

// LineStamper prefixes every line written through it with an RFC 3339 UTC
// timestamp before passing it to the underlying writer. Container output has
// no inherent timeline once detached from the journal; the stamps are what
// lets a stall be located in time. Errors from the underlying writer are
// ignored — it is expected to be a *Writer, which never errors.
type LineStamper struct {
	w       io.Writer
	now     func() time.Time
	midLine bool
}

// NewLineStamper wraps w. now is the clock (pass time.Now).
func NewLineStamper(w io.Writer, now func() time.Time) *LineStamper {
	return &LineStamper{w: w, now: now}
}

// Write implements io.Writer; it always reports len(p) consumed.
func (ls *LineStamper) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if !ls.midLine {
			ls.w.Write([]byte(ls.now().UTC().Format("2006-01-02T15:04:05.000Z") + " "))
			ls.midLine = true
		}
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			ls.w.Write(p)
			break
		}
		ls.w.Write(p[:i+1])
		ls.midLine = false
		p = p[i+1:]
	}
	return n, nil
}
