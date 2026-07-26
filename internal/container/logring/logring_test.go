package logring

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteRotateCap proves the two-file ring: the active file never exceeds
// the cap, one rotated predecessor is kept, and the most recent bytes survive.
func TestWriteRotateCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stdout.log")
	w := New(path, 100)

	chunk := bytes.Repeat([]byte("a"), 60)
	for i := 0; i < 5; i++ {
		n, err := w.Write(chunk)
		if n != len(chunk) || err != nil {
			t.Fatalf("write %d: n=%d err=%v, want full ack", i, n, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("active file missing: %v", err)
	}
	if len(cur) > 100 {
		t.Fatalf("active file %d bytes exceeds cap 100", len(cur))
	}
	old, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("rotated file missing: %v", err)
	}
	if len(old) > 100 {
		t.Fatalf("rotated file %d bytes exceeds cap 100", len(old))
	}
	// 5×60 = 300 bytes written; ring retains the newest ≤200.
	if total := len(cur) + len(old); total == 0 || total > 200 {
		t.Fatalf("ring retains %d bytes, want (0,200]", total)
	}
	if w.Dropped() != 0 {
		t.Fatalf("dropped %d bytes on a healthy filesystem", w.Dropped())
	}
}

// TestOversizeWriteKeepsTail proves a single write larger than the cap keeps
// only its tail and still acknowledges the full length.
func TestOversizeWriteKeepsTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.log")
	w := New(path, 10)
	p := []byte("0123456789ABCDEF") // 16 bytes, cap 10
	if n, err := w.Write(p); n != 16 || err != nil {
		t.Fatalf("n=%d err=%v, want 16,nil", n, err)
	}
	w.Close()
	got, _ := os.ReadFile(path)
	if string(got) != "6789ABCDEF" {
		t.Fatalf("kept %q, want tail %q", got, "6789ABCDEF")
	}
	if w.Dropped() != 6 {
		t.Fatalf("dropped=%d, want 6", w.Dropped())
	}
}

// TestDropModeAndRecovery proves the never-block contract: with an unwritable
// path every Write still acknowledges in full (bytes counted dropped), no
// reopen is attempted before the retry interval, and once the path becomes
// writable and the interval elapses, logging resumes.
func TestDropModeAndRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "s.log") // parent does not exist
	w := New(path, 1000)
	now := time.Unix(1000, 0)
	w.now = func() time.Time { return now }

	if n, err := w.Write([]byte("lost")); n != 4 || err != nil {
		t.Fatalf("drop-mode write: n=%d err=%v, want full ack", n, err)
	}
	if w.Dropped() != 4 {
		t.Fatalf("dropped=%d, want 4", w.Dropped())
	}

	// Make the path writable — but within the retry interval the writer must
	// stay in drop mode (no syscall storm against a broken filesystem).
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	now = now.Add(retryInterval / 2)
	w.Write([]byte("also-lost"))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("writer reopened before the retry interval elapsed")
	}

	now = now.Add(retryInterval)
	if n, err := w.Write([]byte("kept")); n != 4 || err != nil {
		t.Fatalf("recovered write: n=%d err=%v", n, err)
	}
	w.Close()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "kept" {
		t.Fatalf("recovered file = %q, %v; want %q", got, err, "kept")
	}
}

// TestAppendAcrossReopen proves a restarted logger appends after the previous
// tail instead of erasing it (the pre-crash output is the evidence we want).
func TestAppendAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.log")
	w := New(path, 1000)
	w.Write([]byte("first."))
	w.Close()
	w2 := New(path, 1000)
	w2.Write([]byte("second."))
	w2.Close()
	got, _ := os.ReadFile(path)
	if string(got) != "first.second." {
		t.Fatalf("got %q, want %q", got, "first.second.")
	}
}

// TestLineStamper proves each line gets exactly one timestamp prefix, split
// writes mid-line do not re-stamp, and the full input length is acknowledged.
func TestLineStamper(t *testing.T) {
	var buf bytes.Buffer
	at := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	ls := NewLineStamper(&buf, func() time.Time { return at })

	for _, p := range []string{"hel", "lo\nwor", "ld\n"} {
		if n, err := ls.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("write %q: n=%d err=%v", p, n, err)
		}
	}
	want := "2026-07-26T12:00:00.000Z hello\n2026-07-26T12:00:00.000Z world\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
	if strings.Count(buf.String(), "2026-") != 2 {
		t.Fatalf("stamp count wrong: %q", buf.String())
	}
}
