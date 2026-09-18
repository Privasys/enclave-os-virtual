package trustedtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeHost struct {
	mu sync.Mutex
	t  time.Time
}

func (h *fakeHost) now() time.Time  { h.mu.Lock(); defer h.mu.Unlock(); return h.t }
func (h *fakeHost) set(t time.Time) { h.mu.Lock(); h.t = t; h.mu.Unlock() }
func (h *fakeHost) add(d time.Duration) {
	h.mu.Lock()
	h.t = h.t.Add(d)
	h.mu.Unlock()
}

// fakeNTS answers with the "real" time, or an error.
type fakeNTS struct {
	mu    sync.Mutex
	t     time.Time
	err   error
	calls int
}

func (n *fakeNTS) Quorum(_ context.Context, _ time.Time) (Sample, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls++
	if n.err != nil {
		return Sample{}, n.err
	}
	return Sample{Time: n.t, Servers: []string{"a", "b"}}, nil
}

type fakeReporter struct {
	mu   sync.Mutex
	err  error
	got  []Incident
	done chan struct{}
}

func (r *fakeReporter) Report(_ context.Context, _ MonitorConfig, inc Incident) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, inc)
	if r.done != nil {
		select {
		case r.done <- struct{}{}:
		default:
		}
	}
	return r.err
}

func (r *fakeReporter) reasons() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, i := range r.got {
		out = append(out, i.Reason)
	}
	return out
}

type rig struct {
	c    *Clock
	host *fakeHost
	nts  *fakeNTS
	rep  *fakeReporter
	path string
	priv ed25519.PrivateKey
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{
		host: &fakeHost{t: t0},
		nts:  &fakeNTS{t: t0},
		rep:  &fakeReporter{done: make(chan struct{}, 16)},
		path: filepath.Join(t.TempDir(), "clock.json"),
	}
	r.open(t)
	return r
}

func (r *rig) open(t *testing.T) {
	t.Helper()
	c, err := New(Options{StatePath: r.path, EnclaveID: "enc-1", Host: r.host.now, NTS: r.nts, Reporter: r.rep})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
}

func (r *rig) configure(t *testing.T, version int64) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r.priv = priv
	err := r.c.SetConfig(MonitorConfig{
		EnclaveID:     "enc-1",
		MonitorKey:    base64.RawURLEncoding.EncodeToString(pub),
		MonitorKeyID:  KeyID(pub),
		IncidentURL:   "https://monitor.example/api/v1/clock/incidents",
		ConfigVersion: version,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (r *rig) poll(t *testing.T, tm time.Time, seq int64) (PollReply, error) {
	t.Helper()
	sig := ed25519.Sign(r.priv, PollSignedBytes("enc-1", tm.UnixMilli(), seq))
	return r.c.Poll(PollRequest{EnclaveID: "enc-1", TMs: tm.UnixMilli(), Seq: seq, KeyID: r.c.cfg.MonitorKeyID, Sig: base64.RawURLEncoding.EncodeToString(sig)})
}

func mustNow(t *testing.T, c *Clock) time.Time {
	t.Helper()
	v, err := c.Now()
	if err != nil {
		t.Fatalf("Now: %v", err)
	}
	return v
}

func TestBootNeedsNTS(t *testing.T) {
	r := newRig(t)
	r.nts.err = errors.New("blocked")
	if _, err := r.c.Now(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want fail closed before the boot fetch, got %v", err)
	}
	// Within the backoff a read fails at once, without another fetch.
	calls := r.nts.calls
	if _, err := r.c.Now(); err == nil || r.nts.calls != calls {
		t.Fatalf("want an immediate failure inside the backoff (calls %d -> %d)", calls, r.nts.calls)
	}
	r.nts.err = nil
	r.c.fetchAt = time.Time{}
	if got := mustNow(t, r.c); !got.Equal(t0) {
		t.Fatalf("got %v want %v", got, t0)
	}
}

func TestFloorNeverBelowMinimum(t *testing.T) {
	r := newRig(t)
	if r.c.floor < MinTrustedTime.UnixNano() {
		t.Fatal("floor below MinTrustedTime")
	}
}

func TestNeverGoesBackwards(t *testing.T) {
	r := newRig(t)
	a := mustNow(t, r.c)
	r.host.add(-500 * time.Millisecond) // within the slack: no incident
	b := mustNow(t, r.c)
	if b.Before(a) {
		t.Fatalf("time went backwards: %v then %v", a, b)
	}
}

func TestHostBehindFloorWithoutMonitorFreezes(t *testing.T) {
	r := newRig(t)
	mustNow(t, r.c) // boot fetch: floor = t0
	r.host.add(-time.Hour)
	r.nts.t = t0.Add(time.Second)
	got := mustNow(t, r.c)
	if !got.Equal(t0.Add(time.Second)) {
		t.Fatalf("want the frozen NTS time, got %v", got)
	}
	if !r.c.flagged || r.c.reason != ReasonHostBehindFloor {
		t.Fatalf("want flagged host_behind_floor, got %v %q", r.c.flagged, r.c.reason)
	}
	// Frozen: the host moving does not move trusted time.
	r.host.add(30 * time.Minute)
	if got2 := mustNow(t, r.c); !got2.Equal(got) {
		t.Fatalf("want frozen %v, got %v", got, got2)
	}
	// The state survives a restart.
	r.open(t)
	if !r.c.flagged || r.c.floor != t0.Add(time.Second).UnixNano() {
		t.Fatalf("state not persisted: flagged=%v floor=%v", r.c.flagged, time.Unix(0, r.c.floor))
	}
}

func TestHostBehindFloorNeedsReceipt(t *testing.T) {
	r := newRig(t)
	r.configure(t, 1)
	mustNow(t, r.c)
	r.host.add(-time.Hour)
	r.rep.err = errors.New("monitor down")
	if _, err := r.c.Now(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want fail closed without a receipt, got %v", err)
	}
	if r.c.flagged {
		t.Fatal("must not flag before the receipt")
	}
	r.rep.err = nil
	r.c.incidentAt = time.Time{}
	mustNow(t, r.c)
	if !r.c.flagged {
		t.Fatal("want flagged after an acknowledged incident")
	}
	if rs := r.rep.reasons(); len(rs) == 0 || rs[len(rs)-1] != ReasonHostBehindFloor {
		t.Fatalf("reported %v", rs)
	}
}

func TestRefetchCapWhileFlagged(t *testing.T) {
	r := newRig(t)
	mustNow(t, r.c)
	r.host.add(-time.Hour)
	mustNow(t, r.c) // flags
	calls := r.nts.calls
	for i := 0; i < RefetchEvery-1; i++ {
		mustNow(t, r.c)
	}
	if r.nts.calls != calls {
		t.Fatalf("refetched early: %d calls", r.nts.calls-calls)
	}
	r.nts.t = t0.Add(5 * time.Minute)
	got := mustNow(t, r.c) // the 100th read refetches
	if r.nts.calls != calls+1 || !got.Equal(t0.Add(5*time.Minute)) {
		t.Fatalf("want one refetch refreshing the frozen time, calls=%d got=%v", r.nts.calls-calls, got)
	}
	// A failed refetch fails closed.
	r.nts.err = errors.New("blocked")
	for i := 0; i < RefetchEvery-1; i++ {
		mustNow(t, r.c)
	}
	if _, err := r.c.Now(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want fail closed on a failed refetch, got %v", err)
	}
}

func TestFlagClearsWhenHostFixed(t *testing.T) {
	r := newRig(t)
	mustNow(t, r.c)
	r.host.add(-time.Hour)
	mustNow(t, r.c)
	// The host is fixed: back at real time, which has moved on.
	r.host.set(t0.Add(10 * time.Minute))
	r.nts.t = t0.Add(10 * time.Minute)
	for i := 0; i < RefetchEvery; i++ {
		mustNow(t, r.c)
	}
	if r.c.flagged {
		t.Fatal("flag should clear once NTS confirms the host")
	}
	r.host.add(time.Second)
	if got := mustNow(t, r.c); !got.Equal(t0.Add(10*time.Minute + time.Second)) {
		t.Fatalf("want host time again, got %v", got)
	}
}

func TestBootDetectsWrongHost(t *testing.T) {
	r := newRig(t)
	r.host.set(t0.Add(-2 * time.Hour)) // host behind but above MinTrustedTime
	got := mustNow(t, r.c)
	if !got.Equal(t0) || !r.c.flagged || r.c.reason != ReasonHostClockWrong {
		t.Fatalf("got %v flagged=%v reason=%q", got, r.c.flagged, r.c.reason)
	}
}

func TestPollVerdicts(t *testing.T) {
	r := newRig(t)
	r.configure(t, 1)
	mustNow(t, r.c)

	// Bad signature.
	if _, err := r.c.Poll(PollRequest{EnclaveID: "enc-1", TMs: t0.UnixMilli(), KeyID: r.c.cfg.MonitorKeyID, Sig: "AAAA"}); !errors.Is(err, ErrBadPoll) {
		t.Fatalf("want ErrBadPoll, got %v", err)
	}
	// Wrong enclave.
	sig := ed25519.Sign(r.priv, PollSignedBytes("enc-2", t0.UnixMilli(), 1))
	if _, err := r.c.Poll(PollRequest{EnclaveID: "enc-2", TMs: t0.UnixMilli(), Seq: 1, KeyID: r.c.cfg.MonitorKeyID, Sig: base64.RawURLEncoding.EncodeToString(sig)}); !errors.Is(err, ErrBadPoll) {
		t.Fatalf("want ErrBadPoll for another enclave, got %v", err)
	}

	// In sync.
	r.host.add(time.Minute)
	rep, err := r.poll(t, t0.Add(time.Minute+2*time.Second), 1)
	if err != nil || rep.Verdict != VerdictInSync || rep.FloorMs != t0.Add(time.Minute).UnixMilli() || rep.Runtime != "virtual" {
		t.Fatalf("in sync: %+v %v", rep, err)
	}
	// Stale.
	rep, err = r.poll(t, t0, 2)
	if err != nil || rep.Verdict != VerdictIgnoredStale {
		t.Fatalf("stale: %+v %v", rep, err)
	}
	// Monitor wrong: the host agrees with NTS.
	r.nts.t = r.host.now()
	rep, err = r.poll(t, r.host.now().Add(time.Hour), 3)
	if err != nil || rep.Verdict != VerdictMonitorWrong || rep.Flagged || rep.NTS.TimeMs == 0 || len(rep.NTS.Servers) != 2 {
		t.Fatalf("monitor wrong: %+v %v", rep, err)
	}
	// Host wrong: the monitor agrees with NTS.
	real := r.host.now().Add(time.Hour)
	r.nts.t = real
	rep, err = r.poll(t, real, 4)
	if err != nil || rep.Verdict != VerdictHostWrong || !rep.Flagged || rep.Reason != ReasonHostClockWrong || rep.TrustedTimeMs != real.UnixMilli() {
		t.Fatalf("host wrong: %+v %v", rep, err)
	}
	if got := mustNow(t, r.c); !got.Equal(real) {
		t.Fatalf("want frozen at NTS %v, got %v", real, got)
	}
	// NTS unreachable on disagreement fails closed.
	r.nts.err = errors.New("blocked")
	if _, err := r.poll(t, real.Add(3*time.Hour), 5); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if _, err := r.c.Now(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reads must fail closed after an unsettled poll, got %v", err)
	}
}

func TestPollWithoutConfig(t *testing.T) {
	r := newRig(t)
	if _, err := r.c.Poll(PollRequest{EnclaveID: "enc-1"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

func TestSetConfigRules(t *testing.T) {
	r := newRig(t)
	r.configure(t, 3)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := MonitorConfig{
		EnclaveID:     "enc-1",
		MonitorKey:    base64.RawURLEncoding.EncodeToString(pub),
		MonitorKeyID:  KeyID(pub),
		IncidentURL:   "https://m.example/api/v1/clock/incidents",
		ConfigVersion: 3,
	}
	if err := r.c.SetConfig(good); !errors.Is(err, ErrStaleConfig) {
		t.Fatalf("same version: %v", err)
	}
	bad := good
	bad.ConfigVersion = 4
	bad.MonitorKeyID = "0000000000000000"
	if err := r.c.SetConfig(bad); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("key id mismatch: %v", err)
	}
	bad = good
	bad.ConfigVersion = 4
	bad.EnclaveID = "enc-9"
	if err := r.c.SetConfig(bad); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("other enclave: %v", err)
	}
	bad = good
	bad.ConfigVersion = 4
	bad.IncidentURL = "http://m.example/x"
	if err := r.c.SetConfig(bad); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("plain http: %v", err)
	}
	good.ConfigVersion = 4
	if err := r.c.SetConfig(good); err != nil {
		t.Fatal(err)
	}
	r.open(t)
	if r.c.cfg.ConfigVersion != 4 || r.c.cfg.MonitorKeyID != KeyID(pub) {
		t.Fatalf("config not persisted: %+v", r.c.cfg)
	}
}

func TestInstalledSource(t *testing.T) {
	installed.Store(nil)
	if _, err := Now(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want fail closed with nothing installed, got %v", err)
	}
	Install(HostClock{})
	if _, err := Now(); err != nil {
		t.Fatal(err)
	}
	installed.Store(nil)
}
