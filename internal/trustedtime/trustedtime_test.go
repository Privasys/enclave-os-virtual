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
	mono *fakeHost // real elapsed time, as the monotonic clock sees it
	nts  *fakeNTS
	rep  *fakeReporter
	path string
	priv ed25519.PrivateKey
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{
		host: &fakeHost{t: t0},
		mono: &fakeHost{t: t0},
		nts:  &fakeNTS{t: t0},
		rep:  &fakeReporter{done: make(chan struct{}, 16)},
		path: filepath.Join(t.TempDir(), "clock.json"),
	}
	r.open(t)
	return r
}

func (r *rig) open(t *testing.T) {
	t.Helper()
	c, err := New(Options{StatePath: r.path, EnclaveID: "enc-1", Host: r.host.now, Mono: r.mono.now, NTS: r.nts, Reporter: r.rep})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
}

// pass moves real time on: the host clock (if it is honest) and the
// monotonic clock together.
func (r *rig) pass(d time.Duration) {
	r.host.add(d)
	r.mono.add(d)
}

// settle waits for the operation in flight, if any (a background refetch).
func (r *rig) settle() {
	r.c.mu.Lock()
	if r.c.op != nil {
		r.c.waitLocked()
	}
	r.c.mu.Unlock()
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
	mustNow(t, r.c) // flags; this read is the first of the hundred
	calls := r.nts.calls
	for i := 0; i < RefetchEvery-2; i++ {
		mustNow(t, r.c)
	}
	r.settle()
	if r.nts.calls != calls {
		t.Fatalf("refetched early: %d calls", r.nts.calls-calls)
	}
	r.nts.t = t0.Add(5 * time.Minute)
	// The 100th read refetches in the background and answers the frozen
	// floor meanwhile; the reads after it see the refreshed time.
	if got := mustNow(t, r.c); !got.Equal(t0) {
		t.Fatalf("the triggering read must answer the frozen floor, got %v", got)
	}
	r.settle()
	got := mustNow(t, r.c)
	if r.nts.calls != calls+1 || !got.Equal(t0.Add(5*time.Minute)) {
		t.Fatalf("want one refetch refreshing the frozen time, calls=%d got=%v", r.nts.calls-calls, got)
	}
	// A failed refetch fails closed, and is reported once as an incident.
	r.configure(t, 1)
	r.nts.err = errors.New("blocked")
	for i := 0; i < RefetchEvery-1; i++ {
		mustNow(t, r.c)
	}
	r.settle()
	if _, err := r.c.Now(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want fail closed on a failed refetch, got %v", err)
	}
	waitReport(t, r.rep, ReasonNTSUnreachable)
}

func TestFlagClearsWhenHostFixed(t *testing.T) {
	r := newRig(t)
	mustNow(t, r.c)
	r.host.add(-time.Hour)
	mustNow(t, r.c)
	// The host is fixed: back at real time, which has moved on.
	r.pass(10 * time.Minute)
	r.host.set(t0.Add(10 * time.Minute))
	r.nts.t = t0.Add(10 * time.Minute)
	for i := 0; i < RefetchEvery; i++ {
		mustNow(t, r.c)
	}
	r.settle()
	if r.c.flagged {
		t.Fatal("flag should clear once NTS confirms the host")
	}
	r.pass(time.Second)
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
	r.pass(time.Minute)
	calls := r.nts.calls
	rep, err := r.poll(t, t0.Add(time.Minute+2*time.Second), 1)
	if err != nil || rep.Verdict != VerdictInSync || rep.FloorMs != t0.Add(time.Minute).UnixMilli() || rep.Runtime != "virtual" || r.nts.calls != calls {
		t.Fatalf("in sync: %+v %v (NTS calls %d)", rep, err, r.nts.calls-calls)
	}
	// Stale.
	rep, err = r.poll(t, t0, 2)
	if err != nil || rep.Verdict != VerdictIgnoredStale {
		t.Fatalf("stale: %+v %v", rep, err)
	}
	// Monitor wrong: the host agrees with NTS.
	r.pass(sampleReuse)
	r.nts.t = r.host.now()
	rep, err = r.poll(t, r.host.now().Add(time.Hour), 3)
	if err != nil || rep.Verdict != VerdictMonitorWrong || rep.Flagged || rep.NTS.TimeMs == 0 || len(rep.NTS.Servers) != 2 {
		t.Fatalf("monitor wrong: %+v %v", rep, err)
	}
	// Host wrong: the monitor agrees with NTS.
	r.pass(sampleReuse)
	real := r.host.now().Add(time.Hour)
	r.nts.t = real
	rep, err = r.poll(t, real, 4)
	if err != nil || rep.Verdict != VerdictHostWrong || !rep.Flagged || rep.Reason != ReasonHostClockWrong || rep.TrustedTimeMs != real.UnixMilli() {
		t.Fatalf("host wrong: %+v %v", rep, err)
	}
	if got := mustNow(t, r.c); !got.Equal(real) {
		t.Fatalf("want frozen at NTS %v, got %v", real, got)
	}
	// What a poll finds is in its reply, never an incident.
	if rs := r.rep.reasons(); len(rs) != 0 {
		t.Fatalf("poll findings were sent as incidents: %v", rs)
	}
	// NTS unreachable on disagreement fails closed.
	r.pass(sampleReuse)
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
	// The same version is a retry: accepted, and the held config stays.
	held := r.c.cfg
	if err := r.c.SetConfig(good); err != nil {
		t.Fatalf("same version: %v", err)
	}
	if r.c.cfg != held {
		t.Fatal("a same-version push replaced the held config")
	}
	lower := good
	lower.ConfigVersion = 2
	if err := r.c.SetConfig(lower); !errors.Is(err, ErrStaleConfig) {
		t.Fatalf("lower version: %v", err)
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

// waitReport waits for an incident with reason to reach the reporter.
func waitReport(t *testing.T, rep *fakeReporter, reason string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range rep.reasons() {
			if r == reason {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %s incident reported (got %v)", reason, rep.reasons())
}

// An in-sync poll may not raise the floor faster than real time without NTS:
// a host and a monitor key agreeing on a future time get checked, and lose.
func TestInSyncPollRaiseIsCapped(t *testing.T) {
	r := newRig(t)
	r.configure(t, 1)
	mustNow(t, r.c)
	r.pass(time.Minute)
	future := r.host.now().Add(2 * time.Hour)
	r.host.set(future)
	calls := r.nts.calls
	rep, err := r.poll(t, future, 1)
	if err != nil || r.nts.calls != calls+1 {
		t.Fatalf("a jump past real elapsed time must ask NTS: %+v %v", rep, err)
	}
	if rep.Verdict != VerdictHostWrong || rep.FloorMs >= future.UnixMilli() {
		t.Fatalf("floor pushed into the future: %+v", rep)
	}
	// Within real elapsed time (plus tolerance) no NTS is needed.
	r2 := newRig(t)
	r2.configure(t, 1)
	mustNow(t, r2.c)
	r2.pass(5 * time.Minute)
	calls = r2.nts.calls
	rep, err = r2.poll(t, r2.host.now(), 1)
	if err != nil || rep.Verdict != VerdictInSync || r2.nts.calls != calls {
		t.Fatalf("normal in-sync poll: %+v %v calls=%d", rep, err, r2.nts.calls-calls)
	}
	// And NTS confirming a large jump lets it through.
	r3 := newRig(t)
	r3.configure(t, 1)
	mustNow(t, r3.c)
	later := t0.Add(3 * time.Hour) // e.g. the enclave was down for three hours
	r3.host.set(later)
	r3.nts.t = later
	r3.mono.add(sampleReuse)
	rep, err = r3.poll(t, later, 1)
	if err != nil || rep.Verdict != VerdictInSync || rep.FloorMs != later.UnixMilli() {
		t.Fatalf("NTS-confirmed jump: %+v %v", rep, err)
	}
}

// blockingNTS holds every quorum until released.
type blockingNTS struct {
	release chan struct{}
	t       time.Time
}

func (b *blockingNTS) Quorum(ctx context.Context, _ time.Time) (Sample, error) {
	select {
	case <-b.release:
	case <-ctx.Done():
		return Sample{}, ctx.Err()
	}
	return Sample{Time: b.t, Servers: []string{"a", "b"}}, nil
}

// Readers are not held up by a network operation whose outcome they do not
// need: the state mutex is released during NTS. The operation here is the
// background refetch of a flagged clock, during which reads keep getting the
// frozen floor.
func TestReadsDoNotWaitForBackgroundNTS(t *testing.T) {
	host := &fakeHost{t: t0}
	mono := &fakeHost{t: t0}
	nts := &blockingNTS{release: make(chan struct{}, 1), t: t0}
	c, err := New(Options{Host: host.now, Mono: mono.now, NTS: nts, Reporter: &fakeReporter{}})
	if err != nil {
		t.Fatal(err)
	}
	nts.release <- struct{}{}
	if _, err := c.Now(); err != nil { // boot fetch
		t.Fatal(err)
	}
	host.add(-time.Hour)
	nts.release <- struct{}{}
	if _, err := c.Now(); err != nil { // host behind the floor: flagged
		t.Fatal(err)
	}
	// Reach the refetch cap: its NTS quorum blocks until released.
	for i := 0; i < RefetchEvery; i++ {
		if _, err := c.Now(); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	busy := c.op != nil
	c.mu.Unlock()
	if !busy {
		t.Fatal("no background refetch in flight")
	}
	done := make(chan error, 1)
	go func() { _, err := c.Now(); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("a read waited for the background refetch")
	}
	nts.release <- struct{}{}
}

// Between polls, an unflagged clock with an honest host never calls NTS:
// the runtime does not police the host on its own, blocked polls are the
// monitor's to act on.
func TestNoNTSBetweenPollsWhileUnflagged(t *testing.T) {
	r := newRig(t)
	mustNow(t, r.c) // boot fetch
	calls := r.nts.calls
	for i := 0; i < 10*RefetchEvery; i++ {
		r.pass(time.Minute) // hours go by without a poll
		mustNow(t, r.c)
		r.c.tick()
	}
	r.settle()
	if r.nts.calls != calls {
		t.Fatalf("NTS called %d times between polls on an unflagged clock", r.nts.calls-calls)
	}
}

// While trusted time is unavailable, a signed poll retries NTS; an unsigned
// one does not.
func TestSignedPollRetriesNTSWhileFailingClosed(t *testing.T) {
	r := newRig(t)
	r.configure(t, 1)
	r.nts.err = errors.New("blocked")
	if _, err := r.c.Now(); err == nil {
		t.Fatal("want fail closed")
	}
	calls := r.nts.calls
	if _, err := r.c.Poll(PollRequest{EnclaveID: "enc-1", TMs: t0.UnixMilli(), KeyID: r.c.cfg.MonitorKeyID, Sig: "AAAA"}); !errors.Is(err, ErrBadPoll) {
		t.Fatalf("want ErrBadPoll, got %v", err)
	}
	if r.nts.calls != calls {
		t.Fatal("an unsigned poll triggered NTS")
	}
	r.nts.err = nil
	rep, err := r.poll(t, t0, 1)
	if err != nil || r.nts.calls != calls+1 || rep.Verdict != VerdictInSync || rep.TrustedTimeMs == 0 {
		t.Fatalf("signed poll: %+v %v calls=%d", rep, err, r.nts.calls-calls)
	}
	if _, err := r.c.Now(); err != nil {
		t.Fatalf("trusted time not back after the poll's NTS retry: %v", err)
	}
}

// Issuing never blocks and never fails: without trusted time it uses the
// floor, and says so.
func TestIssueTimeWhileFailingClosed(t *testing.T) {
	r := newRig(t)
	r.nts.err = errors.New("blocked")
	it, trusted := r.c.IssueTime()
	if trusted || it.Before(MinTrustedTime) {
		t.Fatalf("got %v trusted=%v", it, trusted)
	}
	r.nts.err = nil
	r.c.fetchAt = time.Time{}
	mustNow(t, r.c)
	if it, trusted = r.c.IssueTime(); !trusted || !it.Equal(t0) {
		t.Fatalf("healthy: got %v trusted=%v", it, trusted)
	}
}
