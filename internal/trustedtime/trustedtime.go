// Package trustedtime is the single source of wall-clock time for every
// security decision the manager makes: token expiry, quote timestamps,
// certificate validity, verdict windows.
//
// # Why
//
// A TDX guest takes its wall clock from the host (kvm-clock, and NTP servers
// the host's DHCP hands out). A host that rolls its clock back can get an
// expired credential accepted. The runtime therefore never reads the host
// clock for a security decision directly: it asks this package, which checks
// the host against three independent references.
//
//   - A platform monitor polls the runtime with a signed "the time is at
//     least T". The monitor only triggers checks: its T never becomes trusted
//     time on its own.
//   - NTS servers (RFC 8915) on the internet settle any disagreement. The
//     list is compiled in (see servers.go), never configured.
//   - Go's monotonic clock, which the guest keeps from the TSC on TDX and the
//     host cannot change, measures how much time really passed since the host
//     clock was last confirmed.
//
// # Algorithm
//
// State: floor (the highest trusted time seen), flagged, reason, all persisted
// on the encrypted /data volume, plus the last value returned and the last
// confirmation (host wall time and monotonic instant), in memory.
//
//   - A read returns the host time while it is not behind the floor and has
//     kept pace with the monotonic clock since the last confirmation, never
//     less than the previous read.
//   - A host more than 1 s behind the floor is an incident: it is reported to
//     the monitor (a signed receipt is required when a monitor is
//     configured), NTS is fetched, the floor is raised to the NTS time and the
//     clock is flagged.
//   - A host whose clock fell more than 10 s behind the monotonic clock since
//     the last confirmation (frozen, or run slow, while staying above the
//     floor) is checked against NTS; if NTS disagrees the clock is flagged.
//   - While flagged, reads return the floor, frozen (never an offset from the
//     host clock, which would still move at the host's pace), and every 100th
//     read refetches NTS. The flag clears when the host is back at or above
//     the floor and within 10 s of NTS.
//   - A monitor poll whose T agrees with the host (10 s) raises the floor to
//     the host time, by no more than the monotonic time since the last raise
//     plus 10 s (and never by more than an hour) unless NTS confirms the host.
//     On disagreement NTS decides who is wrong.
//   - Without a confirmed poll for 15 minutes the runtime checks itself
//     against NTS, since a host can also simply block the monitor.
//   - At boot the persisted floor is loaded (never below MinTrustedTime) and
//     one NTS fetch must succeed before the first read is answered.
//   - Any NTS failure fails closed: the read returns an error, never a zero
//     time, and every caller treats that as "no trusted time".
//
// The floor is only ever raised from a host time that was confirmed (by the
// monitor or NTS) or from NTS itself, so a host jumping forward cannot push it
// above real time.
//
// Conditions found while answering a poll are reported in the poll reply only:
// the monitor is already talking to the runtime. Conditions found anywhere
// else are sent as incidents, once per condition until it changes.
//
// # Locking
//
// Network I/O (NTS, incident reports) never runs under the state mutex. One
// operation runs at a time. While it runs, reads that do not depend on its
// outcome are answered (the fast path, or the frozen floor); reads that do
// wait for it, bounded by the NTS budget and the receipt timeout: before the
// boot fetch there is no trusted time to give, and while a host-behind-floor
// incident is open the algorithm requires the receipt and the NTS answer
// before any time is returned.
package trustedtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	// Tolerance is how far the host may be from a reference and still count
	// as in sync.
	Tolerance = 10 * time.Second

	// behindSlack is how far the host may fall behind the floor before it is
	// an incident (clock slew, rounding).
	behindSlack = time.Second

	// RefetchEvery is the number of reads between two NTS fetches while
	// flagged. The host can block the monitor's polls and the runtime cannot
	// tell a poll is late, so without this the frozen time would grow stale
	// for as long as the host liked.
	RefetchEvery = 100

	// selfCheckAfter is how long the runtime goes without a confirmation
	// (a poll in sync, or NTS) before it checks itself against NTS.
	selfCheckAfter = 15 * time.Minute

	// maxPollRaise bounds how far one in-sync poll may raise the floor
	// without NTS confirming the host.
	maxPollRaise = time.Hour

	// sampleReuse is how long an NTS result stays usable by a poll that
	// arrives while (or just after) another operation fetched it. It is
	// projected forward on the monotonic clock.
	sampleReuse = 10 * time.Second

	// retryBackoff bounds how often a failing NTS fetch or incident report is
	// retried by reads. Reads in between fail closed at once.
	retryBackoff = 5 * time.Second

	// receiptTimeout is the longest an incident waits for the monitor's
	// signed receipt.
	receiptTimeout = 5 * time.Second

	// ntsTimeout bounds one whole quorum, key exchanges and NTP legs of every
	// server included. It is kept well inside the monitor's poll timeout, so a
	// host that delays NTS traffic makes a poll fail closed, not time out.
	ntsTimeout = 8 * time.Second
)

// MinTrustedTime is the lowest floor a runtime ever starts from, so a fresh
// enclave never accepts a time before its own build. Bump it from time to
// time; changing it is a runtime roll (it is part of the measured binary).
var MinTrustedTime = time.Date(2026, time.September, 18, 0, 0, 0, 0, time.UTC)

// Reasons carried by the flag, the poll reply and incident reports.
const (
	ReasonHostBehindFloor   = "host_behind_floor"
	ReasonHostClockWrong    = "host_clock_wrong"
	ReasonMonitorClockWrong = "monitor_clock_wrong"
	ReasonNTSUnreachable    = "nts_unreachable"
)

// ErrUnavailable is wrapped by every error a read returns: there is no trusted
// time right now and the caller must refuse whatever depended on it.
var ErrUnavailable = errors.New("trusted time unavailable")

// Incident is one report to the monitor. Times are Unix milliseconds; zero
// means unknown.
type Incident struct {
	EnclaveID  string
	Reason     string
	HostTimeMs int64
	FloorMs    int64
	NTSTimeMs  int64
}

// Reporter delivers an incident to the monitor configured in cfg. It returns
// nil only once the monitor's signed receipt has been verified.
type Reporter interface {
	Report(ctx context.Context, cfg MonitorConfig, inc Incident) error
}

// Options configure a Clock. Host, Mono, NTS and Reporter are injectable for
// tests; nil selects the production implementation.
type Options struct {
	// StatePath is the JSON file holding floor, flag and monitor config.
	// Keep it on the encrypted /data volume. Empty keeps state in memory
	// (tests only).
	StatePath string
	// EnclaveID, when set, is the only enclave_id a monitor config may carry.
	EnclaveID string
	// Host reads the host wall clock.
	Host func() time.Time
	// Mono reads a clock whose differences measure real elapsed time
	// (time.Now, whose monotonic reading the host cannot change on TDX).
	Mono     func() time.Time
	NTS      NTSSource
	Reporter Reporter
	Log      *zap.Logger
}

// Clock implements the trusted-time state machine.
type Clock struct {
	host      func() time.Time
	mono      func() time.Time
	nts       NTSSource
	reporter  Reporter
	log       *zap.Logger
	path      string
	enclaveID string

	mu      sync.Mutex
	floor   int64 // Unix ns
	flagged bool
	reason  string
	cfg     MonitorConfig
	last    int64 // Unix ns of the last value returned

	// needFetch is set at boot and after a failed NTS fetch: reads fail
	// closed until a fetch succeeds.
	needFetch bool
	fetchErr  error
	fetchAt   time.Time // monotonic, last fetch attempt
	// reads counts reads since the last NTS fetch while flagged.
	reads int
	// incidentErr and incidentAt back off an unacknowledged incident.
	incidentErr error
	incidentAt  time.Time

	// anchorWall is the host wall time confirmed at the monotonic instant
	// anchorMono (a poll in sync, or NTS). Zero anchorMono: none yet.
	anchorWall int64
	anchorMono time.Time
	// raiseMono is the monotonic instant of the last floor raise.
	raiseMono time.Time
	// sample is the last NTS result, taken at monotonic instant sampleMono.
	sample     Sample
	sampleMono time.Time
	// reported is the condition last sent as an incident; it is not sent
	// again until the condition changes.
	reported string

	// op is the network operation in flight, if any (one at a time).
	op *operation
}

// operation is a network step running without c.mu; done closes when its
// result has been applied.
type operation struct{ done chan struct{} }

// New loads the persisted state and returns a Clock that answers no read
// until its boot NTS fetch has succeeded (see Run and Now).
func New(opt Options) (*Clock, error) {
	c := &Clock{
		host:      opt.Host,
		mono:      opt.Mono,
		nts:       opt.NTS,
		reporter:  opt.Reporter,
		log:       opt.Log,
		path:      opt.StatePath,
		enclaveID: opt.EnclaveID,
		needFetch: true,
		fetchErr:  errors.New("boot NTS fetch not done yet"),
	}
	if c.host == nil {
		c.host = time.Now
	}
	if c.mono == nil {
		c.mono = time.Now
	}
	if c.nts == nil {
		c.nts = NewNTSQuorum()
	}
	if c.reporter == nil {
		c.reporter = NewHTTPReporter()
	}
	if c.log == nil {
		c.log = zap.NewNop()
	}
	c.log = c.log.Named("trustedtime")
	st, err := loadState(c.path)
	if err != nil {
		return nil, err
	}
	c.floor = st.FloorMs * int64(time.Millisecond)
	c.flagged = st.Flagged
	c.reason = st.Reason
	if st.Config != nil {
		c.cfg = *st.Config
	}
	if min := MinTrustedTime.UnixNano(); c.floor < min {
		c.floor = min
	}
	c.log.Info("trusted clock loaded",
		zap.Time("floor", time.Unix(0, c.floor).UTC()),
		zap.Bool("flagged", c.flagged),
		zap.String("reason", c.reason),
		zap.Bool("monitor_configured", c.cfg.configured()))
	return c, nil
}

// Run performs the boot NTS fetch, keeps retrying while reads are failing
// closed, and checks the host against NTS when nothing has confirmed it for
// selfCheckAfter (the host can block the monitor's polls). It returns when
// ctx is done.
func (c *Clock) Run(ctx context.Context) error {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		c.tick()
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// tick is one pass of Run.
func (c *Clock) tick() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.op != nil {
		return
	}
	switch {
	case c.needFetch:
		if err := c.fetchLocked(false); err != nil {
			c.log.Warn("NTS fetch failed; trusted time unavailable", zap.Error(err))
		}
	case c.lastCheckLocked().IsZero() || c.mono().Sub(c.lastCheckLocked()) >= selfCheckAfter:
		if err := c.fetchLocked(false); err != nil {
			c.log.Warn("NTS self-check failed; trusted time unavailable", zap.Error(err))
		}
	}
}

// lastCheckLocked is the monotonic instant the host was last checked: a
// confirmation, or an NTS result (which, while flagged, confirms nothing but
// still refreshes the frozen time).
func (c *Clock) lastCheckLocked() time.Time {
	if c.sampleMono.After(c.anchorMono) {
		return c.sampleMono
	}
	return c.anchorMono
}

// hostNow reads the host clock as Unix ns (no monotonic reading).
func (c *Clock) hostNow() int64 { return c.host().UnixNano() }

// Now returns the trusted time, or an error wrapping ErrUnavailable when
// there is none. It never returns less than a previous successful call.
func (c *Clock) Now() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ns, err := c.nowLocked()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, ns).UTC(), nil
}

func (c *Clock) nowLocked() (int64, error) {
	for {
		if c.needFetch {
			if c.op != nil {
				c.waitLocked() // before the boot fetch there is nothing to give
				continue
			}
			if err := c.retryFetchLocked(); err != nil {
				return 0, err
			}
			continue
		}
		if c.flagged {
			c.reads++
			if c.reads >= RefetchEvery && c.op == nil {
				// Refetch in the background: meanwhile the frozen floor is
				// the answer anyway. A failure sets needFetch, so the reads
				// after it fail closed.
				c.reads = 0
				op := c.beginLocked()
				go func() {
					c.mu.Lock()
					defer c.mu.Unlock()
					_ = c.fetchOwnedLocked(op, false)
				}()
			}
			return c.returnLocked(c.floor), nil
		}
		h := c.hostNow()
		behind := h < c.floor-int64(behindSlack)
		slow := c.slowLocked(h)
		if !behind && !slow {
			return c.returnLocked(h), nil
		}
		if c.op != nil {
			c.waitLocked() // one incident at a time; the outcome decides this read
			continue
		}
		if behind {
			if err := c.incidentLocked(h); err != nil {
				return 0, err
			}
			continue
		}
		// Slow or frozen host: NTS decides.
		c.log.Warn("host clock fell behind the monotonic clock; checking NTS",
			zap.Time("host", time.Unix(0, h).UTC()),
			zap.Time("expected", time.Unix(0, c.expectedLocked()).UTC()))
		if err := c.fetchLocked(false); err != nil {
			return 0, err
		}
	}
}

// slowLocked reports whether the host clock advanced more than Tolerance less
// than the monotonic clock since the last confirmation: a host that freezes or
// slows its clock while staying above the floor.
func (c *Clock) slowLocked(h int64) bool {
	if c.anchorMono.IsZero() {
		return false
	}
	return h < c.expectedLocked()-int64(Tolerance)
}

// expectedLocked is the confirmed host time carried forward on the monotonic
// clock.
func (c *Clock) expectedLocked() int64 {
	return c.anchorWall + int64(c.mono().Sub(c.anchorMono))
}

// returnLocked records and returns max(v, last): a read never goes backwards.
func (c *Clock) returnLocked(v int64) int64 {
	if v < c.last {
		v = c.last
	}
	c.last = v
	return v
}

// beginLocked starts an operation. The caller must hold c.mu and have checked
// that none is in flight.
func (c *Clock) beginLocked() *operation {
	op := &operation{done: make(chan struct{})}
	c.op = op
	return op
}

// endLocked finishes an operation and wakes whoever waits on it.
func (c *Clock) endLocked(op *operation) {
	if c.op == op {
		c.op = nil
	}
	close(op.done)
}

// waitLocked releases c.mu until the operation in flight has finished.
func (c *Clock) waitLocked() {
	op := c.op
	c.mu.Unlock()
	<-op.done
	c.mu.Lock()
}

// quorumUnlocked runs an NTS quorum with c.mu released.
func (c *Clock) quorumUnlocked() (Sample, error) {
	floor := time.Unix(0, c.floor).UTC()
	c.mu.Unlock()
	defer c.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), ntsTimeout)
	defer cancel()
	return c.nts.Quorum(ctx, floor)
}

// retryFetchLocked retries a pending NTS fetch unless the previous attempt was
// too recent, in which case the read fails closed with the previous error.
func (c *Clock) retryFetchLocked() error {
	if !c.fetchAt.IsZero() && c.mono().Sub(c.fetchAt) < retryBackoff {
		return fmt.Errorf("%w: %v", ErrUnavailable, c.fetchErr)
	}
	return c.fetchLocked(false)
}

// fetchLocked runs an NTS quorum and applies it. inPoll marks a fetch made
// while answering a poll, whose findings go in the reply, not in incidents.
func (c *Clock) fetchLocked(inPoll bool) error {
	return c.fetchOwnedLocked(c.beginLocked(), inPoll)
}

// fetchOwnedLocked is fetchLocked for an operation the caller already began.
// The flag clears when the host agrees with NTS (and, while flagged, is back
// at or above the floor); otherwise the floor rises to the NTS time and the
// clock is flagged. A failure leaves needFetch set so reads fail closed.
func (c *Clock) fetchOwnedLocked(op *operation, inPoll bool) error {
	defer c.endLocked(op)
	c.fetchAt = c.mono()
	s, err := c.quorumUnlocked()
	if err != nil {
		c.needFetch = true
		c.fetchErr = err
		c.log.Error("CRITICAL: NTS unreachable; trusted time fails closed", zap.Error(err))
		if !inPoll {
			c.incidentAsyncLocked(Incident{Reason: ReasonNTSUnreachable, HostTimeMs: ms(c.hostNow()), FloorMs: ms(c.floor)})
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c.applySampleLocked(s, inPoll)
	return nil
}

// applySampleLocked applies a fresh NTS result.
func (c *Clock) applySampleLocked(s Sample, inPoll bool) {
	c.needFetch = false
	c.fetchErr = nil
	c.reads = 0
	c.sample, c.sampleMono = s, c.mono()
	if c.reported == ReasonNTSUnreachable {
		c.reported = ""
	}
	h := c.hostNow()
	n := s.Time.UnixNano()
	switch {
	case abs(h-n) <= int64(Tolerance) && (!c.flagged || h >= c.floor):
		if c.flagged {
			c.log.Warn("host clock back in sync with NTS; flag cleared",
				zap.Time("host", time.Unix(0, h).UTC()), zap.Time("nts", s.Time), zap.Strings("servers", s.Servers))
		}
		c.confirmLocked(h)
	case abs(h-n) <= int64(Tolerance):
		// In sync with NTS but still behind the frozen floor: stay frozen.
		c.raiseFloorLocked(n)
	default:
		c.raiseFloorLocked(n)
		if !c.flagged {
			c.flagged, c.reason = true, ReasonHostClockWrong
			c.log.Error("CRITICAL: host clock disagrees with NTS; time frozen at the NTS time",
				zap.Time("host", time.Unix(0, h).UTC()), zap.Time("nts", s.Time), zap.Strings("servers", s.Servers))
			if !inPoll {
				c.incidentAsyncLocked(Incident{Reason: ReasonHostClockWrong, HostTimeMs: ms(h), FloorMs: ms(c.floor), NTSTimeMs: ms(n)})
			}
		}
	}
	c.persistLocked()
}

// confirmLocked records a confirmed host time: the floor rises to it, it
// becomes the anchor the monotonic clock is compared against, and the flag
// clears.
func (c *Clock) confirmLocked(h int64) {
	c.raiseFloorLocked(h)
	c.anchorWall, c.anchorMono = h, c.mono()
	if c.flagged || c.reported != "" {
		c.reported = "" // the condition changed: a new one is reported afresh
	}
	c.flagged, c.reason = false, ""
}

// incidentLocked handles a host that went back past a verified time. The
// caller holds c.mu and no operation is in flight; readers that arrive
// meanwhile wait for this one.
func (c *Clock) incidentLocked(h int64) error {
	if c.incidentErr != nil && c.mono().Sub(c.incidentAt) < retryBackoff {
		return fmt.Errorf("%w: %v", ErrUnavailable, c.incidentErr)
	}
	op := c.beginLocked()
	c.log.Error("CRITICAL: host clock went back past the trusted floor",
		zap.Time("host", time.Unix(0, h).UTC()), zap.Time("floor", time.Unix(0, c.floor).UTC()))
	inc := Incident{EnclaveID: c.cfg.EnclaveID, Reason: ReasonHostBehindFloor, HostTimeMs: ms(h), FloorMs: ms(c.floor)}
	if cfg := c.cfg; cfg.configured() {
		c.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), receiptTimeout)
		err := c.reporter.Report(ctx, cfg, inc)
		cancel()
		c.mu.Lock()
		if err != nil {
			c.incidentAt, c.incidentErr = c.mono(), fmt.Errorf("incident not acknowledged by the monitor: %w", err)
			c.endLocked(op)
			return fmt.Errorf("%w: %v", ErrUnavailable, c.incidentErr)
		}
	} else {
		c.log.Error("no clock monitor configured; incident logged only", zap.String("reason", inc.Reason))
	}
	c.reported = ReasonHostBehindFloor
	c.incidentAt, c.incidentErr = time.Time{}, nil
	defer c.endLocked(op)
	c.fetchAt = c.mono()
	s, err := c.quorumUnlocked()
	if err != nil {
		c.needFetch = true
		c.fetchErr = err
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c.needFetch, c.fetchErr, c.reads = false, nil, 0
	c.sample, c.sampleMono = s, c.mono()
	c.raiseFloorLocked(s.Time.UnixNano())
	c.flagged, c.reason = true, ReasonHostBehindFloor
	c.persistLocked()
	return nil
}

func (c *Clock) raiseFloorLocked(v int64) {
	if v > c.floor {
		c.floor = v
		c.raiseMono = c.mono()
	}
}

func (c *Clock) persistLocked() {
	cfg := c.cfg
	st := state{FloorMs: ms(c.floor), Flagged: c.flagged, Reason: c.reason}
	if cfg.configured() {
		st.Config = &cfg
	}
	if err := saveState(c.path, st); err != nil {
		c.log.Error("failed to persist trusted clock state", zap.Error(err))
	}
}

// incidentAsyncLocked sends a best-effort incident without holding up the
// caller, once per condition until the condition changes. With no monitor
// configured it only logs.
func (c *Clock) incidentAsyncLocked(inc Incident) {
	if c.reported == inc.Reason {
		return
	}
	c.reported = inc.Reason
	cfg := c.cfg
	inc.EnclaveID = cfg.EnclaveID
	if !cfg.configured() {
		c.log.Error("no clock monitor configured; incident logged only", zap.String("reason", inc.Reason))
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), receiptTimeout)
		defer cancel()
		if err := c.reporter.Report(ctx, cfg, inc); err != nil {
			c.log.Warn("clock incident report not acknowledged", zap.String("reason", inc.Reason), zap.Error(err))
		}
	}()
}

// IssueTime is the time to stamp on what the runtime issues (its RA-TLS
// certificates and quote times), as opposed to what it verifies. It never
// blocks on the network and never fails: when trusted time is available it
// is trusted time (trusted true), otherwise it is max(floor, last trusted
// value), the most recent time the runtime can vouch for (trusted false).
//
// Issuing is not a security decision of the enclave: whoever verifies a
// certificate or a quote judges its dates against their own clock. Refusing
// to issue would only make the enclave unreachable, including the poll
// endpoint that lets it recover. Every verification decision still reads Now
// and fails closed.
func (c *Clock) IssueTime() (t time.Time, trusted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fallback := c.floor
	if c.last > fallback {
		fallback = c.last
	}
	switch {
	case c.needFetch:
		return time.Unix(0, fallback).UTC(), false
	case c.flagged:
		return time.Unix(0, c.returnLocked(c.floor)).UTC(), true
	}
	h := c.hostNow()
	if h < c.floor-int64(behindSlack) || c.slowLocked(h) {
		// A read would open an incident; issuing does not wait for it.
		return time.Unix(0, fallback).UTC(), false
	}
	return time.Unix(0, c.returnLocked(h)).UTC(), true
}

func ms(ns int64) int64 { return ns / int64(time.Millisecond) }

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// ---------------------------------------------------------------------------
// Process-wide source
// ---------------------------------------------------------------------------

// Source answers trusted-time reads.
type Source interface {
	Now() (time.Time, error)
}

var installed atomic.Pointer[Source]

// Install makes s the process-wide source behind Now. The manager installs its
// Clock at startup, before serving anything.
func Install(s Source) {
	installed.Store(&s)
}

// Now returns the process-wide trusted time. Before a source is installed it
// fails closed.
func Now() (time.Time, error) {
	p := installed.Load()
	if p == nil {
		return time.Time{}, fmt.Errorf("%w: no trusted clock installed", ErrUnavailable)
	}
	return (*p).Now()
}

// HostClock is a Source that trusts the host clock. It exists for tests and
// for tools that run outside the enclave; the manager never installs it.
type HostClock struct{}

// Now returns the host time.
func (HostClock) Now() (time.Time, error) { return time.Now().UTC().Round(0), nil }
