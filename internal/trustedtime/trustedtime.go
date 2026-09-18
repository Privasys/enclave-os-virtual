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
// the host against two independent references.
//
//   - A platform monitor polls the runtime with a signed "the time is at
//     least T". The monitor only triggers checks: its T never becomes trusted
//     time on its own.
//   - NTS servers (RFC 8915) on the internet settle any disagreement. The
//     list is compiled in (see servers.go), never configured.
//
// # Algorithm
//
// State: floor (the highest trusted time seen), flagged, reason, all persisted
// on the encrypted /data volume, plus the last value returned (memory only).
//
//   - A read returns the host time while it is not behind the floor, never
//     less than the previous read.
//   - A host more than 1 s behind the floor is an incident: it is reported to
//     the monitor (a signed receipt is required when a monitor is
//     configured), NTS is fetched, the floor is raised to the NTS time and the
//     clock is flagged.
//   - While flagged, reads return the floor, frozen (never an offset from the
//     host clock, which would still move at the host's pace), and every 100th
//     read refetches NTS. The flag clears when the host is back at or above
//     the floor and within 10 s of NTS.
//   - A monitor poll whose T agrees with the host (10 s) raises the floor to
//     the host time. On disagreement NTS decides who is wrong.
//   - At boot the persisted floor is loaded (never below MinTrustedTime) and
//     one NTS fetch must succeed before the first read is answered.
//   - Any NTS failure fails closed: the read returns an error, never a zero
//     time, and every caller treats that as "no trusted time".
//
// The floor is only ever raised from a host time that was confirmed (by the
// monitor or NTS) or from NTS itself, so a host jumping forward cannot push it
// above real time.
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

// Options configure a Clock. Host, NTS and Reporter are injectable for tests;
// nil selects the production implementation.
type Options struct {
	// StatePath is the JSON file holding floor, flag and monitor config.
	// Keep it on the encrypted /data volume. Empty keeps state in memory
	// (tests only).
	StatePath string
	// EnclaveID, when set, is the only enclave_id a monitor config may carry.
	EnclaveID string
	Host      func() time.Time
	NTS       NTSSource
	Reporter  Reporter
	Log       *zap.Logger
}

// Clock implements the trusted-time state machine.
type Clock struct {
	host      func() time.Time
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
	// incidentErr and incidentAt back off a failed incident report.
	incidentErr error
	incidentAt  time.Time
	// ntsReported is set once an NTS outage has been reported, so retries do
	// not flood the monitor; it clears on the next successful fetch.
	ntsReported bool

	// asyncReports serialises fire-and-forget reports (one at a time).
	asyncReports sync.Mutex
}

// New loads the persisted state and returns a Clock that answers no read
// until its boot NTS fetch has succeeded (see Run and Now).
func New(opt Options) (*Clock, error) {
	c := &Clock{
		host:      opt.Host,
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

// Run performs the boot NTS fetch and keeps retrying while reads are failing
// closed, so the clock recovers even when nothing reads it. It returns when
// ctx is done.
func (c *Clock) Run(ctx context.Context) error {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		c.mu.Lock()
		if c.needFetch {
			if err := c.fetchLocked(); err != nil {
				c.log.Warn("NTS fetch failed; trusted time unavailable", zap.Error(err))
			}
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
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
	if c.needFetch {
		if err := c.retryFetchLocked(); err != nil {
			return 0, err
		}
	}
	if c.flagged {
		c.reads++
		if c.reads >= RefetchEvery {
			if err := c.fetchLocked(); err != nil {
				return 0, err
			}
		}
		if c.flagged {
			return c.returnLocked(c.floor), nil
		}
		return c.returnLocked(c.hostNow()), nil
	}
	h := c.hostNow()
	if h < c.floor-int64(behindSlack) {
		if err := c.incidentLocked(h); err != nil {
			return 0, err
		}
		return c.returnLocked(c.floor), nil
	}
	return c.returnLocked(h), nil
}

// returnLocked records and returns max(v, last): a read never goes backwards.
func (c *Clock) returnLocked(v int64) int64 {
	if v < c.last {
		v = c.last
	}
	c.last = v
	return v
}

// retryFetchLocked retries a pending NTS fetch unless the previous attempt was
// too recent, in which case the read fails closed with the previous error.
func (c *Clock) retryFetchLocked() error {
	if !c.fetchAt.IsZero() && time.Since(c.fetchAt) < retryBackoff {
		return fmt.Errorf("%w: %v", ErrUnavailable, c.fetchErr)
	}
	return c.fetchLocked()
}

// fetchLocked runs an NTS quorum and applies it: the flag clears when the host
// agrees with NTS (and, while flagged, is back at or above the floor);
// otherwise the floor rises to the NTS time and the clock is flagged. A
// failure leaves needFetch set so reads fail closed.
func (c *Clock) fetchLocked() error {
	c.fetchAt = time.Now()
	s, err := c.quorumLocked()
	if err != nil {
		c.needFetch = true
		c.fetchErr = err
		if !c.ntsReported {
			c.ntsReported = true
			c.log.Error("CRITICAL: NTS unreachable; trusted time fails closed", zap.Error(err))
			c.reportAsync(Incident{Reason: ReasonNTSUnreachable, HostTimeMs: ms(c.hostNow()), FloorMs: ms(c.floor)})
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c.needFetch = false
	c.fetchErr = nil
	c.ntsReported = false
	c.reads = 0
	h := c.hostNow()
	n := s.Time.UnixNano()
	switch {
	case abs(h-n) <= int64(Tolerance) && (!c.flagged || h >= c.floor):
		if c.flagged {
			c.log.Warn("host clock back in sync with NTS; flag cleared",
				zap.Time("host", time.Unix(0, h).UTC()), zap.Time("nts", s.Time), zap.Strings("servers", s.Servers))
		}
		c.raiseFloorLocked(h)
		c.flagged, c.reason = false, ""
	case abs(h-n) <= int64(Tolerance):
		// In sync with NTS but still behind the frozen floor: stay frozen.
		c.raiseFloorLocked(n)
	default:
		c.raiseFloorLocked(n)
		if !c.flagged {
			c.flagged, c.reason = true, ReasonHostClockWrong
			c.log.Error("CRITICAL: host clock disagrees with NTS; time frozen at the NTS time",
				zap.Time("host", time.Unix(0, h).UTC()), zap.Time("nts", s.Time), zap.Strings("servers", s.Servers))
			c.reportAsync(Incident{Reason: ReasonHostClockWrong, HostTimeMs: ms(h), FloorMs: ms(c.floor), NTSTimeMs: ms(n)})
		}
	}
	c.persistLocked()
	return nil
}

// incidentLocked handles a host that went back past a verified time. Only one
// incident runs at a time: the caller holds c.mu, so other readers wait.
func (c *Clock) incidentLocked(h int64) error {
	if !c.incidentAt.IsZero() && time.Since(c.incidentAt) < retryBackoff && c.incidentErr != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, c.incidentErr)
	}
	c.log.Error("CRITICAL: host clock went back past the trusted floor",
		zap.Time("host", time.Unix(0, h).UTC()), zap.Time("floor", time.Unix(0, c.floor).UTC()))
	inc := Incident{EnclaveID: c.cfg.EnclaveID, Reason: ReasonHostBehindFloor, HostTimeMs: ms(h), FloorMs: ms(c.floor)}
	if c.cfg.configured() {
		ctx, cancel := context.WithTimeout(context.Background(), receiptTimeout)
		err := c.reporter.Report(ctx, c.cfg, inc)
		cancel()
		if err != nil {
			c.incidentAt, c.incidentErr = time.Now(), fmt.Errorf("incident not acknowledged by the monitor: %w", err)
			return fmt.Errorf("%w: %v", ErrUnavailable, c.incidentErr)
		}
	} else {
		c.log.Error("no clock monitor configured; incident logged only", zap.String("reason", inc.Reason))
	}
	c.incidentAt, c.incidentErr = time.Time{}, nil
	c.fetchAt = time.Now()
	s, err := c.quorumLocked()
	if err != nil {
		c.needFetch = true
		c.fetchErr = err
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c.reads = 0
	c.raiseFloorLocked(s.Time.UnixNano())
	c.flagged, c.reason = true, ReasonHostBehindFloor
	c.persistLocked()
	return nil
}

func (c *Clock) quorumLocked() (Sample, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ntsTimeout)
	defer cancel()
	return c.nts.Quorum(ctx, time.Unix(0, c.floor).UTC())
}

func (c *Clock) raiseFloorLocked(v int64) {
	if v > c.floor {
		c.floor = v
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

// reportAsync sends a best-effort incident report without holding up the
// caller: the monitor learns the same facts from its next poll. Reports go
// out one at a time. With no monitor configured it only logs.
func (c *Clock) reportAsync(inc Incident) {
	cfg := c.cfg
	inc.EnclaveID = cfg.EnclaveID
	if !cfg.configured() {
		c.log.Error("no clock monitor configured; incident logged only", zap.String("reason", inc.Reason))
		return
	}
	go func() {
		c.asyncReports.Lock()
		defer c.asyncReports.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), receiptTimeout)
		defer cancel()
		if err := c.reporter.Report(ctx, cfg, inc); err != nil {
			c.log.Warn("clock incident report not acknowledged", zap.String("reason", inc.Reason), zap.Error(err))
		}
	}()
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
