package trustedtime

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// MonitorConfig pins the clock monitor: its Ed25519 key, the URL incidents go
// to, and the enclave id the monitor knows this runtime by. The management
// service delivers it (PUT /api/v1/clock/config); only a higher
// config_version replaces it.
type MonitorConfig struct {
	EnclaveID     string `json:"enclave_id"`
	MonitorKey    string `json:"monitor_key"`
	MonitorKeyID  string `json:"monitor_key_id"`
	IncidentURL   string `json:"incident_url"`
	ConfigVersion int64  `json:"config_version"`
}

func (m MonitorConfig) configured() bool { return m.MonitorKey != "" && m.IncidentURL != "" }

// publicKey decodes the pinned monitor key.
func (m MonitorConfig) publicKey() (ed25519.PublicKey, error) {
	raw, err := b64Decode(m.MonitorKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("monitor_key must be a base64url 32-byte Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// KeyID is the key id of an Ed25519 public key: the first 16 hex characters
// of its SHA-256.
func KeyID(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])[:16]
}

// Config errors the HTTP layer maps to status codes.
var (
	ErrInvalidConfig = errors.New("invalid clock config")
	ErrStaleConfig   = errors.New("config_version is lower than the current one")
	ErrNotConfigured = errors.New("no clock monitor configured")
	ErrBadPoll       = errors.New("poll rejected")
)

// SetConfig validates and persists a monitor config. A lower version than the
// current one is refused; the same version is a no-op (the management service
// retries its push); only a higher one replaces the config.
func (c *Clock) SetConfig(cfg MonitorConfig) error {
	if cfg.EnclaveID == "" {
		return fmt.Errorf("%w: enclave_id is required", ErrInvalidConfig)
	}
	if c.enclaveID != "" && !strings.EqualFold(cfg.EnclaveID, c.enclaveID) {
		return fmt.Errorf("%w: enclave_id %q is not this enclave", ErrInvalidConfig, cfg.EnclaveID)
	}
	pub, err := cfg.publicKey()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if want := KeyID(pub); !strings.EqualFold(cfg.MonitorKeyID, want) {
		return fmt.Errorf("%w: monitor_key_id %q does not match the key (%s)", ErrInvalidConfig, cfg.MonitorKeyID, want)
	}
	u, err := url.Parse(cfg.IncidentURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: incident_url must be an https URL", ErrInvalidConfig)
	}
	cfg.MonitorKeyID = strings.ToLower(cfg.MonitorKeyID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg.ConfigVersion < c.cfg.ConfigVersion {
		return fmt.Errorf("%w (have %d, got %d)", ErrStaleConfig, c.cfg.ConfigVersion, cfg.ConfigVersion)
	}
	if cfg.ConfigVersion == c.cfg.ConfigVersion && c.cfg.configured() {
		// A re-push of the version already held (a retry): accepted as a
		// no-op. The held config stays; a change needs a higher version.
		if cfg != c.cfg {
			c.log.Warn("clock config re-pushed at the same version with different content; keeping the held one",
				zap.Int64("config_version", cfg.ConfigVersion),
				zap.String("held_key_id", c.cfg.MonitorKeyID),
				zap.String("pushed_key_id", cfg.MonitorKeyID))
		}
		return nil
	}
	c.cfg = cfg
	c.persistLocked()
	c.log.Info("clock monitor config installed",
		zap.String("enclave_id", cfg.EnclaveID),
		zap.String("monitor_key_id", cfg.MonitorKeyID),
		zap.String("incident_url", cfg.IncidentURL),
		zap.Int64("config_version", cfg.ConfigVersion))
	return nil
}

// PollRequest is the monitor's signed floor.
type PollRequest struct {
	EnclaveID string `json:"enclave_id"`
	TMs       int64  `json:"t_ms"`
	Seq       int64  `json:"seq"`
	KeyID     string `json:"key_id"`
	Sig       string `json:"sig"`
}

// PollSignedBytes are the bytes the monitor signs for a poll.
func PollSignedBytes(enclaveID string, tMs, seq int64) []byte {
	return []byte("privasys-clock-floor/v1\n" + enclaveID + "\n" +
		strconv.FormatInt(tMs, 10) + "\n" + strconv.FormatInt(seq, 10))
}

// PollNTS is the NTS result a poll used, if any.
type PollNTS struct {
	TimeMs  int64    `json:"time_ms"`
	Servers []string `json:"servers"`
}

// PollReply is what the runtime answers a poll with.
type PollReply struct {
	EnclaveID     string  `json:"enclave_id"`
	Runtime       string  `json:"runtime"`
	HostTimeMs    int64   `json:"host_time_ms"`
	TrustedTimeMs int64   `json:"trusted_time_ms"`
	FloorMs       int64   `json:"floor_ms"`
	Flagged       bool    `json:"flagged"`
	Reason        string  `json:"reason"`
	Verdict       string  `json:"verdict"`
	NTS           PollNTS `json:"nts"`
	ConfigKeyID   string  `json:"config_key_id"`
}

// Poll verdicts.
const (
	VerdictInSync       = "in_sync"
	VerdictMonitorWrong = ReasonMonitorClockWrong
	VerdictHostWrong    = ReasonHostClockWrong
	VerdictIgnoredStale = "ignored_stale"
)

// Poll applies a monitor poll. It returns ErrNotConfigured when no monitor is
// pinned, ErrBadPoll when the poll is not the pinned monitor's, and an error
// wrapping ErrUnavailable when the host and monitor disagree and NTS cannot
// settle it (the clock then fails closed until NTS answers).
func (c *Clock) Poll(req PollRequest) (PollReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.cfg.configured() {
		return PollReply{}, ErrNotConfigured
	}
	if req.EnclaveID != c.cfg.EnclaveID {
		return PollReply{}, fmt.Errorf("%w: enclave_id %q is not this enclave", ErrBadPoll, req.EnclaveID)
	}
	if !strings.EqualFold(req.KeyID, c.cfg.MonitorKeyID) {
		return PollReply{}, fmt.Errorf("%w: key_id %q is not the pinned monitor key %q", ErrBadPoll, req.KeyID, c.cfg.MonitorKeyID)
	}
	pub, err := c.cfg.publicKey()
	if err != nil {
		return PollReply{}, fmt.Errorf("%w: %v", ErrBadPoll, err)
	}
	sig, err := b64Decode(req.Sig)
	if err != nil || !ed25519.Verify(pub, PollSignedBytes(req.EnclaveID, req.TMs, req.Seq), sig) {
		return PollReply{}, fmt.Errorf("%w: bad signature", ErrBadPoll)
	}

	reply := PollReply{EnclaveID: c.cfg.EnclaveID, Runtime: "virtual", ConfigKeyID: c.cfg.MonitorKeyID, NTS: PollNTS{Servers: []string{}}}
	t := req.TMs * int64(time.Millisecond)
	h := c.hostNow()
	switch {
	case t < c.floor:
		// A replay or a slow monitor: it can say nothing about the floor.
		reply.Verdict = VerdictIgnoredStale
	case abs(h-t) <= int64(Tolerance):
		c.raiseFloorLocked(h)
		c.flagged, c.reason = false, ""
		reply.Verdict = VerdictInSync
	default:
		c.fetchAt = time.Now()
		s, err := c.quorumLocked()
		if err != nil {
			c.needFetch = true
			c.fetchErr = err
			c.log.Error("CRITICAL: host and monitor disagree and NTS is unreachable; failing closed",
				zap.Time("host", time.Unix(0, h).UTC()), zap.Time("monitor", time.Unix(0, t).UTC()), zap.Error(err))
			c.reportAsync(Incident{Reason: ReasonNTSUnreachable, HostTimeMs: ms(h), FloorMs: ms(c.floor)})
			return PollReply{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		c.needFetch, c.fetchErr, c.reads = false, nil, 0
		h = c.hostNow()
		n := s.Time.UnixNano()
		reply.NTS = PollNTS{TimeMs: ms(n), Servers: s.Servers}
		if abs(h-n) <= int64(Tolerance) {
			c.raiseFloorLocked(h)
			c.flagged, c.reason = false, ""
			reply.Verdict = VerdictMonitorWrong
			c.log.Error("CRITICAL: clock monitor disagrees with the host and NTS",
				zap.Time("host", time.Unix(0, h).UTC()), zap.Time("monitor", time.Unix(0, t).UTC()), zap.Time("nts", s.Time))
			c.reportAsync(Incident{Reason: ReasonMonitorClockWrong, HostTimeMs: ms(h), FloorMs: ms(c.floor), NTSTimeMs: ms(n)})
		} else {
			c.raiseFloorLocked(n)
			c.flagged, c.reason = true, ReasonHostClockWrong
			reply.Verdict = VerdictHostWrong
			c.log.Error("CRITICAL: host clock disagrees with the monitor and NTS; time frozen at the NTS time",
				zap.Time("host", time.Unix(0, h).UTC()), zap.Time("monitor", time.Unix(0, t).UTC()), zap.Time("nts", s.Time))
			c.reportAsync(Incident{Reason: ReasonHostClockWrong, HostTimeMs: ms(h), FloorMs: ms(c.floor), NTSTimeMs: ms(n)})
		}
	}
	if reply.Verdict != VerdictIgnoredStale {
		c.persistLocked()
	}

	reply.HostTimeMs = ms(h)
	reply.FloorMs = ms(c.floor)
	reply.Flagged = c.flagged
	reply.Reason = c.reason
	switch {
	case c.needFetch:
		// No trusted time until NTS answers: say so rather than report one.
		if reply.Reason == "" {
			reply.Reason = ReasonNTSUnreachable
		}
	case c.flagged:
		reply.TrustedTimeMs = ms(c.returnLocked(c.floor))
	default:
		v := h
		if v < c.floor-int64(behindSlack) {
			v = c.floor
		}
		reply.TrustedTimeMs = ms(c.returnLocked(v))
	}
	return reply, nil
}

func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
