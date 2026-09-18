package manager

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
)

// maxClockBody bounds the clock config and poll bodies.
const maxClockBody = 16 * 1024

// handleClockConfig handles PUT /api/v1/clock/config: the management service
// pins the clock monitor (its Ed25519 key, key id, incident URL and the id it
// knows this enclave by). Manager role only. A config_version lower than the
// current one is refused with 409, so a replayed older config can never swap
// the key back; the current version again is a 200 no-op, because the
// management service re-pushes until a poll reply shows the key id.
func (s *Server) handleClockConfig(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasManagerAccess() {
		s.jsonError(w, http.StatusForbidden, "manager role required for clock configuration")
		return
	}
	if s.cfg.Clock == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "trusted clock not enabled on this runtime")
		return
	}
	var cfg trustedtime.MonitorConfig
	if err := json.NewDecoder(io.LimitReader(r.Body, maxClockBody)).Decode(&cfg); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if err := s.cfg.Clock.SetConfig(cfg); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, trustedtime.ErrStaleConfig) {
			code = http.StatusConflict
		}
		s.jsonError(w, code, err.Error())
		return
	}
	s.log.Info("clock monitor configured",
		zap.String("monitor_key_id", cfg.MonitorKeyID),
		zap.Int64("config_version", cfg.ConfigVersion),
		zap.String("auth_subject", result.Subject))
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"monitor_key_id": cfg.MonitorKeyID,
		"config_version": cfg.ConfigVersion,
	})
}

// handleClockPoll handles POST /api/v1/clock/poll: the clock monitor's signed
// "the time is at least T". No bearer: the Ed25519 signature under the pinned
// monitor key is the authentication, and the reply is authentic through the
// RA-TLS channel it travels on. Reached through the enclave's -mgr hostname,
// which the gateways keep routing while an enclave is quarantined.
//
// 409 when no monitor is pinned yet, 401 for a poll that is not the pinned
// monitor's, 503 when the host and monitor disagree and NTS cannot settle it
// (the runtime then fails closed until NTS answers).
func (s *Server) handleClockPoll(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Clock == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "trusted clock not enabled on this runtime")
		return
	}
	var req trustedtime.PollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxClockBody)).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	reply, err := s.cfg.Clock.Poll(req)
	switch {
	case err == nil:
		s.writeJSON(w, http.StatusOK, reply)
	case errors.Is(err, trustedtime.ErrNotConfigured):
		s.jsonError(w, http.StatusConflict, err.Error())
	case errors.Is(err, trustedtime.ErrBadPoll):
		s.log.Warn("clock poll rejected", zap.String("remote", r.RemoteAddr), zap.Error(err))
		s.jsonError(w, http.StatusUnauthorized, err.Error())
	default:
		s.jsonError(w, http.StatusServiceUnavailable, err.Error())
	}
}
