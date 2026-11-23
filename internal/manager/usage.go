package manager

// Usage relay. An app billed by consumption (today an inference app's token
// counts) reports its usage to the control plane and asks it whether a caller
// can be charged. The manager makes both calls with the enclave's own
// attested credential and names the app from the load envelope, so the app
// holds no platform credential and cannot choose whom it bills. What a usage
// line means is the control plane's business; the manager relays it as is.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	usageTimeout = 15 * time.Second
	// usageMaxBody bounds a usage batch, as the control plane does.
	usageMaxBody = 1 << 20
	// appIDHeader names the app a relayed call is for. The manager sets it
	// from the load envelope; a value the app sent is never forwarded.
	appIDHeader = "X-Privasys-App-Id"
)

// handleUsage serves POST /api/v1/containers/{name}/usage (container
// token, self only): the app's usage batch, forwarded to the control plane.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, usageMaxBody))
	if err != nil {
		s.jsonError(w, http.StatusRequestEntityTooLarge, "usage batch too large")
		return
	}
	s.relayUsage(w, r, http.MethodPost, "/api/v1/enclave/usage", body)
}

// handleBillableCaller serves GET /api/v1/containers/{name}/billable-caller
// (container token, self only): the billability check, query passed through.
func (s *Server) handleBillableCaller(w http.ResponseWriter, r *http.Request) {
	path := "/api/v1/enclave/billable-caller"
	if q := r.URL.RawQuery; q != "" {
		path += "?" + q
	}
	s.relayUsage(w, r, http.MethodGet, path, nil)
}

func (s *Server) relayUsage(w http.ResponseWriter, r *http.Request, method, path string, body []byte) {
	name := r.PathValue("name")
	if s.cfg.MgmtBaseURL == "" || s.cfg.EnclaveToken == "" {
		s.jsonError(w, http.StatusServiceUnavailable, "usage reporting is not configured on this enclave")
		return
	}
	s.relayUsageFor(w, r, name, s.launcher.ContainerFreezeState(name).AppID, method, path, body)
}

// relayUsageFor makes the upstream call for the named container's app.
func (s *Server) relayUsageFor(w http.ResponseWriter, r *http.Request, name, appID, method, path string, body []byte) {
	if appID == "" {
		s.jsonError(w, http.StatusForbidden, "this container was loaded without an app id, so its usage cannot be attributed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), usageTimeout)
	defer cancel()
	upstream := strings.TrimRight(s.cfg.MgmtBaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, upstream, bytes.NewReader(body))
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "usage request could not be built")
		return
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(appIDHeader, appID)
	req.Header.Set("Authorization", "Bearer "+s.cfg.EnclaveToken)
	if s.cfg.EnclaveSigner != nil {
		if err := s.cfg.EnclaveSigner.Sign(req, body); err != nil {
			s.log.Warn("usage: attested auth unavailable, sending credential only", zap.Error(err))
		}
	}
	resp, err := (&http.Client{Timeout: usageTimeout}).Do(req)
	if err != nil {
		s.log.Warn("usage: upstream call failed", zap.String("container", name), zap.String("path", path), zap.Error(err))
		s.jsonError(w, http.StatusBadGateway, "usage upstream is unreachable")
		return
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, usageMaxBody))
	if err != nil {
		s.jsonError(w, http.StatusBadGateway, fmt.Sprintf("usage upstream response could not be read: %v", err))
		return
	}
	// The status and body are the app's answer (the freeze verdict, the
	// billability verdict). The upstream headers are the manager's
	// conversation with the control plane, not the app's.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}
