// Copyright (c) Privasys. All rights reserved.

package manager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// toolSpecMaxBody caps what we relay from the management service. The tool
// spec is a small JSON document; anything larger is a bug or a hostile
// upstream, and we would rather truncate than hand a container an unbounded
// body.
const toolSpecMaxBody = 1 << 20 // 1 MiB

// toolSpecTimeout bounds the upstream call so a slow management service cannot
// pin manager goroutines on behalf of a polling container.
const toolSpecTimeout = 10 * time.Second

// handleToolSpec relays the fleet tool spec to the calling container.
//
// The tool spec lives on the management service behind the enclave bearer.
// That bearer is the fleet-wide machine credential: the same token also
// authenticates check-in, runtime status, AI usage, per-call API fees and
// attribute-voucher settle/release, and it fetches the attestation token used
// to unseal vault keys. It used to be injected into every container's
// environment as TOOL_SPEC_TOKEN, and a container can read its own
// environment, so every workload on a host held the credential that gates
// every other workload's management endpoints. On a shared VM that was a
// cross-tenant capability.
//
// The container now authenticates to the manager with its own per-container
// token (requireContainerSelf, bound to {name}) and the manager makes the
// upstream call. The fleet credential never leaves the manager.
//
// The container-facing contract is unchanged: the workload still reads
// TOOL_SPEC_URL and TOOL_SPEC_TOKEN and still performs one authenticated GET
// returning the same body. Only the address and the token differ, so no app
// image needs rebuilding.
func (s *Server) handleToolSpec(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if s.cfg.MgmtBaseURL == "" || s.cfg.EnclaveID == "" || s.cfg.EnclaveToken == "" {
		// Same shape as the old behaviour when the launcher had nothing to
		// inject: the puller simply finds nothing to poll.
		s.jsonError(w, http.StatusServiceUnavailable, "tool spec is not configured on this enclave")
		return
	}

	upstream := fmt.Sprintf("%s/api/v1/enclave/tool-spec?enclave_id=%s",
		strings.TrimRight(s.cfg.MgmtBaseURL, "/"),
		url.QueryEscape(s.cfg.EnclaveID))

	ctx, cancel := context.WithTimeout(r.Context(), toolSpecTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream, nil)
	if err != nil {
		s.log.Warn("tool spec: build upstream request", zap.String("container", name), zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, "tool spec request could not be built")
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.EnclaveToken)

	resp, err := (&http.Client{Timeout: toolSpecTimeout}).Do(req)
	if err != nil {
		s.log.Warn("tool spec: upstream call failed", zap.String("container", name), zap.Error(err))
		s.jsonError(w, http.StatusBadGateway, "tool spec upstream is unreachable")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, toolSpecMaxBody))
	if err != nil {
		s.log.Warn("tool spec: read upstream body", zap.String("container", name), zap.Error(err))
		s.jsonError(w, http.StatusBadGateway, "tool spec upstream response could not be read")
		return
	}

	// Relay the upstream status so the puller's own retry logic still sees
	// what it used to see. Deliberately do NOT relay upstream headers: they
	// are the manager's conversation with the management service, not the
	// container's.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(body); err != nil {
		s.log.Debug("tool spec: write to container failed",
			zap.String("container", name), zap.Error(err))
	}
}
