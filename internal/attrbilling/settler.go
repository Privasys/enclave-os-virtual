// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package attrbilling reports disclosure-voucher settlement to the
// management-service. When the runtime has served (or failed to serve) an
// attribute disclosure that a relying party paid for, it tells mgmt to settle
// or release the credit reservation the IdP placed at mint time. The runtime
// never touches the ledger directly: mgmt owns that, and authenticates the
// runtime with the same static enclave bearer the fleet check-in uses.
package attrbilling

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Config addresses the mgmt settlement endpoints and carries the enclave
// bearer. Both MgmtBaseURL and EnclaveToken must be set for a live settler.
type Config struct {
	MgmtBaseURL  string
	EnclaveToken string
}

// Settler POSTs settle/release for a voucher jti to the management-service.
type Settler struct {
	base  string
	token string
	http  *http.Client
	log   *zap.Logger
}

// New returns a Settler, or nil when the runtime is not configured to settle
// (dev/test, or a build with no marketplace) so callers can no-op on nil.
func New(cfg Config, log *zap.Logger) *Settler {
	if cfg.MgmtBaseURL == "" || cfg.EnclaveToken == "" {
		return nil
	}
	return &Settler{
		base:  strings.TrimRight(cfg.MgmtBaseURL, "/"),
		token: cfg.EnclaveToken,
		http:  &http.Client{Timeout: 5 * time.Second},
		log:   log.Named("attrbilling"),
	}
}

// Settle charges the relying party for a delivered disclosure (idempotent on
// jti at the ledger).
func (s *Settler) Settle(ctx context.Context, jti string) error {
	return s.post(ctx, jti, "settle")
}

// Release drops the hold for a disclosure that was not delivered (idempotent).
func (s *Settler) Release(ctx context.Context, jti string) error {
	return s.post(ctx, jti, "release")
}

func (s *Settler) post(ctx context.Context, jti, action string) error {
	if s == nil {
		return nil
	}
	url := fmt.Sprintf("%s/api/v1/enclave/attribute-vouchers/%s/%s", s.base, jti, action)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("attrbilling: %s %s: HTTP %d", action, jti, resp.StatusCode)
	}
	return nil
}
