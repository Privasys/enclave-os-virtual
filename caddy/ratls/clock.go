// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Issuing time for the module. Leaf validity and quote times should not come
// from the host clock (a host that rolls it back could keep an expired leaf or
// a stale quote in service), and Caddy runs as its own process, so the module
// asks the measured manager, which keeps the trusted clock, over a root-only
// Unix socket in the manager's runtime directory that nothing Caddy proxies
// can reach.
//
// Issuing is not a verification decision: whoever checks a certificate or a
// quote judges its dates against their own clock. So the module never refuses
// a handshake or evidence over time. When the manager has no trusted time it
// answers the floor (the latest time it can vouch for); when the manager
// cannot be reached at all the module reuses its last answer, and before any
// answer the host clock. Blocking instead would make the enclave unreachable,
// including the manager API and the clock poll that lets it recover.
const (
	// clockSocket must match trustedtime.DefaultLocalSocket in the manager
	// (a separate module, not a Go dependency of this one).
	clockSocket = "/run/manager/clock.sock"
	// clockCacheFor bounds how long one answer is reused.
	clockCacheFor = time.Second
	// clockTimeout bounds one request. The manager answers without touching
	// the network, so this only matters when it is down or wedged.
	clockTimeout = 2 * time.Second
)

// issueClock is a 1-second cache in front of the manager's issuing time.
// Fetches are serialised, so a burst of handshakes costs one request.
type issueClock struct {
	fetch func(ctx context.Context) (time.Time, error)
	host  func() time.Time
	log   func(msg string, err error)

	mu      sync.Mutex
	value   time.Time
	fetched time.Time // monotonic
}

var clock = &issueClock{
	fetch: fetchManagerTime,
	host:  time.Now,
	log: func(msg string, err error) {
		if g := current.Load(); g != nil && g.logger != nil {
			g.logger.Warn(msg, zap.Error(err))
		}
	},
}

// now returns the issuing time, from the cache when it is under a second old.
// It never fails and never returns less than a previous answer.
func (c *issueClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fetched.IsZero() && time.Since(c.fetched) < clockCacheFor {
		return c.value
	}
	ctx, cancel := context.WithTimeout(context.Background(), clockTimeout)
	defer cancel()
	t, err := c.fetch(ctx)
	if err != nil {
		if c.value.IsZero() {
			c.log("manager clock unreachable and no earlier answer; issuing with the host clock", err)
			return c.host().UTC()
		}
		c.log("manager clock unreachable; issuing with its last answer", err)
		return c.value
	}
	if t.Before(c.value) {
		t = c.value
	}
	c.value, c.fetched = t, time.Now()
	return t
}

// issueTime is what the module stamps on leaves and quotes.
func issueTime() time.Time { return clock.now() }

var clockHTTP = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", clockSocket)
		},
		MaxIdleConns:    1,
		IdleConnTimeout: 30 * time.Second,
	},
}

// fetchManagerTime asks the manager for the issuing time.
func fetchManagerTime(ctx context.Context) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://manager/now", nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := clockHTTP.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	var body struct {
		UnixMs  int64 `json:"unix_ms"`
		Trusted bool  `json:"trusted"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body); err != nil {
		return time.Time{}, fmt.Errorf("unreadable answer (%d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("manager answered %d", resp.StatusCode)
	}
	if body.UnixMs <= 0 {
		return time.Time{}, errors.New("manager answered no time")
	}
	return time.UnixMilli(body.UnixMs).UTC(), nil
}
