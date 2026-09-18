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
)

// Trusted time for the module. Leaf validity and quote timestamps must not
// come from the host clock (a host that rolls it back could get an expired
// certificate or a stale quote accepted), and Caddy runs as its own process,
// so it asks the measured manager, which keeps the trusted clock. The manager
// serves it on a root-only Unix socket in its runtime directory: nothing
// Caddy proxies can reach it.
const (
	// clockSocket must match trustedtime.DefaultLocalSocket in the manager
	// (a separate module, not a Go dependency of this one).
	clockSocket = "/run/manager/clock.sock"
	// clockCacheFor bounds how long one answer is reused.
	clockCacheFor = time.Second
	// clockTimeout bounds one request. The manager answers at once unless its
	// clock is mid NTS fetch; a handshake then waits rather than proceeding on
	// an unchecked time.
	clockTimeout = 10 * time.Second
)

// errNoTrustedTime is returned when the manager cannot vouch for the time;
// callers fail closed (no certificate, no evidence).
var errNoTrustedTime = errors.New("ra_tls: no trusted time")

// trustedClock is a 1-second cache in front of the manager's clock. Fetches
// are serialised, so a burst of handshakes costs one request.
type trustedClock struct {
	fetch func(ctx context.Context) (time.Time, error)

	mu      sync.Mutex
	value   time.Time
	fetched time.Time // monotonic
}

var clock = &trustedClock{fetch: fetchManagerTime}

// now returns the trusted time, from the cache when it is under a second old.
// It never returns less than a previous answer.
func (c *trustedClock) now() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fetched.IsZero() && time.Since(c.fetched) < clockCacheFor {
		return c.value, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), clockTimeout)
	defer cancel()
	t, err := c.fetch(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", errNoTrustedTime, err)
	}
	if t.Before(c.value) {
		t = c.value
	}
	c.value, c.fetched = t, time.Now()
	return t, nil
}

// trustedNow is what the module's time-sensitive paths call.
func trustedNow() (time.Time, error) { return clock.now() }

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

// fetchManagerTime asks the manager for the trusted time.
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
		UnixMs int64  `json:"unix_ms"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body); err != nil {
		return time.Time{}, fmt.Errorf("unreadable answer (%d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("manager answered %d: %s", resp.StatusCode, body.Error)
	}
	if body.UnixMs <= 0 {
		return time.Time{}, errors.New("manager answered no time")
	}
	return time.UnixMilli(body.UnixMs).UTC(), nil
}
