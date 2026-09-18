// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIssueClockCacheAndFallbacks(t *testing.T) {
	base := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	hostT := base.Add(-time.Hour)
	answer, fail, calls := base, true, 0
	c := &issueClock{
		fetch: func(context.Context) (time.Time, error) {
			calls++
			if fail {
				return time.Time{}, errors.New("manager down")
			}
			return answer, nil
		},
		host: func() time.Time { return hostT },
		log:  func(string, error) {},
	}

	// Manager down and nothing known yet: the host clock, never a failure.
	if got := c.now(); !got.Equal(hostT) {
		t.Fatalf("first read with the manager down: %v", got)
	}
	fail = false
	if got := c.now(); !got.Equal(base) || calls != 2 {
		t.Fatalf("manager answer: %v calls=%d", got, calls)
	}
	// Within a second the cached answer is reused.
	answer = base.Add(time.Hour)
	if got := c.now(); !got.Equal(base) || calls != 2 {
		t.Fatalf("cache not used: %v calls=%d", got, calls)
	}
	// After a second it asks again, and never goes backwards.
	c.fetched = time.Now().Add(-2 * clockCacheFor)
	answer = base.Add(-time.Hour)
	if got := c.now(); !got.Equal(base) || calls != 3 {
		t.Fatalf("went backwards or did not refetch: %v calls=%d", got, calls)
	}
	// Manager unreachable later: the last answer, never a failure.
	c.fetched = time.Now().Add(-2 * clockCacheFor)
	fail = true
	if got := c.now(); !got.Equal(base) {
		t.Fatalf("want the last answer, got %v", got)
	}
}

func TestLeafValidityFollowsIssueTime(t *testing.T) {
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	lk := leafKeyFor("clock-test.example", now)
	if !lk.created.Equal(now) {
		t.Fatalf("key created at %v, want %v", lk.created, now)
	}
	// Past its lifetime, the key rotates.
	if next := leafKeyFor("clock-test.example", now.Add(leafLifetime+time.Minute)); next == lk {
		t.Fatal("key not rotated after its lifetime")
	}
}
