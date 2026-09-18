// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTrustedClockCacheAndFailClosed(t *testing.T) {
	base := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	answer, fail, calls := base, false, 0
	c := &trustedClock{fetch: func(context.Context) (time.Time, error) {
		calls++
		if fail {
			return time.Time{}, errors.New("manager down")
		}
		return answer, nil
	}}

	got, err := c.now()
	if err != nil || !got.Equal(base) || calls != 1 {
		t.Fatalf("first read: %v %v calls=%d", got, err, calls)
	}
	// Within a second the cached answer is reused.
	answer = base.Add(time.Hour)
	if got, _ := c.now(); !got.Equal(base) || calls != 1 {
		t.Fatalf("cache not used: %v calls=%d", got, calls)
	}
	// After a second it asks again, and never goes backwards.
	c.fetched = time.Now().Add(-2 * clockCacheFor)
	answer = base.Add(-time.Hour)
	if got, _ := c.now(); !got.Equal(base) || calls != 2 {
		t.Fatalf("went backwards or did not refetch: %v calls=%d", got, calls)
	}
	// An unreachable manager fails closed, even with a stale value cached.
	c.fetched = time.Now().Add(-2 * clockCacheFor)
	fail = true
	if _, err := c.now(); !errors.Is(err, errNoTrustedTime) {
		t.Fatalf("want fail closed, got %v", err)
	}
}

func TestLeafValidityFollowsTrustedTime(t *testing.T) {
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	lk := leafKeyFor("clock-test.example", now)
	if !lk.created.Equal(now) {
		t.Fatalf("key created at %v, want the trusted %v", lk.created, now)
	}
	// Past its lifetime in trusted time, the key rotates.
	if next := leafKeyFor("clock-test.example", now.Add(leafLifetime+time.Minute)); next == lk {
		t.Fatal("key not rotated after its lifetime in trusted time")
	}
}
