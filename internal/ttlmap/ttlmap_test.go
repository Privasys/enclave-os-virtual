package ttlmap

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() (time.Time, bool) { return c.t, true }

func newMap(c *clock, max, above int) *Map[string, time.Time] {
	return New[string](Options[time.Time]{
		Max: max, SweepAbove: above, SweepEvery: time.Second,
		Expired: func(until, now time.Time) bool { return now.After(until) },
		Now:     c.now,
	})
}

// Full, a new key is refused and every entry already there stays; a known
// key is always replaced.
func TestAFullMapRefusesTheNewcomer(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	m := newMap(c, 2, 0)
	live := c.t.Add(time.Hour)
	if !m.Put("a", live) || !m.Put("b", live) {
		t.Fatal("room refused")
	}
	if m.Put("c", live) || m.Len() != 2 || !m.Full() {
		t.Fatalf("a full map took a newcomer: len %d", m.Len())
	}
	if !m.Put("a", live.Add(time.Minute)) {
		t.Fatal("a known key was refused")
	}
}

// A sweep runs only above SweepAbove and at most once per SweepEvery, and
// a due one makes room for the newcomer.
func TestSweepIsBoundedAndMakesRoom(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	m := newMap(c, 2, 1)
	m.Put("old", c.t.Add(time.Second))
	m.Put("live", c.t.Add(time.Hour))

	c.t = c.t.Add(2 * time.Second) // "old" has expired
	m.Sweep()                      // due: the first one
	if _, ok := m.Get("old"); ok {
		t.Fatal("an expired entry survived a due sweep")
	}

	m.Put("x", c.t) // expires at once
	c.t = c.t.Add(500 * time.Millisecond)
	if m.Put("y", c.t.Add(time.Hour)) {
		t.Fatal("a sweep ran within SweepEvery of the last one")
	}
	c.t = c.t.Add(time.Second)
	if !m.Put("y", c.t.Add(time.Hour)) {
		t.Fatal("the due sweep did not make room")
	}

	small := newMap(c, 0, 5)
	small.Put("gone", c.t)
	c.t = c.t.Add(time.Hour)
	small.Sweep()
	if small.Len() != 1 {
		t.Fatal("a map at or under SweepAbove was swept")
	}
}

// No trusted time, no sweep.
func TestNoClockNoSweep(t *testing.T) {
	m := New[string](Options[int]{SweepEvery: time.Second, Expired: func(int, time.Time) bool { return true },
		Now: func() (time.Time, bool) { return time.Time{}, false }})
	m.Put("a", 1)
	m.Put("b", 2)
	m.Sweep()
	if m.Len() != 2 {
		t.Fatal("swept without a clock")
	}
}
