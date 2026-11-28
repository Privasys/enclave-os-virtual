// Package ttlmap is a bounded map whose entries expire. Every table the
// runtime keeps per caller, per connection or per request is one, so each
// states its bound and what happens when it is full: a new key is refused,
// never an entry already there.
//
// A Map is not safe for concurrent use: its owner holds its own lock, which
// usually guards other state too.
package ttlmap

import (
	"iter"
	"time"
)

// Options configure a Map.
type Options[V any] struct {
	// Max is the most entries the map holds. A Put of a new key while it
	// holds Max (after any sweep that is due) stores nothing and returns
	// false. Zero means no cap, for a table its owner bounds another way
	// (and says how).
	Max int
	// A sweep drops expired entries. It runs when the map holds more than
	// SweepAbove entries and the last one is SweepEvery old, on a Put or an
	// explicit Sweep, so a full table is not walked on every call.
	SweepAbove int
	SweepEvery time.Duration
	// Expired reports whether an entry may be dropped at now. Readers that
	// must not see an expired entry check it themselves: a sweep may come
	// up to SweepEvery late.
	Expired func(v V, now time.Time) bool
	// Now is the clock; false skips the sweep (no trusted time, say). Nil
	// is the host clock.
	Now func() (time.Time, bool)
}

// Map is a bounded map with expiring entries.
type Map[K comparable, V any] struct {
	o         Options[V]
	m         map[K]V
	lastSweep time.Time
}

// New returns an empty Map.
func New[K comparable, V any](o Options[V]) *Map[K, V] {
	if o.Now == nil {
		o.Now = func() (time.Time, bool) { return time.Now(), true }
	}
	return &Map[K, V]{o: o, m: map[K]V{}}
}

// Get returns the entry for k, expired or not.
func (m *Map[K, V]) Get(k K) (V, bool) {
	v, ok := m.m[k]
	return v, ok
}

// Put stores v under k. A key already there is always replaced; a new one
// is refused (false) while the map is full.
func (m *Map[K, V]) Put(k K, v V) bool {
	m.Sweep()
	if _, known := m.m[k]; !known && m.o.Max > 0 && len(m.m) >= m.o.Max {
		return false
	}
	m.m[k] = v
	return true
}

// Delete removes k.
func (m *Map[K, V]) Delete(k K) { delete(m.m, k) }

// Len is the number of entries, expired ones included.
func (m *Map[K, V]) Len() int { return len(m.m) }

// Full reports whether a new key would be refused now.
func (m *Map[K, V]) Full() bool { return m.o.Max > 0 && len(m.m) >= m.o.Max }

// All yields every entry; deleting the current one while ranging is safe.
func (m *Map[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for k, v := range m.m {
			if !yield(k, v) {
				return
			}
		}
	}
}

// Sweep drops expired entries when a sweep is due.
func (m *Map[K, V]) Sweep() {
	if len(m.m) <= m.o.SweepAbove || m.o.Expired == nil {
		return
	}
	now, ok := m.o.Now()
	if !ok || now.Sub(m.lastSweep) < m.o.SweepEvery {
		return
	}
	m.lastSweep = now
	for k, v := range m.m {
		if m.o.Expired(v, now) {
			delete(m.m, k)
		}
	}
}
