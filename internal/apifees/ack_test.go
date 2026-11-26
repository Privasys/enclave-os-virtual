package apifees

import (
	"testing"

	"go.uber.org/zap"
)

// An unacknowledged fee event is never dropped: past maxEvents the store is
// Full (the caller refuses priced calls) and every event is still pulled.
func TestUnacknowledgedFeesAreNeverDropped(t *testing.T) {
	s := Open("", zap.NewNop())
	for i := 0; i < maxEvents; i++ {
		s.Record("app", "f", "sub", 1)
	}
	if !s.Full() {
		t.Fatal("not Full at maxEvents unacknowledged events")
	}
	s.Record("app", "f", "sub", 1) // a call already admitted is still recorded
	if got := s.Pull(nil); len(got) != maxEvents+1 || got[0].Seq != 1 {
		t.Fatalf("pull: %d events, first seq %d", len(got), got[0].Seq)
	}
}

// An explicit ack trims exactly what the puller applied.
func TestExplicitAckTrimsOnlyApplied(t *testing.T) {
	s := Open("", zap.NewNop())
	for i := 0; i < 10; i++ {
		s.Record("app", "f", "sub", 1)
	}
	ack := uint64(4)
	got := s.Pull(&ack)
	if len(got) != 6 || got[0].Seq != 5 {
		t.Fatalf("after ack 4: %d events, first %d", len(got), got[0].Seq)
	}
	// Once the puller acknowledges explicitly, a pull without ack trims nothing.
	if got := s.Pull(nil); len(got) != 6 {
		t.Fatalf("pull without ack after explicit acks trimmed: %d", len(got))
	}
	big := uint64(999)
	if got := s.Pull(&big); len(got) != 0 {
		t.Fatalf("ack past seq: %d left", len(got))
	}
}

// A puller that never acknowledges: each pull acknowledges what the previous
// pull returned, so the ring drains at the pull cadence and nothing is lost
// between two pulls.
func TestImplicitAckIsThePreviousPull(t *testing.T) {
	s := Open("", zap.NewNop())
	s.Record("app", "f", "sub", 1)
	s.Record("app", "f", "sub", 1)
	if got := s.Pull(nil); len(got) != 2 {
		t.Fatalf("first pull: %d", len(got))
	}
	s.Record("app", "f", "sub", 1)
	got := s.Pull(nil)
	if len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("second pull: %+v", got)
	}
}
