package apifees

import (
	"os"
	"path/filepath"
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
	if got := s.Pull(nil, ""); len(got) != maxEvents+1 || got[0].Seq != 1 {
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
	got := s.Pull(&ack, s.Epoch())
	if len(got) != 6 || got[0].Seq != 5 {
		t.Fatalf("after ack 4: %d events, first %d", len(got), got[0].Seq)
	}
	// Once the puller acknowledges explicitly, a pull without ack trims nothing.
	if got := s.Pull(nil, ""); len(got) != 6 {
		t.Fatalf("pull without ack after explicit acks trimmed: %d", len(got))
	}
	big := uint64(999)
	if got := s.Pull(&big, s.Epoch()); len(got) != 0 {
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
	if got := s.Pull(nil, ""); len(got) != 2 {
		t.Fatalf("first pull: %d", len(got))
	}
	s.Record("app", "f", "sub", 1)
	got := s.Pull(nil, "")
	if len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("second pull: %+v", got)
	}
}

// The epoch and seq survive a restart (the store is persisted on /data); an
// ack carrying another epoch, or none, trims nothing.
func TestAckCountsOnlyForItsEpoch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manager-api-fees.json")
	s := Open(path, zap.NewNop())
	for i := 0; i < 5; i++ {
		s.Record("app", "f", "sub", 1)
	}
	epoch := s.Epoch()
	s.Pull(nil, "") // persists
	r := Open(path, zap.NewNop()) // a manager restart
	if r.Epoch() != epoch {
		t.Fatalf("epoch changed across restart: %q -> %q", epoch, r.Epoch())
	}
	r.Record("app", "f", "sub", 1)
	if got := r.Pull(nil, ""); got[len(got)-1].Seq != 6 {
		t.Fatalf("seq did not continue across restart: last %d", got[len(got)-1].Seq)
	}
	ack := uint64(6)
	if got := r.Pull(&ack, "an-old-epoch"); len(got) == 0 {
		t.Fatal("an ack for another epoch trimmed events")
	}
	if got := r.Pull(&ack, ""); len(got) == 0 {
		t.Fatal("an ack without an epoch trimmed events")
	}
	if got := r.Pull(&ack, epoch); len(got) != 0 {
		t.Fatalf("the matching epoch's ack trimmed nothing: %d left", len(got))
	}
	// A reset store (a corrupt file) starts a new epoch.
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fresh := Open(path, zap.NewNop()); fresh.Epoch() == epoch || fresh.Epoch() == "" {
		t.Fatalf("a reset store kept the old epoch %q", fresh.Epoch())
	}
}
