package apifees

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

const sampleManifest = `{
  "tools": [
    {"name": "browse", "role": "action", "endpoint": "/browse",
     "x-privasys": {"price": {"credits": 5000, "payer": "caller", "free_for": ["wallet"]}}},
    {"name": "free-tool", "role": "action", "endpoint": "/free"},
    {"name": "zero-priced", "role": "action", "endpoint": "/zero",
     "x-privasys": {"price": {"credits": 0}}},
    {"name": "sponsored", "role": "action", "endpoint": "/sponsored",
     "x-privasys": {"price": {"credits": 100, "payer": "sponsor"}}},
    {"name": "set-key", "role": "config", "endpoint": "/configure",
     "x-privasys": {"price": {"credits": 999}}}
  ],
  "configure": {"endpoint": "/configure"}
}`

func TestParseManifest(t *testing.T) {
	tbl, err := ParseManifest(sampleManifest)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(tbl) != 1 {
		t.Fatalf("expected exactly one enforceable price, got %d: %#v", len(tbl), tbl)
	}
	pt, ok := tbl["/browse"]
	if !ok {
		t.Fatalf("missing /browse entry: %#v", tbl)
	}
	if pt.Tool != "browse" || pt.Rule.Credits != 5000 {
		t.Fatalf("unexpected entry: %#v", pt)
	}
	if !pt.Rule.FreeForWallet() {
		t.Fatal("expected wallet exemption")
	}
}

func TestParseManifestBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(sampleManifest))
	tbl, err := ParseManifest(enc)
	if err != nil {
		t.Fatalf("ParseManifest(base64): %v", err)
	}
	if _, ok := tbl["/browse"]; !ok {
		t.Fatalf("missing /browse entry: %#v", tbl)
	}
}

func TestParseManifestGarbage(t *testing.T) {
	if _, err := ParseManifest("not json at all"); err == nil {
		t.Fatal("expected an error for a garbage label")
	}
	// No priced tools → nil table, no error.
	tbl, err := ParseManifest(`{"tools":[{"name":"a","endpoint":"/a"}]}`)
	if err != nil || tbl != nil {
		t.Fatalf("expected empty table, got %#v, %v", tbl, err)
	}
}

func TestParseManifestDefaultPayerIsCaller(t *testing.T) {
	tbl, err := ParseManifest(`{"tools":[{"name":"t","endpoint":"/t","x-privasys":{"price":{"credits":42}}}]}`)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if pt, ok := tbl["/t"]; !ok || pt.Rule.Credits != 42 {
		t.Fatalf("expected default-payer price enforced: %#v", tbl)
	}
}

func TestStoreRecordAndRing(t *testing.T) {
	s := Open("", zap.NewNop())
	ev := s.Record("app", "browse", "sub-1", 5000)
	if ev.Seq != 1 || ev.App != "app" || ev.Function != "browse" || ev.CallerSub != "sub-1" || ev.Credits != 5000 {
		t.Fatalf("unexpected event: %#v", ev)
	}
	if len(ev.CallID) != 32 {
		t.Fatalf("call_id should be 32 hex chars, got %q", ev.CallID)
	}
	ev2 := s.Record("app", "browse", "", 5000)
	if ev2.Seq != 2 || ev2.CallID == ev.CallID {
		t.Fatalf("seq/call_id not advancing: %#v vs %#v", ev, ev2)
	}
	snap := s.Snapshot()
	if len(snap) != 2 || snap[0].Seq != 1 || snap[1].Seq != 2 {
		t.Fatalf("unexpected snapshot: %#v", snap)
	}
}

func TestStoreRingBound(t *testing.T) {
	s := Open("", zap.NewNop())
	for i := 0; i < maxEvents+10; i++ {
		s.Record("app", "f", "", 1)
	}
	snap := s.Snapshot()
	if len(snap) != maxEvents {
		t.Fatalf("ring not bounded: %d", len(snap))
	}
	if snap[0].Seq != 11 || snap[len(snap)-1].Seq != maxEvents+10 {
		t.Fatalf("oldest events not aged out: first seq %d, last %d", snap[0].Seq, snap[len(snap)-1].Seq)
	}
}

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manager-api-fees.json")

	s := Open(path, zap.NewNop())
	s.Record("app", "f", "sub", 100)
	s.Snapshot() // persists

	// Reopen: seq continues past the persisted value, so a puller cursor
	// from a pre-restart snapshot never skips fresh events.
	s2 := Open(path, zap.NewNop())
	ev := s2.Record("app", "f", "sub", 100)
	if ev.Seq != 2 {
		t.Fatalf("seq did not survive restart: %d", ev.Seq)
	}
	snap := s2.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("events did not survive restart: %#v", snap)
	}
}

func TestEventWireShape(t *testing.T) {
	// The management-service pull path decodes {seq, app, function,
	// call_id, caller_sub, credits} — the wasm ApiFeeEvent shape.
	ev := Event{Seq: 7, App: "a", Function: "f", CallID: "abc", CallerSub: "s", Credits: 12}
	data, _ := json.Marshal(ev)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	for _, k := range []string{"seq", "app", "function", "call_id", "caller_sub", "credits"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing wire field %q in %s", k, data)
		}
	}
	// An anonymous event omits caller_sub rather than sending null.
	data, _ = json.Marshal(Event{Seq: 1})
	var m2 map[string]any
	_ = json.Unmarshal(data, &m2)
	if v, present := m2["caller_sub"]; present && v == nil {
		t.Fatal("caller_sub must be omitted, not null")
	}
}
