// Package apifees implements per-call API fees (x-privasys.price) for
// container apps — the enclave-os-virtual counterpart of the wasm runtime's
// attested per-call meter (enclave-os-mini crates/enclave-os-wasm).
//
// # Where the price comes from
//
// The price rules are read from the app's measured MCP manifest
// (appmanifest), the label the control plane also reads at detect time for
// `package` apps. Enforcement therefore only ever uses a MEASURED price: an
// image change that moves a price moves the attested identity, exactly like
// a wasm price change moving configuration_hash.
// There is deliberately NO platform-supplied fallback: a price the platform
// merely asserts would not be provable through attestation.
//
// # What is enforced
//
// Caller-priced tools only (payer "caller", the default). The manager
// refuses a priced request without the exact X-Billing-Approved consent
// header (mirroring the wasm runtime's byte-exact match), stamps
// X-Billing-Charged on the successful response, and records a fee event in
// a persisted store that the management-service pulls, acknowledges and
// settles through the credit ledger (85/15); an event leaves the store only
// once acknowledged, and a priced call is refused while the store is full. Sponsor-priced tools are NOT supported on the
// container runtime and are skipped at parse time (never mis-priced,
// never half-enforced).
package apifees

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Privasys/enclave-os-virtual/internal/appmanifest"
	"go.uber.org/zap"
)

// maxEvents bounds the UNACKNOWLEDGED fee events. An unacknowledged event is
// never dropped: when this many wait for the puller, new priced calls are
// refused (Full) rather than served unbilled.
const maxEvents = 4096

// PriceRule is a per-tool fee declaration, wire-compatible with the wasm
// runtime's PriceRule (enclave-os-mini protocol.rs).
type PriceRule struct {
	Credits uint64   `json:"credits"`
	Payer   string   `json:"payer,omitempty"`    // "caller" (default) | "sponsor"
	FreeFor []string `json:"free_for,omitempty"` // v1 class: "wallet"
}

// FreeForWallet reports whether the rule exempts wallet-class callers.
func (r PriceRule) FreeForWallet() bool {
	for _, c := range r.FreeFor {
		if c == "wallet" {
			return true
		}
	}
	return false
}

// PricedTool is one enforceable endpoint price: the manifest tool name (for
// fee-event attribution) plus its rule.
type PricedTool struct {
	Tool string
	Rule PriceRule
}

// Table maps an HTTP request path (the tool's manifest `endpoint`) to its
// price. The runtime matches a request on the canonical path (no ;params,
// forward slashes, cleaned, case-folded), like the configure gate, so every
// spelling of an endpoint that reaches the app as that endpoint is priced.
type Table map[string]PricedTool

// ParseManifest builds the price table from the raw org.privasys.manifest
// label value (JSON, or base64-encoded JSON — both label encodings are in
// the wild). Only caller-priced tools with positive credits are
// enforceable; config tools, the configure endpoint, and sponsor-priced
// tools are skipped. A parse error prices nothing: unpriced is always safe,
// mis-priced never is.
func ParseManifest(raw string) (Table, error) {
	doc, err := appmanifest.Decode(raw)
	if err != nil {
		return nil, err
	}

	tbl := make(Table)
	for _, t := range doc.Tools {
		if len(t.XPrivasys.Price) == 0 {
			continue
		}
		var p PriceRule
		if err := json.Unmarshal(t.XPrivasys.Price, &p); err != nil {
			return nil, fmt.Errorf("apifees: tool %q: price: %w", t.Name, err)
		}
		if p.Credits == 0 {
			continue
		}
		if t.Endpoint == "" || t.Role == "config" || t.Endpoint == doc.Configure.Endpoint {
			continue
		}
		if p.Payer != "" && p.Payer != "caller" {
			// Sponsor pricing has no container-runtime enforcement; skipping
			// the rule keeps the tool free rather than half-enforced.
			continue
		}
		if _, dup := tbl[t.Endpoint]; dup {
			// First declaration wins, deterministically.
			continue
		}
		tbl[t.Endpoint] = PricedTool{Tool: t.Name, Rule: p}
	}
	if len(tbl) == 0 {
		return nil, nil
	}
	return tbl, nil
}

// Event is one recorded fee, wire-identical to the wasm runtime's
// ApiFeeEvent so the management-service pull path settles both with the
// same code. seq is the ordering (no timestamps, by design); call_id is
// the ledger idempotency key.
type Event struct {
	Seq       uint64 `json:"seq"`
	App       string `json:"app"`
	Function  string `json:"function"`
	CallID    string `json:"call_id"`
	CallerSub string `json:"caller_sub,omitempty"`
	// PayerLedger is the spend token's ledger handle: how the platform bills
	// the payer without a subject. Named as the management-service reads it.
	PayerLedger string `json:"payer_ledger,omitempty"`
	// PayerApp is the app the caller authorised to spend for them (the
	// spend token's azp), when the call carried one.
	PayerApp string `json:"payer_app,omitempty"`
	Credits  uint64 `json:"credits"`
}

// Store is the persisted fee-event store. Events are appended on each
// successful priced call and stay until the management-service acknowledges
// them; the persisted seq survives a manager restart so the puller's cursor
// stays monotonic. The store is written on each pull, so a crash loses at
// most the events recorded since the last one; the ledger's call_id
// idempotency absorbs re-reads.
type Store struct {
	path string
	log  *zap.Logger

	mu     sync.Mutex
	seq    uint64
	events []Event // unacknowledged events, oldest first
	// acked is the highest seq the puller has acknowledged; events at or
	// below it are trimmed. Only an explicit ?ack= moves it.
	acked uint64
	// epoch names this store's sequence: random when the store is created
	// (or reset after a corrupt file), persisted with seq. An ack counts only
	// for the epoch it names, so an ack from before a reset never trims the
	// events of a new sequence.
	epoch string
}

// persisted is the on-disk shape ({epoch, seq, acked, events}).
type persisted struct {
	Epoch  string  `json:"epoch,omitempty"`
	Seq    uint64  `json:"seq"`
	Acked  uint64  `json:"acked,omitempty"`
	Events []Event `json:"events"`
}

// Epoch is the store's sequence id, returned with every pull.
func (s *Store) Epoch() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

// Open loads (or initialises) a fee store at path. An empty path keeps the
// store memory-only (dev/test). A corrupt file is discarded with a warning
// and a new epoch, so the puller starts the new sequence afresh; keep the
// file on the encrypted /data volume alongside the app registry.
func Open(path string, log *zap.Logger) *Store {
	// A new sequence until a persisted one is loaded.
	s := &Store{path: path, log: log.Named("apifees"), epoch: newCallID()}
	if path == "" {
		return s
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Warn("fee store unreadable; starting empty", zap.String("path", path), zap.Error(err))
		}
		return s
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		s.log.Warn("fee store corrupt; starting empty", zap.String("path", path), zap.Error(err))
		return s
	}
	if p.Epoch != "" {
		s.epoch = p.Epoch
	} // a store written before epochs (v0.40.x and earlier) keeps its seq under a fresh epoch
	s.seq = p.Seq
	s.acked = p.Acked
	s.events = p.Events
	s.trimLocked()
	return s
}

// Full reports that maxEvents events wait for the puller: a priced call must
// then be refused, never served without its fee being kept.
func (s *Store) Full() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events) >= maxEvents
}

// trimLocked drops the acknowledged events.
func (s *Store) trimLocked() {
	i := 0
	for i < len(s.events) && s.events[i].Seq <= s.acked {
		i++
	}
	if i > 0 {
		s.events = append(s.events[:0], s.events[i:]...)
	}
}

// RecordLedger appends one fee event and returns it: payerLedger is the
// spend token's ledger handle, which the platform debits by, and payerApp the
// spender app (its azp, undashed hex) the fee counts against for the payer's
// per-app monthly cap.
func (s *Store) RecordLedger(app, function, callerSub, payerLedger, payerApp string, credits uint64) Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	ev := Event{
		Seq:         s.seq,
		App:         app,
		Function:    function,
		CallID:      newCallID(),
		CallerSub:   callerSub,
		PayerLedger: payerLedger,
		PayerApp:    payerApp,
		Credits:     credits,
	}
	// Never evicted: the caller checked Full before serving the call.
	s.events = append(s.events, ev)
	return ev
}

// Pull returns the unacknowledged events (oldest first) and persists the
// store best-effort. ack, when given with this store's epoch, is the highest
// seq the puller has applied, and only events up to it are trimmed. A pull
// without an ack, or with an ack for another epoch, trims nothing: an event
// leaves the store only once the puller says it applied it.
func (s *Store) Pull(ack *uint64, epoch string) []Event {
	s.mu.Lock()
	if ack != nil && epoch == s.epoch {
		if a := min(*ack, s.seq); a > s.acked {
			s.acked = a
		}
	}
	s.trimLocked()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	p := persisted{Epoch: s.epoch, Seq: s.seq, Acked: s.acked, Events: out}
	path := s.path
	s.mu.Unlock()

	if path != "" {
		if err := save(path, p); err != nil {
			s.log.Warn("fee store persist failed", zap.String("path", path), zap.Error(err))
		}
	}
	return out
}

// save writes the store atomically (tmp+rename, 0600), like the app
// registry it lives next to.
func save(path string, p persisted) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".manager-api-fees.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// newCallID returns a 32-char lowercase-hex random id — the ledger's
// idempotency key for this charge.
func newCallID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails: crypto/rand panics instead
	return hex.EncodeToString(b[:])
}
