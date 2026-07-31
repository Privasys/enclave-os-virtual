// Package apifees implements per-call API fees (x-privasys.price) for
// container apps — the enclave-os-virtual counterpart of the wasm runtime's
// attested per-call meter (enclave-os-mini crates/enclave-os-wasm).
//
// # Where the price comes from
//
// The price rules are read from the app's MCP manifest carried in the OCI
// image label "org.privasys.manifest" — the same manifest the control plane
// reads at detect time for `package` apps. The label lives in the image
// config blob, so it is covered by the digest-pinned image digest that the
// launcher verifies and attests (Config Merkle Tree leaf
// container.image_digest, OID 3.2). Enforcement therefore only ever uses a
// MEASURED price: an image change that moves a price moves the attested
// identity, exactly like a wasm price change moving configuration_hash.
// There is deliberately NO platform-supplied fallback — a price the platform
// merely asserts would not be provable through attestation.
//
// # What is enforced
//
// Caller-priced tools only (payer "caller", the default). The manager
// refuses a priced request without the exact X-Billing-Approved consent
// header (mirroring the wasm runtime's byte-exact match), stamps
// X-Billing-Charged on the successful response, and records a fee event in
// a bounded ring that the management-service pulls and settles through the
// credit ledger (85/15). Sponsor-priced tools are NOT supported on the
// container runtime and are skipped at parse time (never mis-priced,
// never half-enforced).
package apifees

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ManifestLabel is the OCI image label carrying the app's MCP manifest —
// the same label the management-service reads at detect time, so the
// advertised and the enforced price sets share one measured source.
const ManifestLabel = "org.privasys.manifest"

// maxEvents bounds the fee-event ring. At the 60s pull cadence this allows
// ~68 priced calls/second sustained before an unpulled event ages out —
// the same bound as the wasm runtime's ring.
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
// price. Paths are matched literally, like the configure gate.
type Table map[string]PricedTool

// manifest mirrors just the fields of the MCP manifest that pricing needs.
type manifestDoc struct {
	Tools []struct {
		Name      string `json:"name"`
		Role      string `json:"role"`
		Endpoint  string `json:"endpoint"`
		XPrivasys struct {
			Price *PriceRule `json:"price"`
		} `json:"x-privasys"`
	} `json:"tools"`
	Configure struct {
		Endpoint string `json:"endpoint"`
	} `json:"configure"`
}

// ParseManifest builds the price table from the raw org.privasys.manifest
// label value (JSON, or base64-encoded JSON — both label encodings are in
// the wild). Only caller-priced tools with positive credits are
// enforceable; config tools, the configure endpoint, and sponsor-priced
// tools are skipped. A parse error prices nothing: unpriced is always safe,
// mis-priced never is.
func ParseManifest(raw string) (Table, error) {
	data := []byte(raw)
	var doc manifestDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		decoded, derr := base64.StdEncoding.DecodeString(raw)
		if derr != nil {
			return nil, fmt.Errorf("apifees: manifest label is neither JSON nor base64 JSON: %w", err)
		}
		if err := json.Unmarshal(decoded, &doc); err != nil {
			return nil, fmt.Errorf("apifees: manifest label parse: %w", err)
		}
	}

	tbl := make(Table)
	for _, t := range doc.Tools {
		p := t.XPrivasys.Price
		if p == nil || p.Credits == 0 {
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
		tbl[t.Endpoint] = PricedTool{Tool: t.Name, Rule: *p}
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
	Credits   uint64 `json:"credits"`
}

// Store is the bounded, persisted fee-event ring. Events are appended on
// each successful priced call and pulled (never drained) by the
// management-service; the persisted seq survives a manager restart so the
// puller's cursor stays monotonic. Persistence is best-effort and happens
// on Snapshot (the pull), mirroring the wasm runtime's save-on-read: a
// crash loses at most one pull interval of fees — lossy by design, and the
// ledger's call_id idempotency absorbs re-reads.
type Store struct {
	path string
	log  *zap.Logger

	mu     sync.Mutex
	seq    uint64
	events []Event
}

// persisted is the on-disk shape ({seq, events}).
type persisted struct {
	Seq    uint64  `json:"seq"`
	Events []Event `json:"events"`
}

// Open loads (or initialises) a fee store at path. An empty path keeps the
// store memory-only (dev/test). A corrupt file is discarded with a warning
// — fees are lossy by design, but the seq restarts at 0 then, so the
// management-service's in-memory cursor (rebuilt on ITS restart) may skip
// events until seq catches up; keep the file on the encrypted /data volume
// alongside the app registry.
func Open(path string, log *zap.Logger) *Store {
	s := &Store{path: path, log: log.Named("apifees")}
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
	s.seq = p.Seq
	s.events = p.Events
	return s
}

// Record appends one fee event and returns it.
func (s *Store) Record(app, function, callerSub string, credits uint64) Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	ev := Event{
		Seq:       s.seq,
		App:       app,
		Function:  function,
		CallID:    newCallID(),
		CallerSub: callerSub,
		Credits:   credits,
	}
	s.events = append(s.events, ev)
	if n := len(s.events) - maxEvents; n > 0 {
		s.events = append(s.events[:0], s.events[n:]...)
	}
	return ev
}

// Snapshot returns a copy of the ring (oldest first) and persists the store
// best-effort. Events are never drained here — the puller advances its own
// seq cursor and the ring ages out naturally.
func (s *Store) Snapshot() []Event {
	s.mu.Lock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	p := persisted{Seq: s.seq, Events: out}
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
// idempotency key for this charge. On an RNG failure the id is salted with
// the current time rather than colliding on a constant.
func newCallID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		now := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			b[i] = byte(now >> (8 * i))
		}
	}
	return hex.EncodeToString(b[:])
}
