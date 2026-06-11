// Package sessionrelay provides a middleware that lets browser-based SDKs
// reach this enclave through the gateway's terminate-mode path while
// preserving end-to-end confidentiality.
//
// The gateway terminates the public Let's Encrypt TLS leg and reverse-proxies
// plain HTTP into the enclave. This middleware then handles two flows:
//
//  1. Session init: POST /privasys/session/init carrying the SDK's ephemeral
//     P-256 public key. The enclave generates its own ephemeral P-256 key,
//     derives a 256-bit AES-GCM key via HKDF-SHA256 (salt = session_id,
//     info = "privasys-session/v1"), stores the session, and returns
//     {session_id, enc_pub, expires_at}.
//
//  2. Sealed traffic: any other request whose Content-Type is
//     application/privasys-sealed+cbor and which carries
//     Authorization: PrivasysSession <session_id>. The middleware looks up
//     the session, decrypts the body with AAD = method:path:session_id and
//     a deterministic nonce, calls the wrapped handler with the decrypted
//     body, then encrypts the response with the s2c counter.
//
// Sessions are kept in memory; suitable for stateless enclave apps because
// all session state is short-lived (~1h) and reconstructable by the SDK.
package sessionrelay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sealedContentType       = "application/privasys-sealed+cbor"
	sealedStreamContentType = "application/privasys-sealed-stream+cbor"
	authScheme              = "PrivasysSession"
	hkdfInfo                = "privasys-session/v1"
	dirInfoC2S              = "privasys-dir/c2s"
	dirInfoS2C              = "privasys-dir/s2c"
	// defaultTTL is a sliding inactivity window: every successfully
	// authenticated sealed request extends the session by this much.
	// Aligned with the IdP's 15-minute access-token cadence; idle
	// sessions are GC'd and silently re-bootstrapped via EncAuth.
	defaultTTL              = 15 * time.Minute
	initPath                = "/__privasys/session-bootstrap"

	// EncAuth rebind rate limit: at most rebindRateLimit voucher-backed
	// bootstrap attempts (accepted or rejected) per sid per window. A
	// misbehaving iframe re-bootstrapping in a tight loop burns CPU on
	// signature checks and could churn legitimate sessions; legitimate
	// silent rebinds happen at most a few times per hour.
	rebindRateLimit  = 6
	rebindRateWindow = time.Minute
)

// Manager owns active sessions. Safe for concurrent use.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
	now      func() time.Time

	// Long-lived enclave identity key. Used for ECDH on every
	// bootstrap. Stable across SDK sessions for the lifetime of the
	// enclave process so wallet-issued EncAuth vouchers can pin enc_pub.
	encStaticPriv *ecdh.PrivateKey
	encStaticPub  []byte // SEC1 uncompressed (65 B)

	// Optional EncAuth verifier. When non-nil, handleInit accepts an
	// `encauth` field in the request body and uses it to short-circuit
	// the FIDO2 ceremony (silent rebind). Returns the canonical
	// payload on success, or an error to fall through to FIDO2.
	encAuthVerifier EncAuthVerifier

	// Optional expected quote digest used to bind EncAuth vouchers to
	// this enclave's attestation. This is the WALLET attestation digest
	// (crypto-contract §4.1: SHA-256 over the canonical attestation
	// field list) — NOT a hash of the RA-TLS leaf certificate. Set by
	// the host via SetExpectedQuoteDigest, computed over the host's own
	// attestation OID values. When zero, the voucher's quote_hash field
	// is not enforced and instance pinning rests on enc_pub equality
	// (sound: the identity key is regenerated on every restart).
	expectedQuoteDigest    [32]byte
	hasExpectedQuoteDigest bool

	// Fixed-window EncAuth rebind counters keyed by voucher sid.
	rebinds map[string]*rebindWindow

	// Optional predicate: when it returns true for a non-sealed request,
	// the middleware refuses it with 403 sealed-transport-required
	// instead of passing it through. Used to enforce "no plaintext app
	// bodies on an intermediary-terminated leg" (the gateway marks that
	// leg with X-Privasys-Edge: terminate). Set via SetRequireSealed.
	requireSealed func(*http.Request) bool
}

type rebindWindow struct {
	start time.Time
	count int
}

// Session holds derived keys and counters for a single SDK ↔ enclave pairing.
type Session struct {
	ID          string
	Aead        cipher.AEAD
	C2SPrefix   [4]byte
	S2CPrefix   [4]byte
	S2CCtr      uint64
	C2SNext     uint64 // smallest acceptable c2s ctr; rejects replay incl. the last frame
	ExpiresAt   time.Time
}

// NewManager creates a session manager. The enclave identity key is
// generated lazily on the first bootstrap (or via
// EnsureEncStaticKey() at startup) so existing tests that don't drive
// the bootstrap path keep working without ECDH setup.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		rebinds:  make(map[string]*rebindWindow),
		ttl:      defaultTTL,
		now:      time.Now,
	}
}

// EnsureEncStaticKey generates the long-lived enclave identity key if
// it hasn't been created yet. Safe to call multiple times.
func (m *Manager) EnsureEncStaticKey() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureEncStaticKeyLocked()
}

func (m *Manager) ensureEncStaticKeyLocked() error {
	if m.encStaticPriv != nil {
		return nil
	}
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ecdh keygen: %w", err)
	}
	m.encStaticPriv = k
	m.encStaticPub = k.PublicKey().Bytes()
	return nil
}

// EncStaticPub returns the SEC1 uncompressed bytes of the enclave's
// long-lived identity key. The wallet binds these into EncAuth
// vouchers so silent rebinds across sessions can pin the same key.
func (m *Manager) EncStaticPub() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.encStaticPub...)
}

// SetEncAuthVerifier installs an EncAuth verifier. Pass nil to
// disable EncAuth (the enclave then always falls back to FIDO2).
func (m *Manager) SetEncAuthVerifier(v EncAuthVerifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.encAuthVerifier = v
}

// SetExpectedQuoteDigest arms the optional voucher quote_hash check.
// The digest MUST be the wallet attestation digest from
// crypto-contract §4.1 — SHA-256 over the canonical attestation field
// list, computed by the host from its own attestation OID values. It
// is NOT a hash of the RA-TLS leaf certificate; arming this with a
// leaf hash would reject every legitimate voucher.
func (m *Manager) SetExpectedQuoteDigest(h [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expectedQuoteDigest = h
	m.hasExpectedQuoteDigest = true
}

// SetTTL overrides the default session lifetime.
func (m *Manager) SetTTL(d time.Duration) { m.ttl = d }

// SetRequireSealed installs the predicate deciding which non-sealed
// requests must be refused (403) rather than passed through. The
// session-bootstrap endpoint is always exempt (it is JSON by design —
// silent rebind posts it from the browser through the gateway).
func (m *Manager) SetRequireSealed(f func(*http.Request) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requireSealed = f
}

// Middleware wraps next so that:
//   - POST /privasys/session/init handles handshake itself and never reaches next.
//   - sealed requests are decrypted before being passed to next, and the
//     response is re-encrypted before being written to the client.
//   - all other requests pass through unchanged (so the enclave's existing
//     splice-mode RA-TLS clients keep working).
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == initPath && r.Method == http.MethodPost {
			m.handleInit(w, r)
			return
		}
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, sealedContentType) {
			m.mu.RLock()
			requireSealed := m.requireSealed
			m.mu.RUnlock()
			if requireSealed != nil && requireSealed(r) {
				// Intermediary-terminated leg (gateway sets
				// X-Privasys-Edge: terminate) carrying a plaintext app
				// request. Refusing it keeps the "the gateway can never
				// see app data" invariant enforceable server-side; the
				// SDK reacts by (re)establishing a sealed session.
				// RA-TLS clients never hit this: their TLS terminates at
				// the enclave itself and carries no marker.
				http.Error(w, "sealed-transport-required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		m.handleSealed(w, r, next)
	})
}

// initRequest is the body the SDK sends to /privasys/session/init.
type initRequest struct {
	SDKPub  string           `json:"sdk_pub"`           // base64url, SEC1 uncompressed P-256
	EncAuth *EncAuthEnvelope `json:"encauth,omitempty"` // optional silent-rebind voucher
}

// initResponse is what the enclave returns.
type initResponse struct {
	SessionID string `json:"session_id"`
	EncPub    string `json:"enc_pub"`
	ExpiresAt int64  `json:"expires_at"` // epoch seconds (crypto-contract §3)
	// Subject identifier when the session was bootstrapped from an
	// EncAuth voucher (silent rebind). Empty for FIDO2-bootstrapped
	// sessions.
	Sub string `json:"sub,omitempty"`
}

func (m *Manager) handleInit(w http.ResponseWriter, r *http.Request) {
	var req initRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid init body", http.StatusBadRequest)
		return
	}
	sdkPubRaw, err := base64.RawURLEncoding.DecodeString(req.SDKPub)
	if err != nil || len(sdkPubRaw) != 65 || sdkPubRaw[0] != 0x04 {
		http.Error(w, "invalid sdk_pub", http.StatusBadRequest)
		return
	}

	curve := ecdh.P256()
	sdkPub, err := curve.NewPublicKey(sdkPubRaw)
	if err != nil {
		http.Error(w, "invalid sdk_pub: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := m.EnsureEncStaticKey(); err != nil {
		http.Error(w, "ecdh keygen: "+err.Error(), http.StatusInternalServerError)
		return
	}
	m.mu.RLock()
	encPriv := m.encStaticPriv
	encPubBytes := m.encStaticPub
	verifier := m.encAuthVerifier
	hasQuoteDigest := m.hasExpectedQuoteDigest
	quoteDigest := m.expectedQuoteDigest
	m.mu.RUnlock()

	shared, err := encPriv.ECDH(sdkPub)
	if err != nil {
		http.Error(w, "ecdh derive", http.StatusInternalServerError)
		return
	}

	// Default: random session id (FIDO2-bound bootstrap).
	var (
		sessionID    string
		sessionIDRaw []byte
		sub          string
	)

	if req.EncAuth != nil && verifier != nil {
		// Rate-limit voucher-backed bootstraps per sid BEFORE the
		// signature checks: failed attempts are the abuse vector and
		// the sid is readable with a cheap decode (a forged sid only
		// rate-limits the forger's own bucket; signature verification
		// still gates acceptance).
		if sid := encAuthSID(req.EncAuth); sid != "" && !m.allowRebind(sid) {
			w.Header().Set("X-Privasys-EncAuth-Reject", "rate-limited")
			http.Error(w, "encauth rate-limited", http.StatusTooManyRequests)
			return
		}
		payload, vErr := verifier.Verify(req.EncAuth, encPubBytes, quoteDigest, hasQuoteDigest, m.now())
		if vErr != nil {
			// Fall through to legacy bootstrap path so the SDK can
			// retry with a fresh FIDO2 ceremony. Surface the reason
			// via a header for client-side diagnostics.
			w.Header().Set("X-Privasys-EncAuth-Reject", vErr.Error())
		} else {
			sub = payload.Sub
			// Note: the enclave session_id stays random even when an
			// EncAuth voucher authenticates the bootstrap — it's a
			// transport handle, not an identity. The persistent
			// per-(user, app, device) `sid` lives in the IdP and the
			// JWT, and the SDK keeps using it to fetch fresh vouchers.
			_ = payload // (Sub already captured)
		}
	}

	if sessionID == "" {
		sessionIDRaw = make([]byte, 16)
		if _, err := rand.Read(sessionIDRaw); err != nil {
			http.Error(w, "rand", http.StatusInternalServerError)
			return
		}
		sessionID = base64.RawURLEncoding.EncodeToString(sessionIDRaw)
	}

	sess, err := buildSession(sessionID, sessionIDRaw, shared, m.ttl, m.now)
	if err != nil {
		http.Error(w, "session derive: "+err.Error(), http.StatusInternalServerError)
		return
	}

	m.mu.Lock()
	m.gcLocked()
	m.sessions[sessionID] = sess
	m.mu.Unlock()

	resp := initResponse{
		SessionID: sessionID,
		EncPub:    base64.RawURLEncoding.EncodeToString(encPubBytes),
		ExpiresAt: sess.ExpiresAt.Unix(),
		Sub:       sub,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func buildSession(id string, salt, shared []byte, ttl time.Duration, now func() time.Time) (*Session, error) {
	aeadKey := hkdf(shared, salt, []byte(hkdfInfo), 32)
	c2s := hkdf(shared, salt, []byte(dirInfoC2S), 4)
	s2c := hkdf(shared, salt, []byte(dirInfoS2C), 4)
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Session{ID: id, Aead: gcm, ExpiresAt: now().Add(ttl)}
	copy(s.C2SPrefix[:], c2s)
	copy(s.S2CPrefix[:], s2c)
	return s, nil
}

func (m *Manager) handleSealed(w http.ResponseWriter, r *http.Request, next http.Handler) {
	sess, ok := m.lookup(r)
	if !ok {
		http.Error(w, "unknown or expired session", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
	if err != nil {
		http.Error(w, "read sealed body", http.StatusBadRequest)
		return
	}
	env, err := decodeSealed(body)
	if err != nil {
		http.Error(w, "decode sealed: "+err.Error(), http.StatusBadRequest)
		return
	}
	ad := []byte(strings.ToUpper(r.Method) + ":" + r.URL.RequestURI() + ":" + sess.ID)
	nonce := makeNonce(sess.C2SPrefix[:], env.Ctr)
	pt, err := sess.Aead.Open(nil, nonce, env.Ct, ad)
	if err != nil {
		http.Error(w, "aead open", http.StatusUnauthorized)
		return
	}
	// Replay rejection: the SDK uses a strict counter, so accept only
	// ctr >= the smallest not-yet-seen value and advance past it. This
	// also rejects a byte-exact replay of the most recent frame (same
	// nonce/AAD/ct would otherwise pass AEAD). Out-of-order requests
	// across parallel fetches will fail; that's a deliberate trade-off.
	m.mu.Lock()
	if env.Ctr < sess.C2SNext {
		m.mu.Unlock()
		http.Error(w, "replay", http.StatusUnauthorized)
		return
	}
	sess.C2SNext = env.Ctr + 1
	// Sliding inactivity TTL: an authenticated, non-replayed frame keeps
	// the session alive. Touched only after AEAD open + counter accept so
	// replays cannot extend a session's life.
	sess.ExpiresAt = m.now().Add(m.ttl)
	m.mu.Unlock()

	// Replace request body with plaintext and call inner handler with a
	// streaming sealed writer. The writer decides at first Write/Flush
	// whether to use single-envelope or stream framing.
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(pt))
	r2.ContentLength = int64(len(pt))
	r2.Header.Del("Content-Type")
	if len(pt) > 0 {
		// Default the inner content-type so JSON handlers don't have to
		// guess. The plaintext is already what the handler expects.
		r2.Header.Set("Content-Type", "application/json")
	}

	sw := newSealedRespWriter(w, sess, ad, m)
	next.ServeHTTP(sw, r2)
	sw.finalize()
}

func (m *Manager) lookup(r *http.Request) (*Session, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, authScheme+" ") {
		return nil, false
	}
	id := strings.TrimSpace(strings.TrimPrefix(auth, authScheme+" "))
	m.mu.RLock()
	sess, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if m.now().After(sess.ExpiresAt) {
		m.mu.Lock()
		delete(m.sessions, id)
		m.mu.Unlock()
		return nil, false
	}
	return sess, true
}

func (m *Manager) gcLocked() {
	now := m.now()
	for id, s := range m.sessions {
		if now.After(s.ExpiresAt) {
			delete(m.sessions, id)
		}
	}
}

// allowRebind records one EncAuth-backed bootstrap attempt for sid and
// reports whether it is within the fixed per-window budget. Expired
// windows are swept opportunistically so the map cannot grow unbounded
// under randomly-forged sids.
func (m *Manager) allowRebind(sid string) bool {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rebinds) > 10_000 {
		for k, w := range m.rebinds {
			if now.Sub(w.start) > rebindRateWindow {
				delete(m.rebinds, k)
			}
		}
	}
	w, ok := m.rebinds[sid]
	if !ok || now.Sub(w.start) > rebindRateWindow {
		m.rebinds[sid] = &rebindWindow{start: now, count: 1}
		return true
	}
	w.count++
	return w.count <= rebindRateLimit
}

// -----------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869)
// -----------------------------------------------------------------------------

func hkdf(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)
	out := make([]byte, 0, length)
	var t []byte
	var counter byte = 1
	for len(out) < length {
		mac = hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

// -----------------------------------------------------------------------------
// nonces
// -----------------------------------------------------------------------------

func makeNonce(prefix []byte, ctr uint64) []byte {
	n := make([]byte, 12)
	copy(n[:4], prefix[:4])
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// -----------------------------------------------------------------------------
// CBOR (3-key sealed envelope only)
// -----------------------------------------------------------------------------

type sealedEnvelope struct {
	V   uint64
	Ctr uint64
	Ct  []byte
}

func encodeSealed(env sealedEnvelope) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0xa3) // map(3)
	writeCborText(&buf, "v")
	writeCborUint(&buf, env.V)
	writeCborText(&buf, "ctr")
	writeCborUint(&buf, env.Ctr)
	writeCborText(&buf, "ct")
	writeCborBytes(&buf, env.Ct)
	return buf.Bytes()
}

func decodeSealed(in []byte) (sealedEnvelope, error) {
	var env sealedEnvelope
	if len(in) == 0 || in[0] != 0xa3 {
		return env, errors.New("expected map(3)")
	}
	off := 1
	for i := 0; i < 3; i++ {
		key, n, err := readCborText(in, off)
		if err != nil {
			return env, err
		}
		off = n
		switch key {
		case "v":
			v, n, err := readCborUint(in, off)
			if err != nil {
				return env, err
			}
			env.V = v
			off = n
		case "ctr":
			v, n, err := readCborUint(in, off)
			if err != nil {
				return env, err
			}
			env.Ctr = v
			off = n
		case "ct":
			b, n, err := readCborBytes(in, off)
			if err != nil {
				return env, err
			}
			env.Ct = b
			off = n
		default:
			return env, fmt.Errorf("unexpected cbor key %q", key)
		}
	}
	return env, nil
}

func writeCborUint(buf *bytes.Buffer, n uint64) {
	switch {
	case n < 24:
		buf.WriteByte(byte(n))
	case n < 1<<8:
		buf.WriteByte(0x18)
		buf.WriteByte(byte(n))
	case n < 1<<16:
		buf.WriteByte(0x19)
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(n))
		buf.Write(b[:])
	case n < 1<<32:
		buf.WriteByte(0x1a)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		buf.Write(b[:])
	default:
		buf.WriteByte(0x1b)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		buf.Write(b[:])
	}
}

func writeCborHeader(buf *bytes.Buffer, major byte, n uint64) {
	pos := buf.Len()
	writeCborUint(buf, n)
	// Patch the major type into the first byte we just wrote.
	out := buf.Bytes()
	out[pos] = (major << 5) | (out[pos] & 0x1f)
}

func writeCborText(buf *bytes.Buffer, s string) {
	writeCborHeader(buf, 3, uint64(len(s)))
	buf.WriteString(s)
}

func writeCborBytes(buf *bytes.Buffer, b []byte) {
	writeCborHeader(buf, 2, uint64(len(b)))
	buf.Write(b)
}

func readCborUint(in []byte, off int) (uint64, int, error) {
	if off >= len(in) {
		return 0, 0, errors.New("cbor: short uint")
	}
	if in[off]>>5 != 0 {
		return 0, 0, fmt.Errorf("cbor: expected uint, got major %d", in[off]>>5)
	}
	return readCborArgument(in, off)
}

func readCborText(in []byte, off int) (string, int, error) {
	if off >= len(in) {
		return "", 0, errors.New("cbor: short text")
	}
	if in[off]>>5 != 3 {
		return "", 0, fmt.Errorf("cbor: expected text, got major %d", in[off]>>5)
	}
	n, end, err := readCborArgument(in, off)
	if err != nil {
		return "", 0, err
	}
	if end+int(n) > len(in) {
		return "", 0, errors.New("cbor: text overrun")
	}
	return string(in[end : end+int(n)]), end + int(n), nil
}

func readCborBytes(in []byte, off int) ([]byte, int, error) {
	if off >= len(in) {
		return nil, 0, errors.New("cbor: short bytes")
	}
	if in[off]>>5 != 2 {
		return nil, 0, fmt.Errorf("cbor: expected bytes, got major %d", in[off]>>5)
	}
	n, end, err := readCborArgument(in, off)
	if err != nil {
		return nil, 0, err
	}
	if end+int(n) > len(in) {
		return nil, 0, errors.New("cbor: bytes overrun")
	}
	out := make([]byte, n)
	copy(out, in[end:end+int(n)])
	return out, end + int(n), nil
}

func readCborArgument(in []byte, off int) (uint64, int, error) {
	ai := in[off] & 0x1f
	switch {
	case ai < 24:
		return uint64(ai), off + 1, nil
	case ai == 24:
		if off+2 > len(in) {
			return 0, 0, errors.New("cbor: short u8")
		}
		return uint64(in[off+1]), off + 2, nil
	case ai == 25:
		if off+3 > len(in) {
			return 0, 0, errors.New("cbor: short u16")
		}
		return uint64(binary.BigEndian.Uint16(in[off+1 : off+3])), off + 3, nil
	case ai == 26:
		if off+5 > len(in) {
			return 0, 0, errors.New("cbor: short u32")
		}
		return uint64(binary.BigEndian.Uint32(in[off+1 : off+5])), off + 5, nil
	case ai == 27:
		if off+9 > len(in) {
			return 0, 0, errors.New("cbor: short u64")
		}
		return binary.BigEndian.Uint64(in[off+1 : off+9]), off + 9, nil
	}
	return 0, 0, fmt.Errorf("cbor: unsupported additional info %d", ai)
}

// -----------------------------------------------------------------------------
// sealed response writer (single-envelope OR stream framing)
// -----------------------------------------------------------------------------

// sealedRespWriter wraps the outer http.ResponseWriter and seals the inner
// handler's output. It defers the format decision until the first Write or
// Flush:
//
//   - If the inner handler sets Content-Type: text/event-stream OR calls
//     Flush() before completion, the response is emitted as a stream of
//     length-prefixed sealed frames (Content-Type:
//     application/privasys-sealed-stream+cbor). Each frame:
//     [u32 BE length][CBOR sealed envelope {v,ctr,ct}]
//     A trailing length=0 frame terminates the stream.
//   - Otherwise the full body is buffered and emitted as a single sealed
//     envelope (Content-Type: application/privasys-sealed+cbor) — backwards
//     compatible with SDK 0.2.0/0.2.1.
type sealedRespWriter struct {
	outer   http.ResponseWriter
	sess    *Session
	ad      []byte
	mgr     *Manager
	header  http.Header
	status  int
	buf     bytes.Buffer
	decided bool
	stream  bool
}

func newSealedRespWriter(outer http.ResponseWriter, sess *Session, ad []byte, mgr *Manager) *sealedRespWriter {
	return &sealedRespWriter{outer: outer, sess: sess, ad: ad, mgr: mgr, header: make(http.Header), status: http.StatusOK}
}

func (w *sealedRespWriter) Header() http.Header { return w.header }

func (w *sealedRespWriter) WriteHeader(code int) { w.status = code }

func (w *sealedRespWriter) Write(p []byte) (int, error) {
	if !w.decided {
		ct := w.header.Get("Content-Type")
		if strings.HasPrefix(ct, "text/event-stream") {
			w.startStream()
		}
	}
	if w.stream {
		return w.writeFrame(p)
	}
	return w.buf.Write(p)
}

// Flush implements http.Flusher. The first Flush forces stream mode (since
// the handler clearly wants chunked delivery).
func (w *sealedRespWriter) Flush() {
	if !w.decided {
		w.startStream()
	}
	if w.stream {
		if f, ok := w.outer.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (w *sealedRespWriter) startStream() {
	w.decided = true
	w.stream = true
	out := w.outer.Header()
	out.Set("Content-Type", sealedStreamContentType)
	out.Set("Cache-Control", "no-store")
	out.Set("X-Privasys-Inner-Status", fmt.Sprintf("%d", w.status))
	w.outer.WriteHeader(http.StatusOK)
	// If the buffer has bytes (Write happened before SSE header was set, very
	// unlikely), flush them as the first frame.
	if w.buf.Len() > 0 {
		_, _ = w.writeFrame(w.buf.Bytes())
		w.buf.Reset()
	}
}

func (w *sealedRespWriter) writeFrame(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mgr.mu.Lock()
	ctr := w.sess.S2CCtr
	w.sess.S2CCtr++
	w.mgr.mu.Unlock()
	nonce := makeNonce(w.sess.S2CPrefix[:], ctr)
	ct := w.sess.Aead.Seal(nil, nonce, p, w.ad)
	env := encodeSealed(sealedEnvelope{V: 1, Ctr: ctr, Ct: ct})
	var lenHdr [4]byte
	binary.BigEndian.PutUint32(lenHdr[:], uint32(len(env)))
	if _, err := w.outer.Write(lenHdr[:]); err != nil {
		return 0, err
	}
	if _, err := w.outer.Write(env); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *sealedRespWriter) finalize() {
	if w.stream {
		// Terminator: zero-length frame.
		var zero [4]byte
		_, _ = w.outer.Write(zero[:])
		if f, ok := w.outer.(http.Flusher); ok {
			f.Flush()
		}
		return
	}
	// Single-envelope path.
	w.decided = true
	w.mgr.mu.Lock()
	ctr := w.sess.S2CCtr
	w.sess.S2CCtr++
	w.mgr.mu.Unlock()
	respNonce := makeNonce(w.sess.S2CPrefix[:], ctr)
	ct := w.sess.Aead.Seal(nil, respNonce, w.buf.Bytes(), w.ad)
	enc := encodeSealed(sealedEnvelope{V: 1, Ctr: ctr, Ct: ct})
	out := w.outer.Header()
	out.Set("Content-Type", sealedContentType)
	out.Set("Cache-Control", "no-store")
	out.Set("X-Privasys-Inner-Status", fmt.Sprintf("%d", w.status))
	w.outer.WriteHeader(http.StatusOK)
	_, _ = w.outer.Write(enc)
}

// -----------------------------------------------------------------------------
// capturing http.ResponseWriter (legacy; kept for tests that pre-date the
// streaming writer)
// -----------------------------------------------------------------------------

type capturingWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newCapturingWriter() *capturingWriter {
	return &capturingWriter{header: make(http.Header), status: http.StatusOK}
}

func (c *capturingWriter) Header() http.Header { return c.header }

func (c *capturingWriter) WriteHeader(code int) { c.status = code }

func (c *capturingWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c.body.Write(p)
}
