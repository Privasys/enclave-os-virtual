// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessionrelay

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// startEchoApp runs a plaintext WebSocket echo app (the container the relay
// dials) and returns its host:port.
func startEchoApp(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			typ, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), typ, data); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u.Host
}

// startRelay runs the Middleware-wrapped relay with the echo app installed
// as every host's upstream and returns the relay's host:port.
func startRelay(t *testing.T, m *Manager, appHost string) string {
	t.Helper()
	m.SetWSUpstream(func(string) (string, bool) { return appHost, true })
	srv := httptest.NewServer(m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not sealed", http.StatusTeapot)
	})))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u.Host
}

// muxClient is a minimal gateway-side mux client for tests.
type muxClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
}

func dialMux(t *testing.T, relayHost string) *muxClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", relayHost, 5*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: relay\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n", muxPath, muxProtocol)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("mux upgrade: %q err=%v", status, err)
	}
	for { // drain response headers
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	return &muxClient{t: t, conn: conn, br: br}
}

func (c *muxClient) write(typ byte, sid string, stream uint64, payload []byte) {
	c.t.Helper()
	var hdr [14]byte
	hdr[0] = typ
	hdr[1] = byte(len(sid))
	binary.BigEndian.PutUint64(hdr[2:10], stream)
	binary.BigEndian.PutUint32(hdr[10:14], uint32(len(payload)))
	buf := append(append(append([]byte{}, hdr[:2]...), sid...), hdr[2:14]...)
	buf = append(buf, payload...)
	if _, err := c.conn.Write(buf); err != nil {
		c.t.Fatalf("mux write: %v", err)
	}
}

func (c *muxClient) read() (typ byte, sid string, stream uint64, payload []byte) {
	c.t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, sid, stream, payload, err := readMuxFrame(c.br)
	if err != nil {
		c.t.Fatalf("mux read: %v", err)
	}
	return typ, sid, stream, payload
}

func (c *muxClient) openPayload(host, path string, env []byte) []byte {
	out := make([]byte, 2+len(host)+2+len(path)+len(env))
	binary.BigEndian.PutUint16(out[:2], uint16(len(host)))
	copy(out[2:], host)
	off := 2 + len(host)
	binary.BigEndian.PutUint16(out[off:off+2], uint16(len(path)))
	copy(out[off+2:], path)
	copy(out[off+2+len(path):], env)
	return out
}

// streamSealer derives the SDK side of one mux stream.
type streamSealer struct {
	sess      *Session
	streamHex string
	c2s, s2c  [4]byte
	ad        []byte
}

func newStreamSealer(sess *Session, path string, stream uint64) *streamSealer {
	s := &streamSealer{sess: sess, streamHex: fmt.Sprintf("%016x", stream)}
	s.c2s, s.s2c = sess.wsStreamPrefixes(s.streamHex)
	s.ad = []byte("WS:" + path + ":" + sess.ID + ":" + s.streamHex)
	return s
}

func (s *streamSealer) seal(pt []byte, ctr uint64) []byte {
	ct := s.sess.Aead.Seal(nil, makeNonce(s.c2s[:], ctr), pt, s.ad)
	return encodeSealed(sealedEnvelope{V: 1, Ctr: ctr, Ct: ct})
}

func (s *streamSealer) unseal(t *testing.T, frame []byte, wantCtr uint64) []byte {
	t.Helper()
	env, err := decodeSealed(frame)
	if err != nil {
		t.Fatalf("decode sealed: %v", err)
	}
	if env.Ctr != wantCtr {
		t.Fatalf("s2c ctr = %d, want %d", env.Ctr, wantCtr)
	}
	pt, err := s.sess.Aead.Open(nil, makeNonce(s.s2c[:], env.Ctr), env.Ct, s.ad)
	if err != nil {
		t.Fatalf("unseal s2c: %v", err)
	}
	return pt
}

func TestMuxStreamEcho(t *testing.T) {
	m := NewManager()
	sess, _ := testSession(t, m, "user-1")
	relayHost := startRelay(t, m, startEchoApp(t))
	c := dialMux(t, relayHost)

	const stream = uint64(0x0123456789abcdef)
	sealer := newStreamSealer(sess, "/live", stream)
	c.write(muxTypeOpen, sess.ID, stream, c.openPayload("app.example.org", "/live", sealer.seal([]byte("open"), 0)))

	typ, _, gotStream, payload := c.read()
	if typ != muxTypeData || gotStream != stream {
		t.Fatalf("expected ack DATA on stream %x, got type %d stream %x (%q)", stream, typ, gotStream, payload)
	}
	if ack := sealer.unseal(t, payload, 0); string(ack) != "ack" {
		t.Fatalf("ack plaintext = %q", ack)
	}

	c.write(muxTypeData, sess.ID, stream, sealer.seal([]byte("hello mux"), 1))
	typ, _, _, payload = c.read()
	if typ != muxTypeData {
		t.Fatalf("expected echoed DATA, got type %d", typ)
	}
	if echo := sealer.unseal(t, payload, 1); string(echo) != "hello mux" {
		t.Fatalf("echo = %q", echo)
	}

	c.write(muxTypeClose, sess.ID, stream, encodeMuxClose(websocket.StatusNormalClosure, "done"))
	// Session bookkeeping is released once the stream is torn down.
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.RLock()
		n := m.muxSessionStreams[sess.ID]
		m.mu.RUnlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream count not released: %d", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMuxConcurrentStreams proves what v1 cannot do: two live WebSocket
// streams on ONE session, each on an independent keystream.
func TestMuxConcurrentStreams(t *testing.T) {
	m := NewManager()
	sess, _ := testSession(t, m, "")
	relayHost := startRelay(t, m, startEchoApp(t))
	c := dialMux(t, relayHost)

	streams := []uint64{1, 2}
	sealers := make(map[uint64]*streamSealer)
	for _, id := range streams {
		sealers[id] = newStreamSealer(sess, "/live", id)
		c.write(muxTypeOpen, sess.ID, id, c.openPayload("app.example.org", "/live", sealers[id].seal([]byte("open"), 0)))
	}
	acked := map[uint64]bool{}
	for range streams {
		typ, _, id, payload := c.read()
		if typ != muxTypeData {
			t.Fatalf("expected ack, got type %d (%q)", typ, payload)
		}
		sealers[id].unseal(t, payload, 0)
		acked[id] = true
	}
	if len(acked) != 2 {
		t.Fatalf("acks = %v", acked)
	}
	if p1, p2 := sealers[1].c2s, sealers[2].c2s; p1 == p2 {
		t.Fatalf("per-stream c2s prefixes must differ, both %x", p1)
	}
	for _, id := range streams {
		msg := fmt.Sprintf("stream-%d", id)
		c.write(muxTypeData, sess.ID, id, sealers[id].seal([]byte(msg), 1))
	}
	got := map[uint64]string{}
	for range streams {
		typ, _, id, payload := c.read()
		if typ != muxTypeData {
			t.Fatalf("expected echo, got type %d", typ)
		}
		got[id] = string(sealers[id].unseal(t, payload, 1))
	}
	if got[1] != "stream-1" || got[2] != "stream-2" {
		t.Fatalf("echoes = %v", got)
	}
}

func TestMuxRejects(t *testing.T) {
	m := NewManager()
	sess, _ := testSession(t, m, "")
	relayHost := startRelay(t, m, startEchoApp(t))

	t.Run("unknown session", func(t *testing.T) {
		c := dialMux(t, relayHost)
		sealer := newStreamSealer(sess, "/live", 7)
		c.write(muxTypeOpen, "no-such-session", 7, c.openPayload("h", "/live", sealer.seal([]byte("open"), 0)))
		typ, sid, _, _ := c.read()
		if typ != muxTypeClose || sid != "no-such-session" {
			t.Fatalf("expected CLOSE for unknown session, got type %d sid %q", typ, sid)
		}
	})

	t.Run("wrong keystream", func(t *testing.T) {
		c := dialMux(t, relayHost)
		// Seal the open under stream 8's keystream but route it as stream 9:
		// the AAD/prefix mismatch must be rejected before any app dial.
		sealer := newStreamSealer(sess, "/live", 8)
		c.write(muxTypeOpen, sess.ID, 9, c.openPayload("h", "/live", sealer.seal([]byte("open"), 0)))
		typ, _, stream, payload := c.read()
		if typ != muxTypeClose || stream != 9 {
			t.Fatalf("expected CLOSE on stream 9, got type %d stream %d", typ, stream)
		}
		if code, _ := parseMuxClose(payload); code != websocket.StatusPolicyViolation {
			t.Fatalf("close code = %d, want %d", code, websocket.StatusPolicyViolation)
		}
	})

	t.Run("data for unopened stream", func(t *testing.T) {
		c := dialMux(t, relayHost)
		c.write(muxTypeData, sess.ID, 42, []byte{0x01})
		typ, _, stream, _ := c.read()
		if typ != muxTypeClose || stream != 42 {
			t.Fatalf("expected CLOSE for unopened stream, got type %d stream %d", typ, stream)
		}
	})
}

// TestWSStreamPrefixKAT pins the per-stream keystream derivation against a
// vector computed independently with WebCrypto (node:crypto), exactly as the
// SDK derives it (enclave-session.ts openStream): HKDF-SHA256, salt = the
// session-id bytes, info = "<label>/<streamHex>". A label or encoding drift
// on either side breaks this test before it breaks a browser.
func TestWSStreamPrefixKAT(t *testing.T) {
	shared := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i + 1)
	}
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(0xa0 + i)
	}
	s := &Session{IKM: shared, Salt: salt}
	c2s, s2c := s.wsStreamPrefixes("0123456789abcdef")
	if got := fmt.Sprintf("%x", c2s); got != "3aa25068" {
		t.Fatalf("c2s prefix = %s, want 3aa25068", got)
	}
	if got := fmt.Sprintf("%x", s2c); got != "83d5d2e1" {
		t.Fatalf("s2c prefix = %s, want 83d5d2e1", got)
	}
}

func TestMuxPing(t *testing.T) {
	m := NewManager()
	relayHost := startRelay(t, m, "unused")
	c := dialMux(t, relayHost)
	c.write(muxTypePing, "", 0, []byte("hb"))
	typ, _, _, payload := c.read()
	if typ != muxTypePong || string(payload) != "hb" {
		t.Fatalf("expected PONG hb, got type %d %q", typ, payload)
	}
}

// TestDirectSealedWebSocketRefused locks in that a sealed WebSocket upgrade
// arriving at the enclave DIRECTLY (not as a mux stream) is refused: the
// gateway is the only sealed-WebSocket terminator.
func TestDirectSealedWebSocketRefused(t *testing.T) {
	m := NewManager()
	sess, _ := testSession(t, m, "")
	relayHost := startRelay(t, m, startEchoApp(t))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, "ws://"+relayHost+"/live", &websocket.DialOptions{
		Subprotocols: []string{sealedWSSubprotocol, sess.ID, "00000000000000aa"},
	})
	if err == nil {
		ws.CloseNow()
		t.Fatal("direct sealed websocket must be refused")
	}
	if resp == nil || resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("expected 426 refusal, got resp=%v err=%v", resp, err)
	}
}
