// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package sessionrelay

// Multiplexed sealed-WebSocket transport ("privasys-mux/1").
//
// The 1:1 relay (websocket.go) hijacks one gateway->enclave connection per
// browser WebSocket, making the enclave's transport footprint O(clients). On
// this leg a mux-capable gateway terminates the browser WebSockets itself,
// owns all of the WebSocket protocol state (fragmentation, ping/pong, close,
// admission control), and carries each sealed message as a framed unit over
// a SMALL pool of long-lived connections; the enclave demuxes per
// (session_id, stream_id), unseals, and forwards to the app's own plaintext
// WebSocket — the same demux-over-a-pool shape sealed HTTP requests already
// use, so the enclave's connection count is bounded by the gateway pool, not
// the client count.
//
// Wire format (integers big-endian), one frame per message:
//
//	u8  type      1=OPEN 2=DATA 3=CLOSE 4=PING 5=PONG
//	u8  sidLen    session id length (0 for PING/PONG)
//	    sid       session id (ASCII base64url)
//	u64 streamID  raw stream id; its %016x rendering is the streamHex used
//	              in the HKDF info and the AAD
//	u32 len       payload length
//	    payload
//
// OPEN payload:  u16 hostLen | host | u16 pathLen | path | sealed CBOR
//                envelope (the SDK's stream-open: ctr 0, plaintext "open")
// DATA payload:  one sealed CBOR envelope
// CLOSE payload: u16 code | reason (utf-8); code 0 means 1000
//
// Per-stream keystream: the nonce prefixes fold the streamHex into the HKDF
// info (Session.wsStreamPrefixes) and the AAD is
// "WS:<path>:<session_id>:<streamHex>", so concurrent streams on one session
// never share a nonce sequence and a frame cannot be replayed onto another
// stream. The stream id is chosen by the SDK: the OPEN envelope only unseals
// if the SDK derived the same (path, session, stream) tuple, which
// authenticates the gateway's unsealed routing header before the app is
// dialed. The enclave answers with a sealed "ack" (s2c ctr 0); application
// data then flows from ctr 1 in both directions, strictly monotonic.
//
// Must match the SDK's v2 mode (auth/sdk enclave-session.ts) and the
// gateway's mux client (platform-gateway internal/terminate/wsmux.go).

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	muxPath     = "/__privasys/ws-mux"
	muxProtocol = "privasys-mux/1"

	muxTypeOpen  byte = 1
	muxTypeData  byte = 2
	muxTypeClose byte = 3
	muxTypePing  byte = 4
	muxTypePong  byte = 5

	// muxMaxFrame bounds one mux frame payload: the sealed-message cap plus
	// headroom for the AEAD tag, CBOR envelope and OPEN routing header.
	muxMaxFrame = sealedWSMaxMessage + 64*1024
	// muxMaxSIDLen bounds the session-id field (real ids are 22 chars).
	muxMaxSIDLen = 64
	// muxMaxStreamsPerConn bounds live streams on one mux connection.
	muxMaxStreamsPerConn = 1024
	// muxMaxStreamsPerSession bounds concurrent streams one session may
	// hold, so a single client cannot exhaust the per-conn budget.
	muxMaxStreamsPerSession = 32
	// muxMaxStreamsPerSessionLifetime bounds how many stream ids one
	// session may consume in total (ids are single-use — the replay guard
	// remembers each one, so the set must stay bounded). At this point the
	// SDK re-establishes the session, which resets everything.
	muxMaxStreamsPerSessionLifetime = 4096
	// muxStreamQueue is the per-stream inbound buffer (frames): the mux
	// reader must never block on one slow app socket, so overflow closes
	// that stream instead of stalling the shared connection.
	muxStreamQueue = 32
	// muxReadIdle kills a mux connection with no traffic at all; the
	// gateway pings well inside this.
	muxReadIdle = 2 * time.Minute
	// muxWriteTimeout bounds one frame write toward the gateway.
	muxWriteTimeout = 30 * time.Second
)

// SetWSUpstream installs the resolver mapping a request Host to the app
// container's plaintext WebSocket endpoint ("host:port"). Until set, mux
// upgrades are refused with 501.
func (m *Manager) SetWSUpstream(f func(host string) (string, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wsUpstream = f
}

// isMuxUpgrade reports whether r is a privasys-mux/1 upgrade request.
func isMuxUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		r.URL.Path == muxPath &&
		strings.EqualFold(r.Header.Get("Upgrade"), muxProtocol) &&
		hasConnectionUpgrade(r)
}

// isWebSocketUpgrade reports whether r is a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && hasConnectionUpgrade(r)
}

// hasSealedWSSubprotocol reports whether the client advertised the sealed
// marker as its first subprotocol. Such upgrades never terminate here — the
// gateway owns them and relays their frames over the mux — so the enclave
// refuses any that arrive directly.
func hasSealedWSSubprotocol(r *http.Request) bool {
	for _, line := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, tok := range strings.Split(line, ",") {
			if t := strings.TrimSpace(tok); t != "" {
				return t == sealedWSSubprotocol
			}
		}
	}
	return false
}

// hasConnectionUpgrade reports whether the Connection header carries the
// "upgrade" token.
func hasConnectionUpgrade(r *http.Request) bool {
	for _, tok := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

// handleMux upgrades the connection to privasys-mux/1 and serves frames
// until the peer disconnects. One handleMux call = one gateway pool member.
func (m *Manager) handleMux(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	resolver := m.wsUpstream
	m.mu.RUnlock()
	if resolver == nil {
		http.Error(w, "sealed websocket relay not configured", http.StatusNotImplemented)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "mux requires a hijackable connection", http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + muxProtocol + "\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}

	mc := &muxConn{
		m:        m,
		conn:     conn,
		br:       brw.Reader,
		bw:       brw.Writer,
		resolver: resolver,
		streams:  make(map[muxStreamKey]*muxStream),
	}
	mc.ctx, mc.cancel = context.WithCancel(context.Background())
	defer mc.teardown()
	mc.serve()
}

type muxStreamKey struct {
	sid    string
	stream uint64
}

// muxConn is one gateway<->enclave mux connection and the streams riding it.
type muxConn struct {
	m        *Manager
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	resolver func(host string) (string, bool)
	ctx      context.Context
	cancel   context.CancelFunc

	wmu sync.Mutex // serialises frame writes (bw + conn deadline)

	smu     sync.Mutex
	streams map[muxStreamKey]*muxStream
}

// muxStream is one browser WebSocket carried as a logical stream.
type muxStream struct {
	mc        *muxConn
	key       muxStreamKey
	streamHex string
	sess      *Session
	host      string
	path      string

	c2sPrefix [4]byte
	s2cPrefix [4]byte
	ad        []byte

	// inbound receives sealed DATA payloads from the mux reader; bounded so
	// one slow app cannot stall the shared connection (overflow closes the
	// stream). Closed by shutdown.
	inbound chan []byte
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

// serve is the mux read loop: it demuxes frames to streams and never blocks
// on stream work (OPEN dial and app I/O run in per-stream goroutines).
func (mc *muxConn) serve() {
	for {
		_ = mc.conn.SetReadDeadline(time.Now().Add(muxReadIdle))
		typ, sid, stream, payload, err := readMuxFrame(mc.br)
		if err != nil {
			return
		}
		switch typ {
		case muxTypePing:
			_ = mc.writeFrame(muxTypePong, "", 0, payload)
		case muxTypePong:
			// Liveness only; the read deadline already advanced.
		case muxTypeOpen:
			mc.handleOpen(sid, stream, payload)
		case muxTypeData:
			key := muxStreamKey{sid: sid, stream: stream}
			mc.smu.Lock()
			st := mc.streams[key]
			mc.smu.Unlock()
			if st == nil {
				// Unknown stream: already closed, or never opened. Tell the
				// gateway so it can drop its side; not an error for the conn.
				_ = mc.writeClose(sid, stream, websocket.StatusProtocolError, "unknown stream")
				continue
			}
			select {
			case st.inbound <- payload:
			default:
				// The app socket is not draining; closing the stream is the
				// backpressure policy that protects the shared connection.
				st.shutdown(websocket.StatusPolicyViolation, "stream backpressure overflow", true)
			}
		case muxTypeClose:
			key := muxStreamKey{sid: sid, stream: stream}
			mc.smu.Lock()
			st := mc.streams[key]
			mc.smu.Unlock()
			if st != nil {
				code, reason := parseMuxClose(payload)
				st.shutdown(code, reason, false)
			}
		default:
			// Unknown frame type: protocol violation, drop the connection.
			return
		}
	}
}

// handleOpen validates and registers a stream, then completes the open
// (unseal, app dial, ack) asynchronously so the read loop is never blocked
// by a slow upstream dial.
func (mc *muxConn) handleOpen(sid string, stream uint64, payload []byte) {
	host, path, openEnv, err := parseMuxOpen(payload)
	if err != nil {
		_ = mc.writeClose(sid, stream, websocket.StatusProtocolError, "malformed open")
		return
	}
	sess, ok := mc.m.lookupByID(sid)
	if !ok {
		// Mirrors the v1 pre-101 refusal: the SDK re-establishes the session.
		_ = mc.writeClose(sid, stream, websocket.StatusPolicyViolation, "unknown or expired session")
		return
	}
	key := muxStreamKey{sid: sid, stream: stream}

	mc.smu.Lock()
	if len(mc.streams) >= muxMaxStreamsPerConn {
		mc.smu.Unlock()
		_ = mc.writeClose(sid, stream, websocket.StatusTryAgainLater, "stream limit reached")
		return
	}
	if _, dup := mc.streams[key]; dup {
		mc.smu.Unlock()
		_ = mc.writeClose(sid, stream, websocket.StatusProtocolError, "duplicate stream id")
		return
	}
	mc.m.mu.Lock()
	if mc.m.muxSessionStreams[sid] >= muxMaxStreamsPerSession {
		mc.m.mu.Unlock()
		mc.smu.Unlock()
		_ = mc.writeClose(sid, stream, websocket.StatusTryAgainLater, "session stream limit reached")
		return
	}
	// Stream ids are single-use per session: a recorded OPEN cannot be
	// replayed as a fresh stream (its per-stream counters would otherwise
	// restart and the enclave would re-execute the recorded frames).
	used := mc.m.muxUsedStreams[sid]
	if used == nil {
		used = make(map[uint64]struct{})
		mc.m.muxUsedStreams[sid] = used
	}
	if _, replayed := used[stream]; replayed {
		mc.m.mu.Unlock()
		mc.smu.Unlock()
		_ = mc.writeClose(sid, stream, websocket.StatusPolicyViolation, "stream id already used")
		return
	}
	if len(used) >= muxMaxStreamsPerSessionLifetime {
		mc.m.mu.Unlock()
		mc.smu.Unlock()
		_ = mc.writeClose(sid, stream, websocket.StatusTryAgainLater, "session stream budget exhausted; re-establish the session")
		return
	}
	used[stream] = struct{}{}
	mc.m.muxSessionStreams[sid]++
	mc.m.mu.Unlock()

	st := &muxStream{
		mc:        mc,
		key:       key,
		streamHex: fmt.Sprintf("%016x", stream),
		sess:      sess,
		host:      host,
		path:      path,
		inbound:   make(chan []byte, muxStreamQueue),
	}
	st.ctx, st.cancel = context.WithCancel(mc.ctx)
	mc.streams[key] = st
	mc.smu.Unlock()

	go st.run(openEnv)
}

// run completes a registered stream: derive the per-stream keystream, verify
// the SDK's sealed open, dial the app WebSocket, ack, then pump both ways.
func (st *muxStream) run(openEnv []byte) {
	st.c2sPrefix, st.s2cPrefix = st.sess.wsStreamPrefixes(st.streamHex)
	st.ad = []byte("WS:" + st.path + ":" + st.sess.ID + ":" + st.streamHex)

	// The sealed open (c2s ctr 0, plaintext "open") authenticates the
	// gateway's routing header: it only unseals if the SDK derived the same
	// (path, session, stream) tuple into the AAD and keystream.
	env, err := decodeSealed(openEnv)
	if err != nil || env.Ctr != 0 {
		st.shutdown(websocket.StatusProtocolError, "malformed stream open", true)
		return
	}
	pt, err := st.sess.Aead.Open(nil, makeNonce(st.c2sPrefix[:], 0), env.Ct, st.ad)
	if err != nil || string(pt) != "open" {
		st.shutdown(websocket.StatusPolicyViolation, "stream open rejected", true)
		return
	}

	upstream, ok := st.mc.resolver(hostKey(st.host))
	if !ok || upstream == "" {
		st.shutdown(websocket.StatusBadGateway, "no upstream for host", true)
		return
	}
	dialCtx, cancelDial := context.WithTimeout(st.ctx, 10*time.Second)
	defer cancelDial()
	hdr := http.Header{}
	if st.sess.Sub != "" {
		hdr.Set(relaySubHeader, st.sess.Sub)
	}
	appWS, _, err := websocket.Dial(dialCtx, "ws://"+upstream+st.path, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		st.shutdown(websocket.StatusBadGateway, "upstream websocket unreachable", true)
		return
	}
	appWS.SetReadLimit(sealedWSMaxMessage)
	defer appWS.CloseNow()

	// Sealed ack (s2c ctr 0): resolves the SDK's ready promise.
	var s2c uint64
	if err := st.sealAndSend(appWSAck, &s2c); err != nil {
		st.shutdown(websocket.StatusProtocolError, "ack write failed", false)
		return
	}

	// gateway -> app: unseal each queued DATA payload in arrival order.
	go func() {
		var next uint64 = 1 // ctr 0 was the open envelope
		for {
			var sealed []byte
			select {
			case <-st.ctx.Done():
				return
			case sealed = <-st.inbound:
			}
			env, err := decodeSealed(sealed)
			if err != nil || env.Ctr < next {
				st.shutdown(websocket.StatusProtocolError, "replayed or malformed frame", true)
				return
			}
			pt, err := st.sess.Aead.Open(nil, makeNonce(st.c2sPrefix[:], env.Ctr), env.Ct, st.ad)
			if err != nil {
				st.shutdown(websocket.StatusPolicyViolation, "decrypt failed", true)
				return
			}
			next = env.Ctr + 1
			if err := appWS.Write(st.ctx, websocket.MessageBinary, pt); err != nil {
				st.shutdown(websocket.StatusBadGateway, "upstream write failed", true)
				return
			}
		}
	}()

	// app -> gateway: seal each app message as a DATA frame.
	for {
		_, data, err := appWS.Read(st.ctx)
		if err != nil {
			code := websocket.CloseStatus(err)
			if code == -1 {
				code = websocket.StatusInternalError
			}
			st.shutdown(code, "", true)
			return
		}
		if err := st.sealAndSend(data, &s2c); err != nil {
			st.shutdown(websocket.StatusProtocolError, "mux write failed", false)
			return
		}
	}
}

// appWSAck is the plaintext of the sealed stream ack (s2c ctr 0).
var appWSAck = []byte("ack")

func (st *muxStream) sealAndSend(pt []byte, s2c *uint64) error {
	ctr := *s2c
	*s2c = ctr + 1
	ct := st.sess.Aead.Seal(nil, makeNonce(st.s2cPrefix[:], ctr), pt, st.ad)
	frame := encodeSealed(sealedEnvelope{V: 1, Ctr: ctr, Ct: ct})
	return st.mc.writeFrame(muxTypeData, st.key.sid, st.key.stream, frame)
}

// shutdown tears the stream down exactly once. notifyGateway controls whether
// a CLOSE frame is sent back (false when the gateway itself closed the
// stream or the write side is already known broken).
func (st *muxStream) shutdown(code websocket.StatusCode, reason string, notifyGateway bool) {
	st.once.Do(func() {
		st.cancel()
		st.mc.smu.Lock()
		delete(st.mc.streams, st.key)
		st.mc.smu.Unlock()
		st.mc.m.mu.Lock()
		if n := st.mc.m.muxSessionStreams[st.key.sid]; n <= 1 {
			delete(st.mc.m.muxSessionStreams, st.key.sid)
		} else {
			st.mc.m.muxSessionStreams[st.key.sid] = n - 1
		}
		st.mc.m.mu.Unlock()
		if notifyGateway {
			_ = st.mc.writeClose(st.key.sid, st.key.stream, code, reason)
		}
	})
}

// teardown closes every stream when the mux connection dies.
func (mc *muxConn) teardown() {
	mc.cancel()
	mc.smu.Lock()
	streams := make([]*muxStream, 0, len(mc.streams))
	for _, st := range mc.streams {
		streams = append(streams, st)
	}
	mc.smu.Unlock()
	for _, st := range streams {
		st.shutdown(websocket.StatusGoingAway, "mux connection closed", false)
	}
}

// -----------------------------------------------------------------------------
// frame codec
// -----------------------------------------------------------------------------

func (mc *muxConn) writeFrame(typ byte, sid string, stream uint64, payload []byte) error {
	if len(sid) > muxMaxSIDLen {
		return errors.New("mux: session id too long")
	}
	var hdr [14]byte
	hdr[0] = typ
	hdr[1] = byte(len(sid))
	binary.BigEndian.PutUint64(hdr[2:10], stream)
	binary.BigEndian.PutUint32(hdr[10:14], uint32(len(payload)))
	mc.wmu.Lock()
	defer mc.wmu.Unlock()
	_ = mc.conn.SetWriteDeadline(time.Now().Add(muxWriteTimeout))
	if _, err := mc.bw.Write(hdr[:2]); err != nil {
		return err
	}
	if _, err := mc.bw.WriteString(sid); err != nil {
		return err
	}
	if _, err := mc.bw.Write(hdr[2:14]); err != nil {
		return err
	}
	if _, err := mc.bw.Write(payload); err != nil {
		return err
	}
	return mc.bw.Flush()
}

func (mc *muxConn) writeClose(sid string, stream uint64, code websocket.StatusCode, reason string) error {
	return mc.writeFrame(muxTypeClose, sid, stream, encodeMuxClose(code, reason))
}

func encodeMuxClose(code websocket.StatusCode, reason string) []byte {
	out := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(out[:2], uint16(code))
	copy(out[2:], reason)
	return out
}

func parseMuxClose(payload []byte) (websocket.StatusCode, string) {
	if len(payload) < 2 {
		return websocket.StatusNormalClosure, ""
	}
	code := websocket.StatusCode(binary.BigEndian.Uint16(payload[:2]))
	if code == 0 {
		code = websocket.StatusNormalClosure
	}
	return code, string(payload[2:])
}

// parseMuxOpen splits an OPEN payload into host, path and the sealed open
// envelope.
func parseMuxOpen(payload []byte) (host, path string, openEnv []byte, err error) {
	if len(payload) < 2 {
		return "", "", nil, errors.New("mux: short open")
	}
	hostLen := int(binary.BigEndian.Uint16(payload[:2]))
	if len(payload) < 2+hostLen+2 {
		return "", "", nil, errors.New("mux: short open host")
	}
	host = string(payload[2 : 2+hostLen])
	off := 2 + hostLen
	pathLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if len(payload) < off+pathLen {
		return "", "", nil, errors.New("mux: short open path")
	}
	path = string(payload[off : off+pathLen])
	off += pathLen
	if host == "" || !strings.HasPrefix(path, "/") {
		return "", "", nil, errors.New("mux: invalid open routing")
	}
	return host, path, payload[off:], nil
}

// readMuxFrame reads one frame off the wire, enforcing the size caps.
func readMuxFrame(br *bufio.Reader) (typ byte, sid string, stream uint64, payload []byte, err error) {
	var pre [2]byte
	if _, err = io.ReadFull(br, pre[:]); err != nil {
		return 0, "", 0, nil, err
	}
	typ = pre[0]
	sidLen := int(pre[1])
	if sidLen > muxMaxSIDLen {
		return 0, "", 0, nil, errors.New("mux: session id too long")
	}
	buf := make([]byte, sidLen+12)
	if _, err = io.ReadFull(br, buf); err != nil {
		return 0, "", 0, nil, err
	}
	sid = string(buf[:sidLen])
	stream = binary.BigEndian.Uint64(buf[sidLen : sidLen+8])
	plen := binary.BigEndian.Uint32(buf[sidLen+8 : sidLen+12])
	if plen > muxMaxFrame {
		return 0, "", 0, nil, errors.New("mux: frame too large")
	}
	payload = make([]byte, plen)
	if _, err = io.ReadFull(br, payload); err != nil {
		return 0, "", 0, nil, err
	}
	return typ, sid, stream, payload, nil
}
