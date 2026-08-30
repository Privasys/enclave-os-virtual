// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

package sessionrelay

// Sealed WebSocket relay.
//
// A browser opens `wss://<app-host><path>` advertising subprotocols
// [sealedWSSubprotocol, <sessionId>]. The gateway terminates outer TLS and
// proxies the upgrade here; this relay validates the session, terminates the
// sealed WebSocket, dials the app container's PLAINTEXT WebSocket on the same
// path, and pumps messages both ways — unsealing client frames and sealing the
// app's — so the TLS-terminating gateway never sees plaintext.
//
// Each application message is one binary frame carrying an AES-GCM sealed
// envelope under the session key, with the SAME wire format as the sealed HTTP
// transport (CBOR{v,ctr,ct}; nonce = wsPrefix[0:4]||ctr_be; AAD =
// "WS:<request-uri>:<sessionId>") but with WebSocket-specific nonce prefixes so
// its counters never collide with the HTTP channel's. Must match the SDK
// (auth/sdk/src/enclave-session.ts openWebSocket / SealedWebSocketImpl).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// SetWSUpstream installs the resolver mapping a request Host to the app
// container's plaintext WebSocket endpoint ("host:port"). Until set, sealed
// WebSocket upgrades are refused with 501.
func (m *Manager) SetWSUpstream(f func(host string) (string, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wsUpstream = f
}

// isWebSocketUpgrade reports whether r is a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, tok := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

// wsSubprotocols returns the requested Sec-WebSocket-Protocol tokens in order.
func wsSubprotocols(r *http.Request) []string {
	var out []string
	for _, line := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, tok := range strings.Split(line, ",") {
			if t := strings.TrimSpace(tok); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

// hasSealedWSSubprotocol reports whether the client advertised the sealed
// marker as its first subprotocol.
func hasSealedWSSubprotocol(r *http.Request) bool {
	p := wsSubprotocols(r)
	return len(p) >= 1 && p[0] == sealedWSSubprotocol
}

// sealedWSSessionID returns the session id the client carried after the sealed
// marker (the second advertised subprotocol), or "" if absent.
func sealedWSSessionID(r *http.Request) string {
	p := wsSubprotocols(r)
	if len(p) >= 2 && p[0] == sealedWSSubprotocol {
		return p[1]
	}
	return ""
}

// acquireWS marks sid as having a live sealed WebSocket, returning false if one
// already exists (at most one per session — its counters restart at 0).
func (m *Manager) acquireWS(sid string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.activeWS[sid]; exists {
		return false
	}
	m.activeWS[sid] = struct{}{}
	return true
}

func (m *Manager) releaseWS(sid string) {
	m.mu.Lock()
	delete(m.activeWS, sid)
	m.mu.Unlock()
}

// handleSealedWebSocket terminates a sealed WebSocket from the client and
// proxies plaintext frames to the app container's WebSocket, sealing/unsealing
// each message under the session key.
func (m *Manager) handleSealedWebSocket(w http.ResponseWriter, r *http.Request) {
	sid := sealedWSSessionID(r)
	sess, ok := m.lookupByID(sid)
	if !ok {
		// Refuse the upgrade BEFORE 101 so the SDK's `ready` rejects and the
		// caller can re-establish the session.
		http.Error(w, "unknown or expired session", http.StatusUnauthorized)
		return
	}

	m.mu.RLock()
	resolver := m.wsUpstream
	m.mu.RUnlock()
	if resolver == nil {
		http.Error(w, "sealed websocket relay not configured", http.StatusNotImplemented)
		return
	}
	upstream, ok := resolver(hostKey(r.Host))
	if !ok || upstream == "" {
		http.Error(w, "no upstream for host", http.StatusBadGateway)
		return
	}

	// At most one sealed WebSocket per session (nonce-prefix reuse guard).
	if !m.acquireWS(sid) {
		http.Error(w, "a sealed websocket is already open for this session", http.StatusConflict)
		return
	}
	defer m.releaseWS(sid)

	clientWS, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{sealedWSSubprotocol}, // echo only the marker, never the id
	})
	if err != nil {
		return // Accept already wrote the failure
	}
	clientWS.SetReadLimit(sealedWSMaxMessage)
	defer clientWS.CloseNow()

	// Dial the app container's plaintext WebSocket on the same path, asserting
	// the wallet-authenticated subject so the app can attribute the caller
	// without a bearer crossing the gateway leg.
	dialCtx, cancelDial := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancelDial()
	hdr := http.Header{}
	if sess.Sub != "" {
		hdr.Set(relaySubHeader, sess.Sub)
	}
	appURL := "ws://" + upstream + r.URL.RequestURI()
	appWS, _, err := websocket.Dial(dialCtx, appURL, &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		clientWS.Close(websocket.StatusBadGateway, "upstream websocket unreachable")
		return
	}
	appWS.SetReadLimit(sealedWSMaxMessage)
	defer appWS.CloseNow()

	// AAD is fixed for the connection and identical in both directions,
	// matching the SDK's encodeAD("WS", path, sessionId).
	ad := []byte("WS:" + r.URL.RequestURI() + ":" + sess.ID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// client -> app: unseal each sealed binary frame and forward plaintext.
	errc := make(chan error, 2)
	go func() {
		var c2s uint64
		for {
			typ, data, err := clientWS.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			if typ != websocket.MessageBinary {
				clientWS.Close(websocket.StatusUnsupportedData, "binary sealed frames only")
				errc <- errors.New("non-binary client frame")
				return
			}
			env, err := decodeSealed(data)
			if err != nil {
				clientWS.Close(websocket.StatusProtocolError, "malformed sealed frame")
				errc <- err
				return
			}
			// Strict monotonic replay/reorder rejection (matches the HTTP path
			// and the SDK): accept only ctr >= next expected, then advance.
			if env.Ctr < c2s {
				clientWS.Close(websocket.StatusProtocolError, "replayed frame")
				errc <- errors.New("replayed client frame")
				return
			}
			pt, err := sess.Aead.Open(nil, makeNonce(sess.WSC2SPrefix[:], env.Ctr), env.Ct, ad)
			if err != nil {
				clientWS.Close(websocket.StatusPolicyViolation, "decrypt failed")
				errc <- err
				return
			}
			c2s = env.Ctr + 1
			if err := appWS.Write(ctx, websocket.MessageBinary, pt); err != nil {
				errc <- err
				return
			}
		}
	}()

	// app -> client: seal each app message (binary or text) as a sealed frame.
	go func() {
		var s2c uint64
		for {
			_, data, err := appWS.Read(ctx)
			if err != nil {
				errc <- err
				return
			}
			ct := sess.Aead.Seal(nil, makeNonce(sess.WSS2CPrefix[:], s2c), data, ad)
			frame := encodeSealed(sealedEnvelope{V: 1, Ctr: s2c, Ct: ct})
			s2c++
			if err := clientWS.Write(ctx, websocket.MessageBinary, frame); err != nil {
				errc <- err
				return
			}
		}
	}()

	// First side to end tears down both; map a normal close through.
	<-errc
	cancel()
	clientWS.Close(websocket.StatusNormalClosure, "")
	appWS.Close(websocket.StatusNormalClosure, "")
}
