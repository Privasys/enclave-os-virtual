package manager

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTakeWSBearerKeepsTheAppsProtocols(t *testing.T) {
	h := http.Header{}
	h.Add(wsProtocolHeader, "privasys.v1, privasys.bearer.tok")
	h.Add(wsProtocolHeader, "graphql-ws")
	token, ok := takeWSBearer(h)
	if !ok || token != "tok" {
		t.Fatalf("token %q ok %v", token, ok)
	}
	if got := h.Values(wsProtocolHeader); len(got) != 1 || got[0] != "graphql-ws" {
		t.Fatalf("left for the app: %q", got)
	}

	h = http.Header{}
	h.Set(wsProtocolHeader, "privasys.v1, privasys.bearer.tok")
	if _, ok := takeWSBearer(h); !ok || h.Get(wsProtocolHeader) != "" {
		t.Fatalf("ok %v, left %q", ok, h.Get(wsProtocolHeader))
	}

	h = http.Header{}
	h.Set(wsProtocolHeader, "graphql-ws")
	if _, ok := takeWSBearer(h); ok || h.Get(wsProtocolHeader) != "graphql-ws" {
		t.Fatal("a socket without the runtime's protocols is left alone")
	}
}

func wsRequest(protocols string) *http.Request {
	r := directRequest("")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set(wsProtocolHeader, protocols)
	return r
}

// A WebSocket on a direct name carries the token as a subprotocol: the app
// gets the identity, never the token.
func TestDirectWebSocketTokenIsTakenOut(t *testing.T) {
	s, iss := newIdentityServer(t)

	r, ok := s.serveDirect(httptest.NewRecorder(), wsRequest("privasys.v1, privasys.bearer."+iss.token(t, "s1", surfHost, withProfile)))
	if !ok {
		t.Fatal("refused")
	}
	if r.Header.Get("X-Privasys-Sub") != "s1" || r.Header.Get(wsProtocolHeader) != "" {
		t.Fatalf("sub %q, protocols %q", r.Header.Get("X-Privasys-Sub"), r.Header.Get(wsProtocolHeader))
	}
	wantProfile(t, r, "ada@example.com", encodedName)
	if r.Context().Value(wsProtocolKey{}) == nil {
		t.Fatal("the handshake is not marked to answer privasys.v1")
	}
	if _, ok := r.Context().Deadline(); !ok {
		t.Fatal("the socket does not end with the token")
	}

	rec := httptest.NewRecorder()
	if _, ok := s.serveDirect(rec, wsRequest("privasys.v1, privasys.bearer.forged")); ok || rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged token: ok %v, code %d", ok, rec.Code)
	}

	// The subprotocols mean nothing on a request that is not a WebSocket.
	r = directRequest("")
	r.Header.Set(wsProtocolHeader, "privasys.v1, privasys.bearer."+iss.token(t, "s1", surfHost, nil))
	if r, ok = s.serveDirect(httptest.NewRecorder(), r); !ok || r.Header.Get("X-Privasys-Sub") != "" {
		t.Fatal("a plain request took its identity from a subprotocol")
	}
}

// Through the app proxy: the handshake answers privasys.v1 when the app
// picked no protocol, and the socket closes when the token expires.
func TestDirectWebSocketHandshakeAndExpiry(t *testing.T) {
	s, iss := newIdentityServer(t)

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Privasys-Sub") != "s1" || strings.Contains(r.Header.Get(wsProtocolHeader), "bearer") {
			http.Error(w, "bad identity", http.StatusBadRequest)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		brw.Flush()
		io.Copy(io.Discard, conn) // held open until the runtime closes it
	}))
	defer app.Close()
	appURL, _ := url.Parse(app.URL)
	proxy := &httputil.ReverseProxy{
		Rewrite:        func(pr *httputil.ProxyRequest) { pr.SetURL(appURL); pr.Out.Host = pr.In.Host },
		ModifyResponse: func(resp *http.Response) error { answerWSProtocol(resp); return nil },
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(edgeHeader, "direct")
		r, ok := s.serveDirect(w, r)
		if !ok {
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()

	// The verifier compares whole seconds, so this token lives 1 to 2 s.
	token := iss.token(t, "s1", surfHost, map[string]any{"exp": float64(time.Now().Add(2 * time.Second).Unix())})
	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: " + surfHost + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Protocol: privasys.v1, privasys.bearer." + token + "\r\n\r\n"))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get(wsProtocolHeader); got != wsProtocol {
		t.Fatalf("answered protocol %q", got)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("the socket outlived its token: %v", err)
	}
	if waited := time.Since(start); waited > 3*time.Second {
		t.Fatalf("closed after %v", waited)
	}
}
