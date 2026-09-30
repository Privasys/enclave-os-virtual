// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package tunnel serves this enclave through platform gateways over
// connections the enclave opens itself, for hosts that allow no inbound
// traffic.
//
// For each configured gateway the client keeps one connection up:
//
//	TCP to the gateway, TLS verified against public roots with ALPN
//	privasys-tunnel/1, then
//	POST /__privasys/tunnel  Upgrade: privasys-tunnel/1
//	     body {"enclave_id", "gateway"}, signed with enclaveauth (the
//	     quote-bound identity leaf from this enclave's CA)
//	101 Switching Protocols, then a yamux session in which the GATEWAY opens
//	streams.
//
// Every stream starts with a preamble (u8 version, u16 length, the client
// address the gateway saw) and then carries what a TCP connection to this
// enclave's :443 would. The client pipes it into the local Caddy listener,
// so RA-TLS, SNI routing, the platform mux and every app behave exactly as
// they do for a direct connection, and TLS still ends inside the enclave:
// the gateway and the host carry ciphertext only.
//
// Caddy then sees every tunnelled connection as coming from loopback. No
// decision in Caddy or the manager trusts an external peer's address (the
// manager's in-enclave checks look at the Caddy-to-manager hop, which is
// loopback for direct traffic too), and each stream is its own loopback
// connection, so per-connection state in Caddy stays per client.
package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/enclaveauth"
)

const (
	// ALPN is negotiated with the gateway for the tunnel connection itself.
	ALPN = "privasys-tunnel/1"
	// Path is the upgrade request path; the signature covers it.
	Path            = "/__privasys/tunnel"
	upgradeProtocol = "privasys-tunnel/1"

	preambleVersion = 1

	handshakeTimeout = 15 * time.Second
	minBackoff       = time.Second
	maxBackoff       = time.Minute
	// A session that stayed up this long resets the backoff.
	stableAfter = 30 * time.Second
)

// Config configures the client.
type Config struct {
	// Gateways are the gateway instances to hold a tunnel to, "host:port".
	// Gateways share no state, so the enclave needs one tunnel per instance.
	Gateways []string
	// ServerName is the TLS server name presented to every gateway (a name
	// the gateways' public certificate covers, e.g. tunnel.apps.example.org).
	ServerName string
	// Target is where streams are delivered: the local Caddy listener.
	Target string
	// EnclaveID is this enclave's id; the control plane checks it against
	// the identity that signed the request.
	EnclaveID string
	// Signer signs the upgrade request. Required.
	Signer enclaveauth.RequestSigner
	// TLSConfig overrides the TLS client configuration (tests); nil verifies
	// the gateways against the system roots. ServerName
	// and NextProtos are still set by the client.
	TLSConfig *tls.Config
}

// Client maintains the tunnels.
type Client struct {
	cfg Config
	log *zap.Logger

	mu     sync.Mutex
	status map[string]string
}

// New returns a client, or nil when no gateways are configured (tunnels
// disabled: the enclave is reached directly).
func New(cfg Config, log *zap.Logger) (*Client, error) {
	var gws []string
	for _, g := range cfg.Gateways {
		if g = strings.TrimSpace(g); g != "" {
			gws = append(gws, g)
		}
	}
	if len(gws) == 0 {
		return nil, nil
	}
	cfg.Gateways = gws
	if cfg.ServerName == "" {
		return nil, errors.New("tunnel: server name is required")
	}
	if cfg.EnclaveID == "" {
		return nil, errors.New("tunnel: enclave id is required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("tunnel: an enclave signer is required")
	}
	if cfg.Target == "" {
		cfg.Target = "127.0.0.1:443"
	}
	return &Client{cfg: cfg, log: log.Named("tunnel"), status: make(map[string]string)}, nil
}

// Run keeps a tunnel to every gateway until ctx ends.
func (c *Client) Run(ctx context.Context) error {
	c.log.Info("egress tunnels starting",
		zap.Strings("gateways", c.cfg.Gateways),
		zap.String("server_name", c.cfg.ServerName),
		zap.String("target", c.cfg.Target))
	var wg sync.WaitGroup
	for _, gw := range c.cfg.Gateways {
		wg.Add(1)
		go func(gw string) {
			defer wg.Done()
			c.maintain(ctx, gw)
		}(gw)
	}
	wg.Wait()
	return nil
}

// Status reports the state of each gateway tunnel.
func (c *Client) Status() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]string, len(c.status))
	for k, v := range c.status {
		out[k] = v
	}
	return out
}

func (c *Client) setStatus(gw, s string) {
	c.mu.Lock()
	c.status[gw] = s
	c.mu.Unlock()
}

func (c *Client) maintain(ctx context.Context, gw string) {
	backoff := minBackoff
	for ctx.Err() == nil {
		c.setStatus(gw, "connecting")
		start := time.Now()
		err := c.session(ctx, gw)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > stableAfter {
			backoff = minBackoff
		}
		c.setStatus(gw, "down")
		c.log.Warn("tunnel down; reconnecting", zap.String("gateway", gw),
			zap.Error(err), zap.Duration("backoff", backoff))
		// Full jitter, so a gateway restart is not met by every enclave at once.
		wait := backoff/2 + rand.N(backoff/2+1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// session opens one tunnel and serves it until it ends.
func (c *Client) session(ctx context.Context, gw string) error {
	sess, err := c.open(ctx, gw)
	if err != nil {
		return err
	}
	defer sess.Close()
	c.setStatus(gw, "up")
	c.log.Info("tunnel up", zap.String("gateway", gw))

	go func() {
		select {
		case <-ctx.Done():
			sess.Close()
		case <-sess.CloseChan():
		}
	}()
	for {
		s, err := sess.AcceptStream()
		if err != nil {
			return fmt.Errorf("session closed: %w", err)
		}
		go c.serveStream(s)
	}
}

func (c *Client) open(ctx context.Context, gw string) (*yamux.Session, error) {
	tcfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if c.cfg.TLSConfig != nil {
		tcfg = c.cfg.TLSConfig.Clone()
	}
	tcfg.ServerName = c.cfg.ServerName
	tcfg.NextProtos = []string{ALPN}

	dctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	d := tls.Dialer{NetDialer: &net.Dialer{KeepAlive: 30 * time.Second}, Config: tcfg}
	raw, err := d.DialContext(dctx, "tcp", gw)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	conn := raw.(*tls.Conn)
	if conn.ConnectionState().NegotiatedProtocol != ALPN {
		conn.Close()
		return nil, errors.New("gateway did not negotiate " + ALPN + " (tunnels not enabled there?)")
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	body, _ := json.Marshal(map[string]string{"enclave_id": c.cfg.EnclaveID, "gateway": gw})
	req, err := http.NewRequest(http.MethodPost, "https://"+c.cfg.ServerName+Path, bytes.NewReader(body))
	if err != nil {
		conn.Close()
		return nil, err
	}
	req.Header.Set("Upgrade", upgradeProtocol)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Content-Type", "application/json")
	if err := c.cfg.Signer.Sign(req, body); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sign: %w", err)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upgrade: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("gateway refused tunnel: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		// The gateway opens streams only after we answer; nothing may
		// precede the yamux session.
		conn.Close()
		return nil, errors.New("unexpected bytes after upgrade response")
	}

	ycfg := yamux.DefaultConfig()
	ycfg.EnableKeepAlive = true
	ycfg.KeepAliveInterval = 15 * time.Second
	ycfg.ConnectionWriteTimeout = 15 * time.Second
	ycfg.MaxStreamWindowSize = 1 << 20
	ycfg.LogOutput = io.Discard
	sess, err := yamux.Server(conn, ycfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return sess, nil
}

// serveStream reads the preamble and pipes the stream into the target.
func (c *Client) serveStream(s *yamux.Stream) {
	defer s.Close()
	s.SetReadDeadline(time.Now().Add(handshakeTimeout))
	var hdr [3]byte
	if _, err := io.ReadFull(s, hdr[:]); err != nil {
		return
	}
	if hdr[0] != preambleVersion {
		c.log.Warn("tunnel stream with unknown preamble version", zap.Uint8("version", hdr[0]))
		return
	}
	addr := make([]byte, binary.BigEndian.Uint16(hdr[1:]))
	if _, err := io.ReadFull(s, addr); err != nil {
		return
	}
	s.SetReadDeadline(time.Time{})

	target, err := net.DialTimeout("tcp", c.cfg.Target, 5*time.Second)
	if err != nil {
		c.log.Warn("tunnel stream: target unreachable", zap.String("target", c.cfg.Target), zap.Error(err))
		return
	}
	defer target.Close()
	c.log.Debug("tunnel stream", zap.String("client", string(addr)))

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(target, s)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(s, target)
		s.Close() // half-close: FIN to the gateway
		done <- struct{}{}
	}()
	<-done
	<-done
}
