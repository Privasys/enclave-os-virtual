// Copyright (c) Privasys. All rights reserved.

package manager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
)

// stillNTS answers every quorum with a fixed time.
type stillNTS struct{ t time.Time }

func (n stillNTS) Quorum(context.Context, time.Time) (trustedtime.Sample, error) {
	return trustedtime.Sample{Time: n.t, Servers: []string{"a", "b"}}, nil
}

func clockServer(t *testing.T, now time.Time) *Server {
	t.Helper()
	c, err := trustedtime.New(trustedtime.Options{
		EnclaveID: "enc-1",
		Host:      func() time.Time { return now },
		NTS:       stillNTS{now},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{log: zap.NewNop(), cfg: Config{Clock: c}}
}

func withRole(r *http.Request, role string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authResultKey, &auth.AuthResult{Role: role}))
}

func TestClockConfigAndPoll(t *testing.T) {
	now := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	s := clockServer(t, now)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := trustedtime.MonitorConfig{
		EnclaveID:     "enc-1",
		MonitorKey:    base64.RawURLEncoding.EncodeToString(pub),
		MonitorKeyID:  trustedtime.KeyID(pub),
		IncidentURL:   "https://monitor.example/api/v1/clock/incidents",
		ConfigVersion: 2,
	}
	body, _ := json.Marshal(cfg)

	// Polls are refused until a monitor is pinned.
	rec := httptest.NewRecorder()
	s.handleClockPoll(rec, httptest.NewRequest(http.MethodPost, "/api/v1/clock/poll", bytes.NewReader([]byte(`{"enclave_id":"enc-1"}`))))
	if rec.Code != http.StatusConflict {
		t.Fatalf("unconfigured poll: %d", rec.Code)
	}

	// The monitoring role cannot pin a monitor.
	rec = httptest.NewRecorder()
	s.handleClockConfig(rec, withRole(httptest.NewRequest(http.MethodPut, "/api/v1/clock/config", bytes.NewReader(body)), "monitoring"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("monitoring role: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.handleClockConfig(rec, withRole(httptest.NewRequest(http.MethodPut, "/api/v1/clock/config", bytes.NewReader(body)), "manager"))
	if rec.Code != http.StatusOK {
		t.Fatalf("config: %d %s", rec.Code, rec.Body)
	}
	// The same version again is stale.
	rec = httptest.NewRecorder()
	s.handleClockConfig(rec, withRole(httptest.NewRequest(http.MethodPut, "/api/v1/clock/config", bytes.NewReader(body)), "manager"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale config: %d", rec.Code)
	}

	// A signed poll in sync with the host.
	tMs := now.UnixMilli()
	sig := ed25519.Sign(priv, trustedtime.PollSignedBytes("enc-1", tMs, 7))
	poll, _ := json.Marshal(trustedtime.PollRequest{EnclaveID: "enc-1", TMs: tMs, Seq: 7, KeyID: cfg.MonitorKeyID, Sig: base64.RawURLEncoding.EncodeToString(sig)})
	rec = httptest.NewRecorder()
	s.handleClockPoll(rec, httptest.NewRequest(http.MethodPost, "/api/v1/clock/poll", bytes.NewReader(poll)))
	if rec.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
	var reply map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &reply)
	for _, k := range []string{"enclave_id", "runtime", "host_time_ms", "trusted_time_ms", "floor_ms", "flagged", "reason", "verdict", "nts", "config_key_id"} {
		if _, ok := reply[k]; !ok {
			t.Fatalf("reply lacks %q: %s", k, rec.Body)
		}
	}
	if reply["verdict"] != "in_sync" || reply["runtime"] != "virtual" || reply["config_key_id"] != cfg.MonitorKeyID {
		t.Fatalf("reply: %s", rec.Body)
	}

	// A forged signature is refused.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	sig = ed25519.Sign(other, trustedtime.PollSignedBytes("enc-1", tMs, 8))
	poll, _ = json.Marshal(trustedtime.PollRequest{EnclaveID: "enc-1", TMs: tMs, Seq: 8, KeyID: cfg.MonitorKeyID, Sig: base64.RawURLEncoding.EncodeToString(sig)})
	rec = httptest.NewRecorder()
	s.handleClockPoll(rec, httptest.NewRequest(http.MethodPost, "/api/v1/clock/poll", bytes.NewReader(poll)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("forged poll: %d", rec.Code)
	}
}
