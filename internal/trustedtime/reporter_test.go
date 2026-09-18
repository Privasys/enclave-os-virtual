package trustedtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPReporterReceipt(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := MonitorConfig{
		EnclaveID:    "enc-1",
		MonitorKey:   base64.RawURLEncoding.EncodeToString(pub),
		MonitorKeyID: KeyID(pub),
	}
	var signWith = priv
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in incidentBody
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		if raw, err := base64.RawURLEncoding.DecodeString(in.Nonce); err != nil || len(raw) != 32 {
			http.Error(w, "nonce", 400)
			return
		}
		sig := ed25519.Sign(signWith, ReceiptSignedBytes(in.EnclaveID, in.Nonce, "inc-7"))
		_ = json.NewEncoder(w).Encode(receipt{IncidentID: "inc-7", Nonce: in.Nonce, KeyID: cfg.MonitorKeyID, Sig: base64.RawURLEncoding.EncodeToString(sig)})
	}))
	defer srv.Close()
	cfg.IncidentURL = srv.URL
	rep := &HTTPReporter{Client: srv.Client()}
	if err := rep.Report(context.Background(), cfg, Incident{Reason: ReasonHostBehindFloor}); err != nil {
		t.Fatal(err)
	}
	_, signWith, _ = ed25519.GenerateKey(rand.Reader)
	if err := rep.Report(context.Background(), cfg, Incident{Reason: ReasonHostBehindFloor}); err == nil {
		t.Fatal("want a receipt under another key refused")
	}
}

func TestLocalHandler(t *testing.T) {
	h := LocalHandler(sourceFunc(func() (time.Time, error) { return t0, nil }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, LocalPath, nil))
	var body localReply
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body.UnixMs != t0.UnixMilli() {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	h = LocalHandler(sourceFunc(func() (time.Time, error) { return time.Time{}, ErrUnavailable }))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, LocalPath, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

type sourceFunc func() (time.Time, error)

func (f sourceFunc) Now() (time.Time, error) { return f() }

// The default reporter must reach the monitor enclave through the gateway's
// splice path: it advertises the RA-TLS ALPN, and it accepts a certificate
// that is not web PKI (the receipt signature is the authentication).
func TestHTTPReporterSplicesWithRATLSALPN(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := MonitorConfig{
		EnclaveID:    "enc-1",
		MonitorKey:   base64.RawURLEncoding.EncodeToString(pub),
		MonitorKeyID: KeyID(pub),
	}
	var offered []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var in incidentBody
		_ = json.NewDecoder(r.Body).Decode(&in)
		sig := ed25519.Sign(priv, ReceiptSignedBytes(in.EnclaveID, in.Nonce, "inc-1"))
		_ = json.NewEncoder(w).Encode(receipt{IncidentID: "inc-1", Nonce: in.Nonce, KeyID: cfg.MonitorKeyID, Sig: base64.RawURLEncoding.EncodeToString(sig)})
	}))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		offered = h.SupportedProtos
		return nil, nil
	}}
	srv.StartTLS() // self-signed: no web PKI chain
	defer srv.Close()
	cfg.IncidentURL = srv.URL
	if err := NewHTTPReporter().Report(context.Background(), cfg, Incident{Reason: ReasonHostBehindFloor}); err != nil {
		t.Fatal(err)
	}
	if len(offered) == 0 || offered[0] != RATLSALPN {
		t.Fatalf("offered ALPN %q, want %q first (the gateway would terminate, not splice)", offered, RATLSALPN)
	}
}
