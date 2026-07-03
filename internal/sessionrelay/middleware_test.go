// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessionrelay

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testSession installs a ready-made session (bypassing the bootstrap
// ceremony) and returns it together with the SDK-side seal helper.
func testSession(t *testing.T, m *Manager, sub string) (*Session, func(method, path string, pt []byte, ctr uint64) []byte) {
	t.Helper()
	sdkScalar := sha256.Sum256([]byte("privasys-mw-test-sdk/v1"))
	encScalar := sha256.Sum256([]byte("privasys-mw-test-enc/v1"))
	curve := ecdh.P256()
	sdkPriv, err := curve.NewPrivateKey(sdkScalar[:])
	if err != nil {
		t.Fatalf("sdk scalar: %v", err)
	}
	encPriv, err := curve.NewPrivateKey(encScalar[:])
	if err != nil {
		t.Fatalf("enc scalar: %v", err)
	}
	shared, err := encPriv.ECDH(sdkPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	sidRaw := make([]byte, 16)
	if _, err := rand.Read(sidRaw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sid := base64.RawURLEncoding.EncodeToString(sidRaw)
	sess, err := buildSession(sid, sidRaw, shared, time.Hour, time.Now)
	if err != nil {
		t.Fatalf("buildSession: %v", err)
	}
	sess.Sub = sub
	m.mu.Lock()
	m.sessions[sid] = sess
	m.mu.Unlock()

	seal := func(method, path string, pt []byte, ctr uint64) []byte {
		ad := []byte(strings.ToUpper(method) + ":" + path + ":" + sid)
		ct := sess.Aead.Seal(nil, makeNonce(sess.C2SPrefix[:], ctr), pt, ad)
		return encodeSealed(sealedEnvelope{V: 1, Ctr: ctr, Ct: ct})
	}
	return sess, seal
}

// TestSealedGETViaHeaderEnvelope verifies that a bodyless method carries
// its envelope in X-Privasys-Sealed (browser fetch refuses GET bodies)
// and still reaches the inner handler with the real method.
func TestSealedGETViaHeaderEnvelope(t *testing.T) {
	m := NewManager()

	var gotMethod, gotSub, gotEnvelopeHdr string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotSub = r.Header.Get(relaySubHeader)
		gotEnvelopeHdr = r.Header.Get(sealedEnvelopeHeader)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tools":[]}`))
	})
	srv := httptest.NewServer(m.Middleware(inner))
	defer srv.Close()

	sess, seal := testSession(t, m, "user-123")
	env := seal("GET", "/api/v1/me/tools", nil, 0)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/me/tools", nil)
	req.Header.Set("Content-Type", sealedContentType)
	req.Header.Set("Authorization", authScheme+" "+sess.ID)
	req.Header.Set(sealedEnvelopeHeader, base64.RawURLEncoding.EncodeToString(env))
	// A spoofed identity must not survive the relay.
	req.Header.Set(relaySubHeader, "attacker")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("inner method = %q, want GET", gotMethod)
	}
	if gotSub != "user-123" {
		t.Fatalf("inner %s = %q, want the session sub", relaySubHeader, gotSub)
	}
	if gotEnvelopeHdr != "" {
		t.Fatalf("inner request still carries %s", sealedEnvelopeHeader)
	}

	// The response must come back sealed.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/privasys-sealed") {
		t.Fatalf("response content-type = %q, want sealed", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	respEnv, err := decodeSealed(body)
	if err != nil {
		t.Fatalf("decode sealed response: %v", err)
	}
	ad := []byte("GET:/api/v1/me/tools:" + sess.ID)
	pt, err := sess.Aead.Open(nil, makeNonce(sess.S2CPrefix[:], respEnv.Ctr), respEnv.Ct, ad)
	if err != nil {
		t.Fatalf("open sealed response: %v", err)
	}
	if string(pt) != `{"tools":[]}` {
		t.Fatalf("response plaintext = %q", pt)
	}
}

// TestRelaySubInjection covers the identity header rules on the sealed
// POST path: vouched sessions assert their sub, sub-less sessions assert
// nothing, and inbound spoofs are stripped everywhere (incl. passthrough).
func TestRelaySubInjection(t *testing.T) {
	m := NewManager()

	var gotSub string
	var sawHeader bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSub = r.Header.Get(relaySubHeader)
		_, sawHeader = r.Header[http.CanonicalHeaderKey(relaySubHeader)]
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(m.Middleware(inner))
	defer srv.Close()

	post := func(sess *Session, env []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/x", strings.NewReader(string(env)))
		req.Header.Set("Content-Type", sealedContentType)
		req.Header.Set("Authorization", authScheme+" "+sess.ID)
		req.Header.Set(relaySubHeader, "attacker")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}

	// Vouched session: sub asserted.
	vouched, sealV := testSession(t, m, "user-123")
	post(vouched, sealV("POST", "/x", []byte(`{}`), 0))
	if gotSub != "user-123" {
		t.Fatalf("vouched sub = %q, want user-123", gotSub)
	}

	// Sub-less (FIDO2-ceremony) session: header absent entirely.
	anon, sealA := testSession(t, m, "")
	post(anon, sealA("POST", "/x", []byte(`{}`), 0))
	if sawHeader {
		t.Fatalf("sub-less session leaked %s = %q", relaySubHeader, gotSub)
	}

	// Plaintext passthrough: spoof stripped.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/plain", nil)
	req.Header.Set(relaySubHeader, "attacker")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if sawHeader {
		t.Fatalf("passthrough leaked %s = %q", relaySubHeader, gotSub)
	}
}
