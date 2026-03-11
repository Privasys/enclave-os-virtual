package oidcbootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// TestGenerateAndMarshalKey verifies that a generated ECDSA P-256 key can be
// serialised to SPKI PEM → base64 (the format Zitadel expects).
func TestGenerateAndMarshalKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})
	b64 := base64.StdEncoding.EncodeToString(pemBlock)

	if len(b64) == 0 {
		t.Fatal("base64 PEM must not be empty")
	}

	// Round-trip: base64 → PEM → DER → public key.
	pemBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("PEM decode failed")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse SPKI: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected *ecdsa.PublicKey")
	}
	if ecPub.Curve != elliptic.P256() {
		t.Fatal("expected P-256 curve")
	}
}

// TestFingerprint verifies the SHA-256 fingerprint format.
func TestFingerprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fp := Fingerprint(key)
	if len(fp) != 64 {
		t.Fatalf("fingerprint should be 64 hex chars, got %d", len(fp))
	}

	// Verify it matches a manual computation.
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	h := sha256.Sum256(spki)
	expected := fmt.Sprintf("%x", h)
	if fp != expected {
		t.Fatalf("fingerprint mismatch: %s vs %s", fp, expected)
	}
}

// TestBootstrapEndToEnd tests the full bootstrap flow against a mock Zitadel server.
func TestBootstrapEndToEnd(t *testing.T) {
	// Mock Zitadel: AddKey endpoint + token endpoint.
	mux := http.NewServeMux()

	mux.HandleFunc("/v2/users/test-sa-id/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Verify auth header.
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-manager-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Read and verify body.
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req["type"] != "KEY_TYPE_JSON" {
			t.Errorf("expected KEY_TYPE_JSON, got %s", req["type"])
		}
		if req["publicKey"] == "" {
			t.Error("publicKey must not be empty")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"keyId": "mock-key-123"}`)
	})

	mux.HandleFunc("/oauth/v2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("unexpected grant_type: %s", r.Form.Get("grant_type"))
		}

		assertion := r.Form.Get("assertion")
		if assertion == "" {
			t.Error("assertion must not be empty")
		}
		// Verify JWT structure (3 parts).
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Errorf("expected 3 JWT parts, got %d", len(parts))
		}

		// Decode and verify header.
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var header map[string]string
		json.Unmarshal(headerJSON, &header)
		if header["alg"] != "ES256" {
			t.Errorf("expected ES256, got %s", header["alg"])
		}
		if header["kid"] != "mock-key-123" {
			t.Errorf("expected kid=mock-key-123, got %s", header["kid"])
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "mock-access-token-xyz", "expires_in": 43200}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	log := zaptest.NewLogger(t)
	mgr := NewManager(log)

	cfg := Config{
		Issuer:           server.URL,
		ServiceAccountID: "test-sa-id",
		ProjectID:        "test-project-id",
	}

	err := mgr.Bootstrap(server.URL+"/verify", cfg, "test-manager-token")
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}

	// Verify token is available.
	token := mgr.Token(server.URL + "/verify")
	if token != "mock-access-token-xyz" {
		t.Fatalf("expected mock-access-token-xyz, got %s", token)
	}
}

// TestTokenRefresh verifies the refresh loop works.
func TestTokenRefresh(t *testing.T) {
	callCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/users/sa/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keyId": "k1"}`)
	})
	mux.HandleFunc("/oauth/v2/token", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "token-%d", "expires_in": 1}`, callCount)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	log := zaptest.NewLogger(t)
	mgr := NewManager(log)

	cfg := Config{Issuer: server.URL, ServiceAccountID: "sa"}
	if err := mgr.Bootstrap("srv", cfg, "mgr-tok"); err != nil {
		t.Fatal(err)
	}

	// Force the token to appear expired.
	mgr.mu.RLock()
	state := mgr.states["srv"]
	mgr.mu.RUnlock()
	state.mu.Lock()
	state.expiresAt = time.Now().Add(-1 * time.Second)
	state.mu.Unlock()

	// Token() should trigger an inline refresh.
	tok := mgr.Token("srv")
	if tok != "token-2" {
		t.Fatalf("expected token-2 after refresh, got %s", tok)
	}
}
