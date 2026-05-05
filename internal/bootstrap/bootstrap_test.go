package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_HappyPath(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPath := writeServiceKeyJSON(t, dir, priv, "test-key", "test-user")

	gotIdpAud := ""
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				http.Error(w, "wrong grant_type", http.StatusBadRequest)
				return
			}
			gotIdpAud = r.Form.Get("scope")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 900,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()

	gotBootstrapAuth := ""
	gotBootstrapHost := ""
	mgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/enclave/bootstrap" {
			http.NotFound(w, r)
			return
		}
		gotBootstrapAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		var in bootstrapRequest
		_ = json.Unmarshal(body, &in)
		gotBootstrapHost = in.Host
		_ = json.NewEncoder(w).Encode(bootstrapResponse{
			CACert:     "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----\n",
			CAKey:      "-----BEGIN PRIVATE KEY-----\nMIICdQ==\n-----END PRIVATE KEY-----\n",
			ManagerEnv: map[string]string{"NEW_KEY": "new-value", "OIDC_ISSUER": "should-not-overwrite"},
		})
	}))
	defer mgmt.Close()

	envPath := filepath.Join(dataDir, "manager.env")
	if err := os.WriteFile(envPath, []byte("OIDC_ISSUER=existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Run(context.Background(), Config{
		DataDir:        dataDir,
		ManagerEnvPath: envPath,
		ServiceKeyPath: keyPath,
		IDPIssuer:      idp.URL,
		IDPAudience:    "privasys-platform",
		ManagementURL:  mgmt.URL,
		Hostname:       "ai-gpu-test-1",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.Contains(gotIdpAud, "audience:privasys-platform") {
		t.Errorf("scope missing audience:privasys-platform, got %q", gotIdpAud)
	}
	if gotBootstrapAuth != "Bearer test-access-token" {
		t.Errorf("bootstrap Authorization = %q, want Bearer test-access-token", gotBootstrapAuth)
	}
	if gotBootstrapHost != "ai-gpu-test-1" {
		t.Errorf("bootstrap host = %q, want ai-gpu-test-1", gotBootstrapHost)
	}

	if b, err := os.ReadFile(filepath.Join(dataDir, "ca.crt")); err != nil || !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Errorf("ca.crt not written or wrong contents: err=%v body=%q", err, string(b))
	}
	st, _ := os.Stat(filepath.Join(dataDir, "ca.key"))
	if st == nil || st.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode = %v, want 0600", st)
	}

	envOut, _ := os.ReadFile(envPath)
	if !strings.Contains(string(envOut), "OIDC_ISSUER=existing") {
		t.Errorf("merge clobbered existing key: %s", envOut)
	}
	if !strings.Contains(string(envOut), "NEW_KEY=new-value") {
		t.Errorf("merge missed new key: %s", envOut)
	}
}

func TestRun_Idempotent(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	_ = os.MkdirAll(dataDir, 0o755)
	caPath := filepath.Join(dataDir, "ca.crt")
	_ = os.WriteFile(caPath, []byte("preexisting"), 0o644)

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	err := Run(context.Background(), Config{
		DataDir:        dataDir,
		ManagerEnvPath: filepath.Join(dataDir, "manager.env"),
		ServiceKeyPath: "/nonexistent",
		IDPIssuer:      srv.URL,
		ManagementURL:  srv.URL,
		Hostname:       "host",
	})
	if err != nil {
		t.Fatalf("Run idempotent: %v", err)
	}
	if called {
		t.Errorf("Run made network calls despite ca.crt existing")
	}
	b, _ := os.ReadFile(caPath)
	if string(b) != "preexisting" {
		t.Errorf("ca.crt clobbered: %q", b)
	}
}

func TestRun_BootstrapEndpointRejects(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	_ = os.MkdirAll(dataDir, 0o755)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPath := writeServiceKeyJSON(t, dir, priv, "k", "u")

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok"})
	}))
	defer idp.Close()
	mgmt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"already bootstrapped"}`, http.StatusConflict)
	}))
	defer mgmt.Close()

	err := Run(context.Background(), Config{
		DataDir: dataDir, ManagerEnvPath: filepath.Join(dataDir, "manager.env"),
		ServiceKeyPath: keyPath, IDPIssuer: idp.URL, ManagementURL: mgmt.URL, Hostname: "h",
	})
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Errorf("expected 409 error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "ca.crt")); !os.IsNotExist(err) {
		t.Errorf("ca.crt should not have been written on rejection")
	}
}

// writeServiceKeyJSON marshals priv as a PKCS#1 PEM, wraps it in the
// service-account key JSON layout, and returns the path.
func writeServiceKeyJSON(t *testing.T, dir string, priv *rsa.PrivateKey, kid, uid string) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	body, _ := json.Marshal(serviceKeyFile{
		Type: "serviceaccount", KeyID: kid, Key: string(pemBytes), UserID: uid,
	})
	path := filepath.Join(dir, "key.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
