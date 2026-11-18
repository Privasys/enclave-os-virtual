package sessionrelay

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bootstrapHost posts one unauthenticated session bootstrap for host and
// returns the status code.
func bootstrapHost(t *testing.T, h http.Handler, host string) int {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(initRequest{SDKPub: base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())})
	r := httptest.NewRequest(http.MethodPost, initPath, strings.NewReader(string(body)))
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// The Host is client-supplied and bootstrap needs no credential, so a Host
// this manager does not serve must leave nothing behind.
func TestBootstrapUnknownHostLeavesNoKey(t *testing.T) {
	m := NewManager()
	m.SetKnownHost(func(host string) bool { return host == "app.example" })
	h := m.Middleware(http.NotFoundHandler())

	for i := 0; i < 100; i++ {
		if code := bootstrapHost(t, h, fmt.Sprintf("unknown-%d.example", i)); code != http.StatusNotFound {
			t.Fatalf("unknown host %d: status %d, want 404", i, code)
		}
	}
	if n := len(m.encKeys); n != 0 {
		t.Fatalf("%d identity keys after unknown hosts, want 0", n)
	}
	if n := len(m.sessions); n != 0 {
		t.Fatalf("%d sessions after unknown hosts, want 0", n)
	}
}

// A loaded app keeps one key however its Host is spelled.
func TestBootstrapKnownHostHoldsOneKey(t *testing.T) {
	m := NewManager()
	m.SetKnownHost(func(host string) bool { return host == "app.example" })
	h := m.Middleware(http.NotFoundHandler())

	for _, host := range []string{"app.example", "APP.example", "app.example:443"} {
		if code := bootstrapHost(t, h, host); code != http.StatusOK {
			t.Fatalf("host %q: status %d, want 200", host, code)
		}
	}
	if n := len(m.encKeys); n != 1 {
		t.Fatalf("%d identity keys, want 1", n)
	}
}

// An installed key keeps serving its Host once the app is no longer known.
func TestBootstrapInstalledKeyIsServed(t *testing.T) {
	m := NewManager()
	m.SetKnownHost(func(string) bool { return false })
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetEncStaticKeyForHost("app.example", k); err != nil {
		t.Fatal(err)
	}
	if code := bootstrapHost(t, m.Middleware(http.NotFoundHandler()), "app.example"); code != http.StatusOK {
		t.Fatalf("status %d, want 200", code)
	}
}
