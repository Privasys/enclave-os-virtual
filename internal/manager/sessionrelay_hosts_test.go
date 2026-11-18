package manager

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// A session bootstrap is answered only for the Host of a loaded app.
func TestSessionBootstrapNeedsALoadedApp(t *testing.T) {
	log := zap.NewNop()
	s := New(Config{}, log, launcher.New(launcher.Config{}, log), nil)
	s.RegisterAppHost("app.example", "127.0.0.1:1")
	h := s.sessionRelay.Middleware(http.NotFoundHandler())

	bootstrap := func(host string) int {
		t.Helper()
		k, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]string{"sdk_pub": base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())})
		r := httptest.NewRequest(http.MethodPost, "/__privasys/session-bootstrap", strings.NewReader(string(body)))
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := bootstrap("app.example:443"); code != http.StatusOK {
		t.Fatalf("loaded app: status %d, want 200", code)
	}
	if code := bootstrap("not-an-app.example"); code != http.StatusNotFound {
		t.Fatalf("unknown host: status %d, want 404", code)
	}
	if pub := s.sessionRelay.EncStaticPubForHost("not-an-app.example"); pub != nil {
		t.Fatal("an unknown host was given an identity key")
	}
}
