package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
	"go.uber.org/zap"
)

// identityIssuer is a test identity provider: it serves its keys and signs
// tokens for a verifier the test hands to a Server.
type identityIssuer struct {
	key    *ecdsa.PrivateKey
	issuer string
}

func newIdentityServer(t *testing.T) (*Server, *identityIssuer) {
	t.Helper()
	trustedtime.Install(trustedtime.HostClock{})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
		"x": b64(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": b64(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}}}
	iss := &identityIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"jwks_uri": iss.issuer + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(jwks) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	iss.issuer = srv.URL
	v, err := auth.NewVerifier(&auth.OIDCConfig{Issuer: srv.URL, Audience: "enclave-os-virtual"}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	s := surfServer(t, webManifest)
	s.verifier = v
	return s, iss
}

func (i *identityIssuer) token(t *testing.T, sub, aud string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{"iss": i.issuer, "sub": sub, "aud": aud, "exp": float64(time.Now().Add(10 * time.Minute).Unix())}
	for k, v := range extra {
		claims[k] = v
	}
	b64 := base64.RawURLEncoding.EncodeToString
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "at+jwt", "kid": "k1"})
	body, _ := json.Marshal(claims)
	input := b64(hdr) + "." + b64(body)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig)
}

var withProfile = map[string]any{"email": "ada@example.com", "name": "Zoë O'Neil"}

const encodedName = "Zo%C3%AB%20O%27Neil"

func directRequest(token string) *http.Request {
	r := clearReq("GET", "/api/v1/me", map[string]string{"X-Privasys-Email": "spoofed@example.com", "X-Privasys-Name": "spoofed"})
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set(edgeHeader, "direct")
	return r
}

func sealedRequest(sub, token string) *http.Request {
	r := httptest.NewRequest("GET", "https://"+surfHost+"/api/v1/me", nil)
	r.Header.Set(TransportHeader, TransportSealed)
	if sub != "" {
		r.Header.Set("X-Privasys-Sub", sub)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func wantProfile(t *testing.T, r *http.Request, email, name string) {
	t.Helper()
	if got := r.Header.Get(emailHeader); got != email {
		t.Errorf("email = %q, want %q", got, email)
	}
	if got := r.Header.Get(nameHeader); got != name {
		t.Errorf("name = %q, want %q", got, name)
	}
}

// A direct name: the token's claims reach the app, the token does not, and a
// token without claims (one minted by refresh) yields the subject alone.
func TestDirectAssertsTheTokensProfile(t *testing.T) {
	s, iss := newIdentityServer(t)

	r := directRequest(iss.token(t, "s1", surfHost, withProfile))
	if !s.serveDirect(httptest.NewRecorder(), r) {
		t.Fatal("refused")
	}
	wantProfile(t, r, "ada@example.com", encodedName)
	if r.Header.Get("X-Privasys-Sub") != "s1" || r.Header.Get("Authorization") != "" {
		t.Fatalf("sub %q, authorization %q", r.Header.Get("X-Privasys-Sub"), r.Header.Get("Authorization"))
	}

	r = directRequest(iss.token(t, "s1", surfHost, nil))
	if !s.serveDirect(httptest.NewRecorder(), r) {
		t.Fatal("refused")
	}
	wantProfile(t, r, "", "")
	if r.Header.Get("X-Privasys-Sub") != "s1" {
		t.Fatal("the subject stands without a profile")
	}

	// Anonymous: an inbound profile never reaches the app.
	r = directRequest("")
	if !s.serveDirect(httptest.NewRecorder(), r) {
		t.Fatal("refused")
	}
	wantProfile(t, r, "", "")
}

func TestSealedAssertsTheInnerBearersProfile(t *testing.T) {
	s, iss := newIdentityServer(t)
	own := iss.token(t, "s1", surfHost, withProfile)

	t.Run("session subject, same person, any audience", func(t *testing.T) {
		tok := iss.token(t, "s1", "some-client", withProfile)
		r := s.assertSealedIdentity(sealedRequest("s1", tok))
		wantProfile(t, r, "ada@example.com", encodedName)
		if r.Header.Get("Authorization") != "Bearer "+tok {
			t.Fatal("the inner bearer stays during the transition")
		}
		if got := s.callerIdentity(r); got != "s1" {
			t.Fatalf("a voucher subject stays a payer, got %q", got)
		}
	})
	t.Run("session subject, another person", func(t *testing.T) {
		r := s.assertSealedIdentity(sealedRequest("s1", iss.token(t, "s2", surfHost, withProfile)))
		wantProfile(t, r, "", "")
		if r.Header.Get("X-Privasys-Sub") != "s1" {
			t.Fatal("the session's subject stands")
		}
	})
	t.Run("session subject, refreshed token", func(t *testing.T) {
		r := s.assertSealedIdentity(sealedRequest("s1", iss.token(t, "s1", surfHost, nil)))
		wantProfile(t, r, "", "")
	})
	t.Run("no session subject, token for this app", func(t *testing.T) {
		r := s.assertSealedIdentity(sealedRequest("", own))
		wantProfile(t, r, "ada@example.com", encodedName)
		if r.Header.Get("X-Privasys-Sub") != "s1" {
			t.Fatal("the bearer supplies the subject")
		}
		if got := s.callerIdentity(r); got != "" {
			t.Fatalf("a subject from a bearer the app may hold must never pay, got %q", got)
		}
	})
	t.Run("no session subject, token for another app", func(t *testing.T) {
		r := s.assertSealedIdentity(sealedRequest("", iss.token(t, "s1", "other.example.com", withProfile)))
		wantProfile(t, r, "", "")
		if r.Header.Get("X-Privasys-Sub") != "" {
			t.Fatal("no identity from a token for another app")
		}
	})
	t.Run("invalid bearer", func(t *testing.T) {
		r := s.assertSealedIdentity(sealedRequest("", "not.a.token"))
		wantProfile(t, r, "", "")
		if r.Header.Get("X-Privasys-Sub") != "" || r.Header.Get("Authorization") != "Bearer not.a.token" {
			t.Fatal("an invalid bearer adds nothing and is left for the app to judge")
		}
	})
}

func TestAssertProfileLeavesOutWhatAHeaderCannotCarry(t *testing.T) {
	h := http.Header{}
	assertProfile(h, auth.AppUser{Email: "a@example.com\r\nX-Evil: 1", Name: "a\r\nb"})
	if h.Get(emailHeader) != "" {
		t.Fatalf("email = %q", h.Get(emailHeader))
	}
	if h.Get(nameHeader) != "a%0D%0Ab" {
		t.Fatalf("name = %q", h.Get(nameHeader))
	}
}
