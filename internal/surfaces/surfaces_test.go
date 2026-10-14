package surfaces

import (
	"encoding/base64"
	"strings"
	"testing"
)

const manifest = `{
  "tools": [{"name": "x", "endpoint": "/api/v1/paid"}],
  "surfaces": {
    "static": ["/", "/assets/", "/favicon.svg"],
    "public": [
      {"method": "get", "path": "/api/v1/public/"},
      {"method": "POST", "path": "/api/v1/webhooks/stripe", "headers": ["stripe-signature"]},
      {"method": "GET", "path": "/.well-known/openid-federation"}
    ],
    "cors": "*",
    "limits": {"rps": 20, "burst": 100}
  }
}`

func TestParseRawAndBase64(t *testing.T) {
	for name, raw := range map[string]string{
		"raw":    manifest,
		"base64": base64.StdEncoding.EncodeToString([]byte(manifest)),
	} {
		s, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s == nil || len(s.Static) != 3 || len(s.Public) != 3 {
			t.Fatalf("%s: parsed %+v", name, s)
		}
		if s.Public[0].Method != "GET" || s.Public[1].Headers[0] != "Stripe-Signature" {
			t.Fatalf("%s: not canonicalised: %+v", name, s.Public)
		}
		if !s.OpenCORS() || s.RPS() != 20 || s.Burst() != 100 {
			t.Fatalf("%s: cors/limits: %+v", name, s)
		}
	}
}

func TestParseAbsentBlock(t *testing.T) {
	s, err := Parse(`{"tools":[]}`)
	if err != nil || s != nil {
		t.Fatalf("absent block: %+v %v", s, err)
	}
	if s, err := Parse(""); err != nil || s != nil {
		t.Fatalf("empty label: %+v %v", s, err)
	}
	if !s.Empty() || s.Covers("GET", "/") || s.RPS() != DefaultRPS || s.Burst() != DefaultBurst {
		t.Fatal("a nil declaration serves nothing and keeps the defaults")
	}
}

func TestMatching(t *testing.T) {
	s, err := Parse(manifest)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/", true},
		{"HEAD", "/assets/app-1.js", true},
		{"POST", "/assets/app-1.js", false}, // static is GET/HEAD only
		{"GET", "/anything", false},         // "/" is the root document only
		{"GET", "/api/v1/public/feed", true},
		{"GET", "/api/v1/public", false}, // prefix needs the slash
		{"POST", "/api/v1/public/feed", false},
		{"POST", "/api/v1/webhooks/stripe", true},
		{"POST", "/api/v1/webhooks/stripe/extra", false}, // exact
		{"GET", "/api/v1/webhooks/stripe", false},
		{"GET", "/.well-known/openid-federation", true},
		{"GET", "/api/v1/paid", false},
		{"GET", "/api/session.list", false},
	}
	for _, c := range cases {
		if got := s.Covers(c.method, c.path); got != c.want {
			t.Errorf("Covers(%s %s) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
	if got := s.PublicMethods("/api/v1/public/x"); len(got) != 1 || got[0] != "GET" {
		t.Errorf("PublicMethods = %v", got)
	}
	if got := s.PublicHeaders("/api/v1/webhooks/stripe"); len(got) != 1 || got[0] != "Stripe-Signature" {
		t.Errorf("PublicHeaders = %v", got)
	}
	if s.PublicMethods("/api/v1/paid") != nil {
		t.Error("an undeclared path has no public methods")
	}
}

func TestStaticNeverCoversAPI(t *testing.T) {
	s := &Surfaces{Static: []string{"/"}}
	if s.IsStatic("/api/session.list") || s.IsStatic("/api") {
		t.Error("/api must stay private even when the app declares '/'")
	}
	if !s.IsStatic("/") || s.IsStatic("/anything") {
		t.Error("'/' is the root document only")
	}
}

func TestValidation(t *testing.T) {
	bad := []string{
		`{"surfaces":{"static":["/api/"]}}`,
		`{"surfaces":{"static":["assets/"]}}`,
		`{"surfaces":{"public":[{"method":"CONNECT","path":"/x"}]}}`,
		`{"surfaces":{"public":[{"method":"GET","path":"x"}]}}`,
		`{"surfaces":{"public":[{"method":"GET","path":"/"}]}}`,
		`{"surfaces":{"public":[{"method":"POST","path":"/__privasys/session-bootstrap"}]}}`,
		`{"surfaces":{"public":[{"method":"POST","path":"/hook","headers":["Authorization"]}]}}`,
		`{"surfaces":{"public":[{"method":"POST","path":"/hook","headers":["cookie"]}]}}`,
		`{"surfaces":{"cors":"https://a.example"}}`,
		`{"surfaces":{"limits":{"rps":-1}}}`,
		`not json at all`,
	}
	for _, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestLegacyLabelUnion(t *testing.T) {
	s := AddLegacyStatic(nil, " /, /assets/ ,,/favicon.svg")
	if s == nil || len(s.Static) != 3 || !s.IsStatic("/assets/x.js") {
		t.Fatalf("label alone: %+v", s)
	}
	s = AddLegacyStatic(&Surfaces{Static: []string{"/assets/"}}, "/assets/,/plugins/")
	if len(s.Static) != 2 || !s.IsStatic("/plugins/a.js") {
		t.Fatalf("union: %+v", s.Static)
	}
	if AddLegacyStatic(nil, " , ") != nil {
		t.Fatal("an empty label declares nothing")
	}
}

func TestConflicts(t *testing.T) {
	s, _ := Parse(manifest)
	if err := s.CheckPriced([]string{"/api/v1/public/feed"}); err == nil {
		t.Error("a priced endpoint under a public prefix must be refused")
	} else if !strings.Contains(err.Error(), "cannot carry a price") {
		t.Error(err)
	}
	if err := s.CheckPriced([]string{"/api/v1/paid"}); err != nil {
		t.Error(err)
	}
	if err := s.CheckConfigAPI("post", "/api/v1/webhooks/stripe"); err == nil {
		t.Error("a public configure surface must be refused")
	}
	if err := s.CheckConfigAPI("POST", "/configure"); err != nil {
		t.Error(err)
	}
	var nilS *Surfaces
	if nilS.CheckPriced([]string{"/x"}) != nil || nilS.CheckConfigAPI("POST", "/configure") != nil {
		t.Error("nothing declared conflicts with nothing")
	}
}

func TestSummary(t *testing.T) {
	s, _ := Parse(manifest)
	if got := s.Summary(); !strings.Contains(got, "static /assets/") || !strings.Contains(got, "POST /api/v1/webhooks/stripe") {
		t.Error(got)
	}
	var nilS *Surfaces
	if nilS.Summary() != "none" {
		t.Error(nilS.Summary())
	}
}
