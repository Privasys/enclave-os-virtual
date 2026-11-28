package routeauth

import (
	"encoding/base64"
	"reflect"
	"testing"
)

// The grammar is Enclave OS Mini's @auth, case-insensitive, spaces allowed.
func TestParseAuthAnnotation(t *testing.T) {
	good := []struct {
		in    string
		p     Policy
		roles []string
	}{
		{"public", PolicyPublic, nil},
		{" Authenticated ", PolicyAuthenticated, nil},
		{"OWNER", PolicyOwner, nil},
		{"role(privasys-platform:manager)", PolicyRole, []string{"privasys-platform:manager"}},
		{"Role ( a , b )", PolicyRole, []string{"a", "b"}},
	}
	for _, g := range good {
		p, roles, err := ParseAuthAnnotation(g.in)
		if err != nil || p != g.p || !reflect.DeepEqual(roles, g.roles) {
			t.Errorf("%q: got %v %v %v", g.in, p, roles, err)
		}
	}
	for _, bad := range []string{"", "admin", "role()", "role( , )", "role a", "owners"} {
		if _, _, err := ParseAuthAnnotation(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

const authManifest = `{
  "configure": {"endpoint": "/v1/models/load"},
  "tools": [
    {"name": "chat", "endpoint": "/v1/chat/completions"},
    {"name": "load_model", "endpoint": "/v1/models/load", "x-privasys": {"auth": "owner"}},
    {"name": "unload_model", "endpoint": "/v1/models/unload", "x-privasys": {"auth": "owner"}},
    {"name": "billing", "endpoint": "/configure", "x-privasys": {"auth": "role(privasys-platform:manager)"}},
    {"name": "me", "endpoint": "/v1/me", "x-privasys": {"auth": "authenticated"}},
    {"name": "health", "endpoint": "/health", "x-privasys": {"auth": "public"}}
  ]
}`

// Public and unannotated tools need nothing; the configure endpoint keeps
// its own gate; the rest are guarded, in both label encodings.
func TestParse(t *testing.T) {
	want := []RouteAuth{
		{Tool: "unload_model", Path: "/v1/models/unload", Policy: PolicyOwner},
		{Tool: "billing", Path: "/configure", Policy: PolicyRole, Roles: []string{"privasys-platform:manager"}},
		{Tool: "me", Path: "/v1/me", Policy: PolicyAuthenticated},
	}
	for _, raw := range []string{authManifest, base64.StdEncoding.EncodeToString([]byte(authManifest))} {
		got, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v\nwant %+v", got, want)
		}
	}
	if got, err := Parse(""); err != nil || got != nil {
		t.Fatalf("empty label: %v %v", got, err)
	}
}

// A policy the developer did not write is never applied: the load is
// refused instead.
func TestParseRefuses(t *testing.T) {
	for _, raw := range []string{
		`{"tools": [{"name": "x", "endpoint": "/x", "x-privasys": {"auth": "admins"}}]}`,
		`{"tools": [{"name": "x", "x-privasys": {"auth": "owner"}}]}`,
		`{"tools": [{"name": "x", "endpoint": "x", "x-privasys": {"auth": "owner"}}]}`,
		`{"tools": [{"name": "x", "endpoint": "/", "x-privasys": {"auth": "owner"}}]}`,
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
