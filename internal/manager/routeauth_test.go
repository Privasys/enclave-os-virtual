package manager

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Privasys/enclave-os-virtual/internal/apifees"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

var guarded = []apifees.RouteAuth{
	{Tool: "unload_model", Path: "/v1/models/unload", Policy: apifees.PolicyOwner},
	{Tool: "billing", Path: "/configure", Policy: apifees.PolicyRole, Roles: []string{"privasys-platform:manager"}},
	{Tool: "me", Path: "/v1/me", Policy: apifees.PolicyAuthenticated},
}

// Every spelling a router reads as the guarded path is guarded, whatever the
// method; a path that only resembles it is not.
func TestMatchRouteAuth(t *testing.T) {
	cases := []struct {
		method, path string
		want         string
	}{
		{"POST", "/v1/models/unload", "unload_model"},
		{"GET", "/v1/models/unload", "unload_model"},
		{"POST", "/V1/Models/Unload/", "unload_model"},
		{"POST", "//v1/models//unload", "unload_model"},
		{"POST", "/v1/x/../models/unload", "unload_model"},
		{"POST", "/v1/models/unload;jsessionid=1", "unload_model"},
		{"POST", "/v1/models/unload.turbo_stream", "unload_model"},
		{"POST", "/configure.json", "billing"},
		{"POST", "/v1/models/unloaded", ""},
		{"POST", "/v1/models/unload/x", ""},
		{"POST", "/v1/models/load", ""},
	}
	for _, c := range cases {
		ra, ok := matchRouteAuth(guarded, httptest.NewRequest(c.method, "http://h"+c.path, nil))
		if got := ""; ok {
			got = ra.Tool
			if got != c.want {
				t.Errorf("%s %s: matched %q, want %q", c.method, c.path, got, c.want)
			}
		} else if c.want != "" {
			t.Errorf("%s %s: not matched, want %q", c.method, c.path, c.want)
		}
	}
	if _, ok := matchRouteAuth(nil, httptest.NewRequest("POST", "/v1/models/unload", nil)); ok {
		t.Error("no guarded routes must match nothing")
	}
}

const routeAppHex = "00112233445566778899aabbccddeeff"

func routeReq(path, bearer string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

func TestAuthorizeRoute(t *testing.T) {
	s, iss := newIdentityServer(t)
	st := launcher.FreezeState{AppID: routeAppHex}
	aud := "enclave-os-virtual"
	owner := iss.token(t, "alice", aud, map[string]any{"roles": []string{aud + ":app:" + routeAppHex + ":owner"}})
	admin := iss.token(t, "bob", aud, map[string]any{"roles": []string{aud + ":app:" + routeAppHex + ":admin"}})
	stranger := iss.token(t, "eve", aud, map[string]any{"roles": []string{aud + ":app:ffffffffffffffffffffffffffffffff:owner"}})
	manager := iss.token(t, "mgmt", aud, map[string]any{"roles": []string{"privasys-platform:manager"}})
	plain := iss.token(t, "carol", aud, nil)
	unload, billing, me := guarded[0], guarded[1], guarded[2]

	check := func(name string, ra apifees.RouteAuth, r *http.Request, allow bool) {
		t.Helper()
		err := s.authorizeRoute(r, "app", st, ra)
		if allow && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if !allow && err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	// owner: the app's owner and admin, nobody else.
	check("owner on owner route", unload, routeReq(unload.Path, owner), true)
	check("admin on owner route", unload, routeReq(unload.Path, admin), true)
	check("other app's owner on owner route", unload, routeReq(unload.Path, stranger), false)
	check("manager on owner route", unload, routeReq(unload.Path, manager), false)
	check("no token on owner route", unload, routeReq(unload.Path, ""), false)
	// role(...): the roles as written.
	check("manager on role route", billing, routeReq(billing.Path, manager), true)
	check("owner on manager-role route", billing, routeReq(billing.Path, owner), false)
	check("junk on role route", billing, routeReq(billing.Path, "junk"), false)
	// authenticated: any verified bearer, or a runtime-asserted subject.
	check("plain bearer on authenticated route", me, routeReq(me.Path, plain), true)
	check("no caller on authenticated route", me, routeReq(me.Path, ""), false)
	check("junk on authenticated route", me, routeReq(me.Path, "junk"), false)
	sealed := routeReq(me.Path, "")
	sealed.Header.Set("X-Privasys-Sub", "sealed-user")
	check("sealed subject on authenticated route", me, sealed, true)
	asserted := routeReq(unload.Path, "")
	asserted.Header.Set("X-Privasys-Sub", "sealed-user")
	check("sealed subject on owner route", unload, asserted, false)
}
