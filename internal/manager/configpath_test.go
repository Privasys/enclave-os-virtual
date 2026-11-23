package manager

import (
	"net/http/httptest"
	"testing"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

func TestConfigureGateCoversEverySpellingOfThePath(t *testing.T) {
	spec := &launcher.ConfigAPISpec{Method: "POST", Path: "/configure"}
	guarded := []string{
		"/configure", "/Configure", "/CONFIGURE", "/configure/", "//configure",
		"/x/../configure", "/./configure", "/configure;jsessionid=1", `/\configure`, "/x;y/../configure", "/;a/configure;b",
		"/%63onfigure", "/configure?a=1",
	}
	for _, target := range guarded {
		r := httptest.NewRequest("POST", target, nil)
		if !matchesConfigAPI(spec, r) {
			t.Errorf("POST %s skipped the configure gate", target)
		}
	}
	for _, target := range []string{"/configured", "/configure/x", "/", "/config"} {
		r := httptest.NewRequest("POST", target, nil)
		if matchesConfigAPI(spec, r) {
			t.Errorf("POST %s was taken for the configure path", target)
		}
	}
}

func TestConfigureGateCoversMethodOverrides(t *testing.T) {
	spec := &launcher.ConfigAPISpec{Method: "POST", Path: "/configure"}
	r := httptest.NewRequest("GET", "/configure", nil)
	if matchesConfigAPI(spec, r) {
		t.Fatal("a plain GET was taken for the POST configure endpoint")
	}
	for _, h := range configMethodOverrides {
		r := httptest.NewRequest("GET", "/configure", nil)
		r.Header.Set(h, "post")
		if !matchesConfigAPI(spec, r) {
			t.Errorf("%s: post skipped the configure gate", h)
		}
	}
	r = httptest.NewRequest("GET", "/configure?_method=POST", nil)
	if !matchesConfigAPI(spec, r) {
		t.Error("_method=POST skipped the configure gate")
	}
	get := &launcher.ConfigAPISpec{Method: "GET", Path: "/configure"}
	if !matchesConfigAPI(get, httptest.NewRequest("HEAD", "/configure", nil)) {
		t.Error("HEAD skipped a GET configure gate")
	}
}

func TestConfigureGateGuardsEveryPost(t *testing.T) {
	// A POST form body may carry `_method=PUT` (Rails, Laravel, Symfony), so
	// a POST to the configure path is guarded whatever method is declared.
	for _, m := range []string{"PUT", "PATCH", "DELETE", "GET"} {
		spec := &launcher.ConfigAPISpec{Method: m, Path: "/configure"}
		if !matchesConfigAPI(spec, httptest.NewRequest("POST", "/configure", nil)) {
			t.Errorf("POST skipped a %s configure gate", m)
		}
		if matchesConfigAPI(spec, httptest.NewRequest("POST", "/elsewhere", nil)) {
			t.Errorf("POST elsewhere was taken for the %s configure path", m)
		}
	}
}

func TestConfigureGateCoversFormatSuffix(t *testing.T) {
	spec := &launcher.ConfigAPISpec{Method: "POST", Path: "/api/configure"}
	for _, target := range []string{
		"/api/configure.json", "/api/configure.XML", "/api/Configure.yaml", "/api/configure.j",
		"/api/configure.turbo_stream", "/api/configure.jsonapi", "/api/configure.toolong",
		"/api/configure.js0n", "/api/configure.json.bak", "/api/configure.", "/api/configure.x/y", "/api/configure.x%2Fy",
	} {
		if !matchesConfigAPI(spec, httptest.NewRequest("POST", target, nil)) {
			t.Errorf("POST %s skipped the configure gate", target)
		}
	}
	for _, target := range []string{"/api.json/configure2", "/api/configured", "/api/configure2.json"} {
		if matchesConfigAPI(spec, httptest.NewRequest("POST", target, nil)) {
			t.Errorf("POST %s was taken for the configure path", target)
		}
	}
	root := &launcher.ConfigAPISpec{Method: "POST", Path: "/"}
	if matchesConfigAPI(root, httptest.NewRequest("POST", "/.well-known/x", nil)) {
		t.Error("a dot path was taken for a root configure endpoint")
	}
}
