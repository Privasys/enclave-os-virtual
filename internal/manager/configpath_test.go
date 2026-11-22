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
