package ratls

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A workload that answers the extensions request with a redirect never
// sends Caddy anywhere else: the target is not fetched and nothing goes into
// the certificate.
func TestExtensionFetchNeverFollowsARedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`[{"oid":"1.3.6.1.4.1.65230.9.9","value":"c2VjcmV0"}]`))
	}))
	defer target.Close()
	workload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/config", http.StatusFound)
	}))
	defer workload.Close()

	exts, err := fetchContainerExtensions(workload.URL)
	if err != nil {
		t.Fatalf("err %v", err)
	}
	if reached {
		t.Fatal("the redirect target was fetched")
	}
	if len(exts) != 0 {
		t.Fatalf("extensions from a redirect: %v", exts)
	}
}
