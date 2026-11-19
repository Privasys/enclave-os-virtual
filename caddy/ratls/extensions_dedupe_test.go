package ratls

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// An app that pushes an extension and still declares it on its pull endpoint
// must not put the OID on the certificate twice: x509 would refuse the leaf and
// every handshake to the hostname would fail. The manager's value wins.
func TestHostnameExtensionsAreNotDuplicated(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]extensionEntry{
			{OID: "1.3.6.1.4.1.65230.5.4.5", Value: b64("from-container")},
			{OID: "1.3.6.1.4.1.65230.5.4.6", Value: b64("container-only")},
			{OID: "1.3.6.1.4.1.65230.5.4.6", Value: b64("container-twice")},
		})
	}))
	defer app.Close()

	dir := t.TempDir()
	file := extensionsFile{
		Extensions: []extensionEntry{
			{OID: "1.3.6.1.4.1.65230.3.6", Value: b64("app-id")},
			{OID: "1.3.6.1.4.1.65230.5.4.5", Value: b64("stamped")},
			{OID: "1.3.6.1.4.1.65230.3.6", Value: b64("app-id-again")},
		},
		Upstream: app.URL,
	}
	data, _ := json.Marshal(file)
	if err := os.WriteFile(filepath.Join(dir, "app.example.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	g := &RATLSCertGetter{ExtensionsDir: dir, logger: zap.NewNop()}
	exts, err := g.loadHostnameExtensions("app.example")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range exts {
		id := e.Id.String()
		if _, dup := got[id]; dup {
			t.Fatalf("OID %s appears twice", id)
		}
		got[id] = string(e.Value)
	}
	want := map[string]string{
		"1.3.6.1.4.1.65230.3.6":   "app-id",
		"1.3.6.1.4.1.65230.5.4.5": "stamped",
		"1.3.6.1.4.1.65230.5.4.6": "container-only",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
