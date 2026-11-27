package launcher

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/caddy"
	"github.com/Privasys/enclave-os-virtual/internal/directtls"
	"github.com/Privasys/enclave-os-virtual/internal/manifest"
	"github.com/Privasys/enclave-os-virtual/internal/merkle"
)

const (
	testAppDomain = "apps.test.privasys.org"
	testPlatform  = "m6-dev.privasys.org"
	testManager   = "m6-dev-mgr.apps.test.privasys.org"
)

// fakeDomainStore stands in for the policy store: which app owns which
// direct domain on this host.
type fakeDomainStore struct{ owners map[string]string }

func (f *fakeDomainStore) DomainsFor(appID string) []string {
	var out []string
	for d, o := range f.owners {
		if o == appID {
			out = append(out, d)
		}
	}
	return out
}
func (f *fakeDomainStore) DomainOwner(name string) string { return f.owners[name] }

// approve records name as owned by the container's app, as an accepted
// policy would.
func approve(store *fakeDomainStore, container string, names ...string) {
	for _, n := range names {
		store.owners[n] = testAppID(container)
	}
}

// testAppID is a container's app id in these tests: its name, hex-encoded.
func testAppID(container string) string { return hex.EncodeToString([]byte(container)) }

// hostTestLauncher builds a launcher with direct domains wired to nothing
// reachable: Caddy's admin API is a stub that accepts every config, and the
// ACME, CT and probe endpoints fail, so no certificate is ever ordered.
func hostTestLauncher(t *testing.T, appDomain string) (*Launcher, string, *fakeDomainStore) {
	t.Helper()
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(admin.Close)
	extDir := t.TempDir()
	l := New(Config{
		ExtensionsDir:    extDir,
		PlatformHostname: testPlatform,
		MachineName:      "m6-dev",
		AppDomain:        appDomain,
	}, zap.NewNop())
	l.caddyClient = caddy.NewClient(caddy.Config{AdminAddr: strings.TrimPrefix(admin.URL, "http://")}, zap.NewNop())
	l.direct = directtls.New(directtls.Config{
		StorageRoot:    t.TempDir(),
		CA:             "http://127.0.0.1:1/directory",
		CTSearch:       "http://127.0.0.1:1/",
		LookupHost:     func(context.Context, string) ([]string, error) { return nil, errors.New("no resolver in tests") },
		ProbeDial:      func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no dial in tests") },
		ProbeFirstWait: time.Hour,
		ProbeMaxWait:   time.Hour,
	}, zap.NewNop())
	store := &fakeDomainStore{owners: map[string]string{}}
	l.SetApprovedDomains(store)
	t.Cleanup(func() {
		l.mu.Lock()
		names := make([]string, 0, len(l.directDomains))
		for n := range l.directDomains {
			names = append(names, n)
		}
		l.mu.Unlock()
		for _, n := range names {
			l.direct.Remove(n)
		}
	})
	return l, extDir, store
}

// addHostTestApp puts a loaded, vault-backed app on the launcher with its
// Caddy route, as a load would leave it.
func addHostTestApp(t *testing.T, l *Launcher, name, host string, port int) {
	t.Helper()
	l.mu.Lock()
	l.specs[name] = manifest.Container{Name: name, Image: "example.invalid/" + name, Hostname: host, Port: port}
	l.containerTrees[name] = merkle.New([]merkle.Leaf{{Name: name, Data: []byte(name)}})
	l.directBranches[name] = []byte(strings.Repeat(name[:1], 32))
	l.appIDs[name] = []byte(name)
	l.mu.Unlock()
	if err := l.caddyClient.AddRoute(host, "localhost:8080", false); err != nil {
		t.Fatal(err)
	}
}

func readOrEmpty(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// Rex Liu's report (2026-11-27): an app's owner names another app's direct
// domain in their own signed policy. The second claim is refused, and the
// victim's extensions file is left exactly as it was.
func TestDirectDomainOfAnotherAppIsRefused(t *testing.T) {
	l, extDir, store := hostTestLauncher(t, testAppDomain)
	addHostTestApp(t, l, "victim", "victim."+testAppDomain, 10001)
	addHostTestApp(t, l, "attacker", "attacker."+testAppDomain, 10002)

	approve(store, "victim", "shop.example.com")
	if err := l.SetDirectDomains("victim", []string{"shop.example.com"}); err != nil {
		t.Fatalf("the victim's own domain: %v", err)
	}
	ext := filepath.Join(extDir, "shop.example.com.json")
	before := readOrEmpty(ext)
	if before == "" {
		t.Fatal("the victim's direct domain has no extensions file")
	}

	// Refused by the policy route's pre-check, and by the launcher even if
	// the store were wrong.
	if err := l.CheckDirectDomains("attacker", []string{"shop.example.com"}); err == nil || !strings.Contains(err.Error(), `already served by "victim"`) {
		t.Fatalf("the pre-check let the claim through: %v", err)
	}
	approve(store, "attacker", "shop.example.com")
	err := l.SetDirectDomains("attacker", []string{"shop.example.com"})
	if err == nil || !strings.Contains(err.Error(), `already served by "victim"`) {
		t.Fatalf("a second claim on the victim's domain was not refused: %v", err)
	}
	if got := l.DirectDomainsOf("attacker"); len(got) != 0 {
		t.Fatalf("the attacker serves %v", got)
	}
	if after := readOrEmpty(ext); after != before {
		t.Fatal("the victim's extensions file was rewritten by the refused claim")
	}
	// Dropping its other names does not touch the victim's file either.
	if err := l.SetDirectDomains("attacker", nil); err != nil {
		t.Fatal(err)
	}
	if after := readOrEmpty(ext); after != before {
		t.Fatal("the victim's extensions file was removed by another app")
	}
}

// The review of the fix (2026-11-27): who is loaded must not decide who
// owns a name. While the victim is not loaded (boot replay, a redeploy, a
// stop) the attacker still cannot take a name the store gives the victim,
// and the victim gets it back when it loads. A name the store gives no one
// is served by no one.
func TestDirectDomainOwnerIsTheStoresNotWhoIsLoaded(t *testing.T) {
	l, _, store := hostTestLauncher(t, testAppDomain)
	addHostTestApp(t, l, "attacker", "attacker."+testAppDomain, 10002)
	approve(store, "victim", "shop.example.com")

	if err := l.SetDirectDomains("attacker", []string{"shop.example.com"}); err == nil || !strings.Contains(err.Error(), "not approved for this app") {
		t.Fatalf("the attacker took an absent victim's name: %v", err)
	}
	addHostTestApp(t, l, "victim", "victim."+testAppDomain, 10001)
	if err := l.SetDirectDomains("victim", []string{"shop.example.com"}); err != nil {
		t.Fatalf("the victim's name after its load: %v", err)
	}
	if err := l.SetDirectDomains("attacker", []string{"free.example.com"}); err == nil {
		t.Fatal("a name no accepted policy approved was served")
	}
}

// A name no one holds is accepted; its owner can apply the same list again,
// add a name, and drop one (whose file then goes).
func TestDirectDomainOwnerKeepsAndUpdatesItsNames(t *testing.T) {
	l, extDir, store := hostTestLauncher(t, testAppDomain)
	addHostTestApp(t, l, "app", "app."+testAppDomain, 10001)
	approve(store, "app", "a.example.com", "b.example.com")

	if err := l.SetDirectDomains("app", []string{"a.example.com"}); err != nil {
		t.Fatalf("a unique name: %v", err)
	}
	if err := l.SetDirectDomains("app", []string{"a.example.com"}); err != nil {
		t.Fatalf("the same list again: %v", err)
	}
	if err := l.SetDirectDomains("app", []string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatalf("adding a name: %v", err)
	}
	if err := l.SetDirectDomains("app", []string{"b.example.com"}); err != nil {
		t.Fatalf("dropping a name: %v", err)
	}
	if readOrEmpty(filepath.Join(extDir, "a.example.com.json")) != "" {
		t.Fatal("the dropped name's extensions file is still there")
	}
	if readOrEmpty(filepath.Join(extDir, "b.example.com.json")) == "" {
		t.Fatal("the kept name has no extensions file")
	}
	// Once its owner's policy drops it, another app may take it.
	delete(store.owners, "a.example.com")
	addHostTestApp(t, l, "other", "other."+testAppDomain, 10002)
	approve(store, "other", "a.example.com")
	if err := l.SetDirectDomains("other", []string{"a.example.com"}); err != nil {
		t.Fatalf("a released name: %v", err)
	}
}

// The names the platform keeps and the app domain's names are never direct
// domains: another app's canonical hostname, the manager's name, the
// platform hostname, the app's own name, the app domain itself, and an IP
// address (the control plane reaches the enclave by its IP). Even with the
// store approving them.
func TestDirectDomainCannotTakeAssignedNames(t *testing.T) {
	l, _, store := hostTestLauncher(t, testAppDomain)
	addHostTestApp(t, l, "victim", "victim."+testAppDomain, 10001)
	addHostTestApp(t, l, "attacker", "attacker."+testAppDomain, 10002)
	for _, d := range []string{
		"victim." + testAppDomain,
		"attacker." + testAppDomain,
		testManager,
		testPlatform,
		testAppDomain,
		"deeper.victim." + testAppDomain,
		"34.155.1.2",
		"127.0.0.1",
	} {
		approve(store, "attacker", d)
		if err := l.CheckDirectDomains("attacker", []string{d}); err == nil {
			t.Errorf("pre-check: direct domain %s was accepted", d)
		}
		if err := l.SetDirectDomains("attacker", []string{d}); err == nil {
			t.Errorf("direct domain %s was accepted", d)
		}
	}
	if got := l.DirectDomainsOf("attacker"); len(got) != 0 {
		t.Fatalf("the attacker serves %v", got)
	}
}

// Without an app domain (no namespace split) the registry alone keeps one
// owner per name: a direct domain cannot be another app's canonical name,
// and a load cannot take another app's direct domain.
func TestOneOwnerWithoutAnAppDomain(t *testing.T) {
	l, _, store := hostTestLauncher(t, "")
	addHostTestApp(t, l, "victim", "victim.example.org", 10001)
	addHostTestApp(t, l, "attacker", "attacker.example.org", 10002)
	approve(store, "attacker", "victim.example.org")
	if err := l.SetDirectDomains("attacker", []string{"victim.example.org"}); err == nil {
		t.Fatal("a direct domain naming another app's hostname was accepted")
	}
	approve(store, "victim", "shop.example.com")
	if err := l.SetDirectDomains("victim", []string{"shop.example.com"}); err != nil {
		t.Fatal(err)
	}
	_, err := l.Load(context.Background(), LoadRequest{Name: "late", Image: "example.invalid/x@sha256:" + strings.Repeat("0", 64), Hostname: "shop.example.com", Port: 10003})
	if err == nil || !strings.Contains(err.Error(), `already served by "victim"`) {
		t.Fatalf("a load taking another app's direct domain was not refused: %v", err)
	}
}

// F10: a load's hostname is one concrete lowercase name directly under the
// app domain, never a pattern and never a platform name.
func TestLoadHostnameIsOneConcreteName(t *testing.T) {
	l := New(Config{MachineName: "m6-dev", PlatformHostname: testPlatform, AppDomain: testAppDomain}, zap.NewNop())
	for _, h := range []string{
		"*." + testAppDomain,
		"*",
		"App." + testAppDomain,
		"a.b." + testAppDomain,
		"app.example.com",
		testAppDomain,
		testPlatform,
		testManager,
		"app." + testAppDomain + ".",
		"34.155.1.2",
	} {
		if err := l.ValidateLoadHostname(h); err == nil {
			t.Errorf("load hostname %q was accepted", h)
		}
		_, err := l.Load(context.Background(), LoadRequest{Name: "x", Image: "example.invalid/x@sha256:" + strings.Repeat("0", 64), Hostname: h, Port: 10001})
		if err == nil {
			t.Errorf("Load with hostname %q was not refused", h)
		}
	}
	for _, h := range []string{"", "app." + testAppDomain, "my-app-2." + testAppDomain} {
		if err := l.ValidateLoadHostname(h); err != nil {
			t.Errorf("load hostname %q was refused: %v", h, err)
		}
	}
}

// An unload removes only what its app held: a name another app holds by then
// keeps its extensions file, and a name no one holds loses it. (Unload
// itself needs containerd; this is its direct-domain step, run as Unload
// runs it, after the spec is gone.)
func TestUnloadRemovesOnlyItsOwnNames(t *testing.T) {
	l, extDir, store := hostTestLauncher(t, testAppDomain)
	addHostTestApp(t, l, "a", "a."+testAppDomain, 10001)
	approve(store, "a", "a.example.com", "b.example.com")
	if err := l.SetDirectDomains("a", []string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatal(err)
	}
	l.directMu.Lock()
	l.mu.Lock()
	delete(l.specs, "a")
	l.reserved["b"] = loadReservation{hostname: "a.example.com"} // held by another app by now
	l.removeDirect("a", "a."+testAppDomain)
	l.mu.Unlock()
	l.directMu.Unlock()
	if readOrEmpty(filepath.Join(extDir, "a.example.com.json")) == "" {
		t.Fatal("an unload removed a name another app holds")
	}
	if readOrEmpty(filepath.Join(extDir, "b.example.com.json")) != "" {
		t.Fatal("an unload left the file of a name no one holds")
	}
}
