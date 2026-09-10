package manager

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

var testDecl = capabilityDecl{Kind: capabilityKindFolder, Name: "storage", Label: "Harness", Permissions: []string{"read", "write"}}

// The key is per app, sealed on first use and stable across brokers on the
// same directory: a redeploy must keep every approved capability valid.
func TestCapabilityKeyIsPerAppAndStable(t *testing.T) {
	dir := t.TempDir()
	b := newCapabilityBroker(dir, zap.NewNop())
	a1, _ := b.bindingPubkey("app1")
	a2, _ := b.bindingPubkey("app2")
	if a1 == "" || a1 == a2 {
		t.Fatalf("keys must be distinct per app: %q %q", a1, a2)
	}
	again, _ := newCapabilityBroker(dir, nil).bindingPubkey("app1")
	if again != a1 {
		t.Fatal("key did not survive a broker restart")
	}
	sig, _ := b.sign("app1", []byte("payload"))
	pub, _ := base64.StdEncoding.DecodeString(a1)
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte("payload"), sig) {
		t.Fatal("signature does not verify under the published key")
	}
}

// Create → wallet fetch → outcome, with the nonce consumed and the outcome
// (approved or denied) persisted per (app, resource, subject).
func TestCapabilityFlowAndDenialSticks(t *testing.T) {
	dir := t.TempDir()
	b := newCapabilityBroker(dir, nil)
	p, err := b.create("ctr", "app1", "cf7a0d58", "sub-A", testDecl)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := b.get(p.Nonce)
	if !ok || got.BindingPubkey == "" || got.ResourceApp != "cf7a0d58" || got.Capability.ResourceLabel != "Harness" {
		t.Fatalf("pending: %+v", got)
	}
	var req map[string]string
	_ = json.Unmarshal(got.Capability.Request, &req)
	if req["folder"] != "Harness" {
		t.Fatalf("request %s", got.Capability.Request)
	}
	if _, _, err := b.resolve(p.Nonce, "denied", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.get(p.Nonce); ok {
		t.Fatal("nonce must be single use")
	}
	if g := newCapabilityBroker(dir, nil).granted("app1", "storage", "sub-A"); !g.denied() {
		t.Fatalf("denial must persist across restarts: %+v", g)
	}
	if g := b.granted("app1", "storage", "sub-B"); g != nil {
		t.Fatal("another subject must not see the outcome")
	}
	p2, _ := b.create("ctr", "app1", "cf7a0d58", "sub-A", testDecl)
	_, g, _ := b.resolve(p2.Nonce, "approved", "cap-1", map[string]string{"tenant_id": "t", "node_id": "n", "path": "AppData/Harness"})
	if !g.usable() || b.granted("app1", "storage", "sub-A").ServiceResult["path"] != "AppData/Harness" {
		t.Fatalf("approval: %+v", g)
	}
}

// The wallet-facing routes only show a container its own asks.
func TestCapabilityWellKnownScopedToContainer(t *testing.T) {
	s := &Server{log: zap.NewNop(), caps: newCapabilityBroker("", nil)}
	p, _ := s.caps.create("ctr-a", "app1", "cf7a0d58", "sub", testDecl)

	rec := httptest.NewRecorder()
	s.serveCapabilityWellKnown(rec, httptest.NewRequest("GET", capabilityRequestPath+"?nonce="+p.Nonce, nil), "ctr-b")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("other container must not see the ask: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.serveCapabilityWellKnown(rec, httptest.NewRequest("GET", capabilityRequestPath+"?nonce="+p.Nonce, nil), "ctr-a")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"binding_pubkey"`) {
		t.Fatalf("own ask: %d %s", rec.Code, rec.Body.String())
	}
	body := `{"nonce":"` + p.Nonce + `","status":"approved","capability_id":"cap-9","service_result":{"tenant_id":"t","node_id":"n"}}`
	rec = httptest.NewRecorder()
	s.serveCapabilityWellKnown(rec, httptest.NewRequest("POST", capabilityResultPath, strings.NewReader(body)), "ctr-b")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("result on the wrong host: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.serveCapabilityWellKnown(rec, httptest.NewRequest("POST", capabilityResultPath, strings.NewReader(body)), "ctr-a")
	if rec.Code != 200 || !s.caps.granted("app1", "storage", "sub").usable() {
		t.Fatalf("result: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.serveCapabilityWellKnown(rec, httptest.NewRequest("POST", capabilityResultPath, strings.NewReader(`{"nonce":"x","status":"maybe"}`)), "ctr-a")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad status: %d", rec.Code)
	}
}

// The resource service is stamped by the CONTROL PLANE onto the declaration
// and merely relayed here. The runtime knows no product: which app serves
// "mail.mailbox" is not an operating system's business, and a table of them
// compiled in would make shipping a connector a runtime release.
//
// The env map is an operator override for a control plane that does not stamp
// yet. A kind resolved by neither must be unaskable rather than defaulted to
// something plausible.
func TestResourceAppComesFromTheFleetAndUnknownKindsRefuse(t *testing.T) {
	s := &Server{cfg: Config{ResourceApps: map[string]string{
		capabilityKindFolder: "cf7a0d58",
		"mail.mailbox":       "7958ba28",
	}}}
	if got := s.resourceAppFor(capabilityDecl{Kind: capabilityKindFolder}); got != "cf7a0d58" {
		t.Fatalf("folder: %q", got)
	}
	if got := s.resourceAppFor(capabilityDecl{Kind: "mail.mailbox"}); got != "7958ba28" {
		t.Fatalf("mailbox: %q", got)
	}
	if got := s.resourceAppFor(capabilityDecl{Kind: "calendar.events"}); got != "" {
		t.Fatalf("an undeployed kind must resolve to nothing, got %q", got)
	}
	if got := (&Server{}).resourceAppFor(capabilityDecl{Kind: capabilityKindFolder}); got != "" {
		t.Fatalf("a fleet with no mapping must refuse everything, got %q", got)
	}
}

// The opaque request is kind-specific: a folder capability has to say which
// folder, and a mailbox capability has nothing to name, because the resource
// service derives the mailbox from the holder who authenticated.
func TestCapabilityRequestIsKindSpecific(t *testing.T) {
	folder := capabilityRequestFor(capabilityDecl{Kind: capabilityKindFolder, Label: "Harness"})
	if folder["folder"] != "Harness" {
		t.Fatalf("folder request: %v", folder)
	}
	mailbox := capabilityRequestFor(capabilityDecl{Kind: "mail.mailbox", Label: "Mail Connector"})
	if len(mailbox) != 0 {
		t.Fatalf("a mailbox ask must name nothing, got %v", mailbox)
	}
	// The label must not leak into the body under another name either: it is
	// rendered by the wallet from resource_label, not carried as a parameter.
	for k, v := range mailbox {
		if v == "Mail Connector" {
			t.Fatalf("label leaked into the request as %q", k)
		}
	}
}

// The control plane's stamp is the source of truth, and the runtime carries no
// product knowledge of its own. The override exists for fleets whose control
// plane predates the stamp, and must never win over it: if it did, an operator
// env var set once would silently outlive the deployment that corrected it.
func TestStampedResourceServiceWinsOverTheOperatorOverride(t *testing.T) {
	s := &Server{cfg: Config{ResourceApps: map[string]string{
		"mail.mailbox": "the-override",
	}}}
	stamped := capabilityDecl{Kind: "mail.mailbox", ResourceApp: "from-the-control-plane"}
	if got := s.resourceAppFor(stamped); got != "from-the-control-plane" {
		t.Fatalf("the stamp must win, got %q", got)
	}
	unstamped := capabilityDecl{Kind: "mail.mailbox"}
	if got := s.resourceAppFor(unstamped); got != "the-override" {
		t.Fatalf("an unstamped declaration should fall back to the override, got %q", got)
	}
	// A runtime with neither knows nothing about any product, which is the
	// state a generic OS should be in.
	if got := (&Server{}).resourceAppFor(unstamped); got != "" {
		t.Fatalf("a bare runtime must know no resource services, got %q", got)
	}
}
