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

// A declaration as the control plane forwards one. The kind is a string the
// runtime carries and never interprets; this one happens to be Drive's.
var testDecl = capabilityDecl{Kind: "storage.folder", Name: "storage", Label: "Harness", Permissions: []string{"read", "write"}}

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
	if req["label"] != "Harness" {
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
		"storage.folder": "cf7a0d58",
		"mail.mailbox":   "7958ba28",
	}}}
	if got := s.resourceAppFor(capabilityDecl{Kind: "storage.folder"}); got != "cf7a0d58" {
		t.Fatalf("folder: %q", got)
	}
	if got := s.resourceAppFor(capabilityDecl{Kind: "mail.mailbox"}); got != "7958ba28" {
		t.Fatalf("mailbox: %q", got)
	}
	if got := s.resourceAppFor(capabilityDecl{Kind: "calendar.events"}); got != "" {
		t.Fatalf("an undeployed kind must resolve to nothing, got %q", got)
	}
	if got := (&Server{}).resourceAppFor(capabilityDecl{Kind: "storage.folder"}); got != "" {
		t.Fatalf("a fleet with no mapping must refuse everything, got %q", got)
	}
}

// The opaque request is the SAME SHAPE for every kind: the declared label,
// under that generic name. What a service does with it is the service's
// business — Drive makes a folder called that, a mail connector ignores it —
// and neither meaning belongs in a runtime shared by every app on the fleet.
//
// This test exists because the previous version emitted {"folder": ...} for
// storage.folder, so one product's vocabulary was compiled into every enclave.
func TestCapabilityRequestCarriesTheLabelAndNoProductVocabulary(t *testing.T) {
	for _, kind := range []string{"storage.folder", "mail.mailbox", "anything.at.all"} {
		got := capabilityRequestFor(capabilityDecl{Kind: kind, Label: "Harness"})
		if len(got) != 1 || got["label"] != "Harness" {
			t.Fatalf("%s: want {label: Harness}, got %v", kind, got)
		}
		if _, ok := got["folder"]; ok {
			t.Fatalf("%s: a product's word for the label reached the wire", kind)
		}
	}
	// Nothing to say is said as nothing, not as an empty label.
	if got := capabilityRequestFor(capabilityDecl{Kind: "mail.mailbox"}); len(got) != 0 {
		t.Fatalf("an unlabelled declaration must name nothing, got %v", got)
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

// A grant approved under one permission set is not an answer to a manifest
// that now declares another: the request path asks again (the old outcome
// stands meanwhile), the status path says so, and an explicit retry from the
// holder always re-asks. Outcomes recorded before permissions were kept are
// treated as stale once, never as silently matching.
func TestCapabilityReasksWhenPermissionsMoveOrOnRetry(t *testing.T) {
	dir := t.TempDir()
	b := newCapabilityBroker(dir, nil)
	p, _ := b.create("ctr", "app1", "cf7a0d58", "sub-A", testDecl)
	_, g, _ := b.resolve(p.Nonce, "approved", "cap-1", map[string]string{"tenant_id": "t", "node_id": "n"})
	if !g.usable() || g.stale(testDecl) {
		t.Fatalf("same permissions must not be stale: %+v", g)
	}
	reordered := testDecl
	reordered.Permissions = []string{"Write", "read"}
	if g.stale(reordered) {
		t.Fatal("permission order and case carry no meaning")
	}
	wider := testDecl
	wider.Permissions = []string{"read", "write", "delete"}
	if !g.stale(wider) {
		t.Fatal("a declaration asking for more must read as stale")
	}
	narrower := testDecl
	narrower.Permissions = []string{"read"}
	if !g.stale(narrower) {
		t.Fatal("a declaration asking for less must read as stale too: the holder approved something else")
	}
	legacy := &capabilityGrant{Resource: "storage", CapabilityID: "cap-0", Status: "approved"}
	if !legacy.stale(testDecl) {
		t.Fatal("an outcome recorded without permissions must be re-asked once")
	}
	if b.granted("app1", "storage", "sub-A").Permissions[0] != "read" {
		t.Fatal("the approved permissions must persist with the outcome")
	}
}
