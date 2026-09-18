// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package manager

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestHolderKeyWrapsAndUnwrapsUnderItsAAD(t *testing.T) {
	kek := make([]byte, 32)
	raw := make([]byte, 64)
	_, _ = rand.Read(kek)
	_, _ = rand.Read(raw)
	wrapped, err := wrapKey(kek, raw, "holder|cap_1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := unwrapKey(kek, wrapped, "holder|cap_1")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := unwrapKey(kek, wrapped, "holder|cap_2"); err == nil {
		t.Fatal("a wrapped key must be bound to its capability id")
	}
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	if _, err := unwrapKey(other, wrapped, "holder|cap_1"); err == nil {
		t.Fatal("another app's key must not unwrap it")
	}
}

func TestHolderKeyIsDerivedNeverNamed(t *testing.T) {
	a := holderKeyFor("app1", "subject-a")
	if len(a) != 32 || a != holderKeyFor("app1", "subject-a") {
		t.Fatalf("holder key must be a stable 32-hex hash, got %q", a)
	}
	if a == holderKeyFor("app2", "subject-a") || a == holderKeyFor("app1", "subject-b") {
		t.Fatal("holder key must differ per app and per subject")
	}
}

func TestBrokerRecordsHolderOutcomeAndRevokesIt(t *testing.T) {
	b := newCapabilityBroker(t.TempDir(), nil)
	decl := capabilityDecl{Kind: "app_storage", Name: "holders", Label: "Your working files", Permissions: []string{"read", "write"}}
	p, err := b.create("ctr", "app1", "app1", "subject-a", decl)
	if err != nil {
		t.Fatal(err)
	}
	if p.Capability.Kind != "app_storage" {
		t.Fatalf("kind: %q", p.Capability.Kind)
	}
	_, g, err := b.resolveHolder(p.Nonce, "hf_1", map[string]string{"path": "/data/holders/x"}, "0123456789abcdef0123456789abcdef", "keyid", "wrapped", true)
	if err != nil {
		t.Fatal(err)
	}
	if !g.usable() || g.Subject != "subject-a" || g.Kind != "app_storage" || g.WrappedKey != "wrapped" || !g.Unattended {
		t.Fatalf("record: %+v", g)
	}
	// A fresh broker over the same directory sees it, with everything.
	b2 := newCapabilityBroker(b.dir, nil)
	all := b2.grantsFor("app1")
	if len(all) != 1 || all[0].CapabilityID != "hf_1" || all[0].WrappedKey != "wrapped" {
		t.Fatalf("grantsFor: %+v", all)
	}
	key, found := b2.byCapabilityID("app1", "hf_1")
	if found == nil || key != grantKey("app1", "holders", "subject-a") {
		t.Fatalf("byCapabilityID: %q %+v", key, found)
	}
	b2.revoke("app1", key)
	g3 := b2.granted("app1", "holders", "subject-a")
	if g3.usable() || g3.Status != "revoked" || g3.WrappedKey != "" || g3.KeyID != "" {
		t.Fatalf("after revoke: %+v", g3)
	}
	// Persisted: a third broker sees the revoke, and no wrapped key.
	b3 := newCapabilityBroker(b.dir, nil)
	if g4 := b3.granted("app1", "holders", "subject-a"); g4.Status != "revoked" || g4.WrappedKey != "" {
		t.Fatalf("revoke not persisted: %+v", g4)
	}
}

func TestEventHubFansOutAndDropsSlowListeners(t *testing.T) {
	h := newEventHub()
	ch, cancel := h.subscribe("ctr")
	defer cancel()
	h.emit("ctr", resourceEvent{Type: "capability.approved", Subject: "s"})
	h.emit("other", resourceEvent{Type: "capability.approved", Subject: "x"})
	select {
	case ev := <-ch:
		if ev.Type != "capability.approved" || ev.Subject != "s" || ev.At == "" {
			t.Fatalf("event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
	select {
	case ev := <-ch:
		t.Fatalf("another container's event leaked: %+v", ev)
	default:
	}
	for i := 0; i < 100; i++ {
		h.emit("ctr", resourceEvent{Type: "holder.opened"})
	}
}

func TestDeclUnattendedDefaultsToTrue(t *testing.T) {
	if !declUnattended(capabilityDecl{}) {
		t.Fatal("no options: unattended by default")
	}
	if declUnattended(capabilityDecl{Options: map[string]any{"unattended": false}}) {
		t.Fatal("unattended false must be honoured")
	}
}
