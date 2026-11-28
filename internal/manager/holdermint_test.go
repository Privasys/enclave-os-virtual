//go:build testhooks

package manager

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// The wallet's mint unlocks the folder through unlockHolderFolder, in the
// mode of the permission set the holder approved, and records that mode:
// for [read] the read-only bind and the container's confirmation come
// before the new folder is sealed.
func TestMintUnlocksInTheApprovedMode(t *testing.T) {
	for _, c := range []struct {
		perms []string
		ro    bool
	}{{[]string{"read"}, true}, {[]string{"read", "write"}, false}} {
		l := launcher.New(launcher.Config{}, zap.NewNop())
		launcher.SetHolderFoldersForTest(l, "ctr-a", []launcher.ResourceDecl{{Kind: launcher.AppStorageKind, Name: "workspace", Permissions: c.perms}}, make([]byte, 32))
		f := &fakeFolders{missing: true}
		s := &Server{log: zap.NewNop(), caps: newCapabilityBroker("", nil), holdersOpen: newHolderState(), events: newEventHub(), launcher: l, folderOps: f}
		decl := testDecl
		decl.Kind, decl.Name, decl.Permissions = launcher.AppStorageKind, "workspace", c.perms
		p, err := s.caps.create("ctr-a", "app1", resourceAppSelf, "sub", decl)
		if err != nil {
			t.Fatal(err)
		}
		key := base64.StdEncoding.EncodeToString(make([]byte, 64))
		rec := httptest.NewRecorder()
		s.mintHolderCapability(rec, httptest.NewRequest("POST", "/", strings.NewReader(`{"nonce":"`+p.Nonce+`","setup":{"key_b64":"`+key+`"}}`)), "ctr-a", "app1", "sub")
		if rec.Code != http.StatusCreated {
			t.Fatalf("%v: mint %d %s", c.perms, rec.Code, rec.Body.String())
		}

		mount, exposed := launcher.HolderPaths("ctr-a")
		holder := holderKeyFor("app1", "sub")
		folder := exposed + "/holders/" + holder
		if c.ro {
			f.check(t, "read-only mint", "make "+mount, "bind-ro "+folder, "check-view 4242 /data/holders/"+holder, "seal "+mount)
		} else {
			f.check(t, "writable mint", "make "+mount, "seal "+mount, "unbind "+folder)
		}
		st, open := s.holdersOpen.get(grantKey("app1", p.resource, "sub"))
		if !open || st.ReadOnly != c.ro || st.KeyID != "kid" || st.HolderKey != holder || st.Container != "ctr-a" {
			t.Fatalf("%v: recorded %+v open %v", c.perms, st, open)
		}
	}
}
