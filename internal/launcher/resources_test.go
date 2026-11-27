package launcher

import "testing"

// An app_storage declaration must say whether the app works unattended: the
// load refuses one that does not, or says it with anything but a bool.
func TestAppStorageDeclarationMustSetUnattended(t *testing.T) {
	for _, opts := range []map[string]any{nil, {}, {"quota": "1G"}, {"unattended": "true"}} {
		err := validateResourceDecls([]ResourceDecl{{Kind: AppStorageKind, Name: "holders", Options: opts}})
		if err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
	for _, v := range []bool{true, false} {
		if err := validateResourceDecls([]ResourceDecl{{Kind: AppStorageKind, Name: "holders", Options: map[string]any{"unattended": v}}}); err != nil {
			t.Errorf("unattended %v refused: %v", v, err)
		}
	}
	if err := validateResourceDecls([]ResourceDecl{{Kind: "storage.folder", Name: "storage"}}); err != nil {
		t.Errorf("another kind needs no option: %v", err)
	}
}
