package appmanifest

import (
	"encoding/base64"
	"testing"
)

// Only an app that declares a marketplace namespace may consume a disclosure
// voucher. Every ordinary app declares none, which is what stops one spending
// an attester's voucher on its own unrelated 2xx.
func TestAttributeProvider(t *testing.T) {
	ordinary := `{"tools": [{"name": "browse", "role": "action", "endpoint": "/browse"}]}`
	if got := AttributeProvider(ordinary); got != "" {
		t.Errorf("an ordinary app declared the provider %q", got)
	}
	attester := `{"x-privasys": {"attribute_provider": " privasys "},
	              "tools": [{"name": "prove", "role": "action", "endpoint": "/prove/field"}]}`
	if got := AttributeProvider(attester); got != "privasys" {
		t.Errorf("attester provider = %q, want privasys", got)
	}
	if got := AttributeProvider(base64.StdEncoding.EncodeToString([]byte(attester))); got != "privasys" {
		t.Errorf("base64 attester provider = %q, want privasys", got)
	}
	for name, raw := range map[string]string{
		"garbage":       "not a manifest",
		"empty":         "",
		"no x-privasys": `{"tools": []}`,
	} {
		if got := AttributeProvider(raw); got != "" {
			t.Errorf("%s yielded the provider %q", name, got)
		}
	}
}
