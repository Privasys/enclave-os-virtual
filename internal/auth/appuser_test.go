// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"testing"
	"time"
)

// A bearer on a direct adopter name must be minted for THIS app: the platform
// audience (or another app's) is refused, so a token cannot be replayed from
// one app to another.
func TestAuthenticateAppUser(t *testing.T) {
	f := newVoucherFixture(t)
	tok := func(aud any, extra map[string]any) string {
		c := map[string]any{
			"iss": f.issuer, "sub": "pairwise-sub-1", "aud": aud,
			"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
		}
		for k, v := range extra {
			c[k] = v
		}
		return f.sign(t, "JWT", c)
	}
	app := []string{"app:0123456789abcdef0123456789abcdef", "shop.example.com"}

	sub, wallet, err := f.verifier.AuthenticateAppUser(tok("app:0123456789abcdef0123456789abcdef", nil), app)
	if err != nil || sub != "pairwise-sub-1" || wallet {
		t.Fatalf("app-scoped token: sub=%q wallet=%v err=%v", sub, wallet, err)
	}
	if _, wallet, err = f.verifier.AuthenticateAppUser(tok([]any{"other", "shop.example.com"}, map[string]any{"wallet": "true"}), app); err != nil || !wallet {
		t.Fatalf("hostname audience with the wallet marker: wallet=%v err=%v", wallet, err)
	}
	for name, bad := range map[string]string{
		"platform audience": tok("enclave-os-virtual", nil),
		"another app":       tok("app:ffffffffffffffffffffffffffffffff", nil),
		"expired": f.sign(t, "JWT", map[string]any{"iss": f.issuer, "sub": "s", "aud": app[0],
			"exp": float64(time.Now().Add(-time.Minute).Unix())}),
		"no subject": f.sign(t, "JWT", map[string]any{"iss": f.issuer, "aud": app[0],
			"exp": float64(time.Now().Add(time.Minute).Unix())}),
	} {
		if _, _, err := f.verifier.AuthenticateAppUser(bad, app); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := f.verifier.AuthenticateAppUser(tok(app[0], nil), nil); err == nil {
		t.Error("no app audience configured must refuse")
	}
}
