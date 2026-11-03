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

	u, err := f.verifier.AuthenticateAppUser(tok("app:0123456789abcdef0123456789abcdef", nil), app)
	if err != nil || u.Sub != "pairwise-sub-1" || u.Wallet || u.Email != "" || u.Name != "" {
		t.Fatalf("app-scoped token: %+v err=%v", u, err)
	}
	if u, err = f.verifier.AuthenticateAppUser(tok([]any{"other", "shop.example.com"}, map[string]any{"wallet": "true"}), app); err != nil || !u.Wallet {
		t.Fatalf("hostname audience with the wallet marker: %+v err=%v", u, err)
	}
	if u, err = f.verifier.AuthenticateAppUser(tok(app[0], map[string]any{"email": "ada@example.com", "email_verified": "true", "name": "Ada"}), app); err != nil || u.Email != "ada@example.com" || u.Name != "Ada" {
		t.Fatalf("the token's profile: %+v err=%v", u, err)
	}
	for _, claims := range []map[string]any{
		{"email": "typed@example.com", "name": "Ada"},
		{"email": "typed@example.com", "email_verified": false, "name": "Ada"},
		{"email": "typed@example.com", "email_verified": "false", "name": "Ada"},
	} {
		if u, err = f.verifier.AuthenticateAppUser(tok(app[0], claims), app); err != nil || u.Email != "" || u.Name != "Ada" {
			t.Fatalf("an unproved address: %v gave %+v err=%v", claims, u, err)
		}
	}
	for name, bad := range map[string]string{
		"platform audience": tok("enclave-os-virtual", nil),
		"another app":       tok("app:ffffffffffffffffffffffffffffffff", nil),
		"expired": f.sign(t, "JWT", map[string]any{"iss": f.issuer, "sub": "s", "aud": app[0],
			"exp": float64(time.Now().Add(-time.Minute).Unix())}),
		"no subject": f.sign(t, "JWT", map[string]any{"iss": f.issuer, "aud": app[0],
			"exp": float64(time.Now().Add(time.Minute).Unix())}),
	} {
		if _, err := f.verifier.AuthenticateAppUser(bad, app); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := f.verifier.AuthenticateAppUser(tok(app[0], nil), nil); err == nil {
		t.Error("no app audience configured must refuse")
	}
}

// Inside a session authenticated as a subject, any audience will do but the
// token must name that subject.
func TestAuthenticateSubject(t *testing.T) {
	f := newVoucherFixture(t)
	tok := func(sub string) string {
		return f.sign(t, "JWT", map[string]any{
			"iss": f.issuer, "sub": sub, "aud": "some-client", "name": "Ada",
			"exp": float64(time.Now().Add(10 * time.Minute).Unix()),
		})
	}
	if u, err := f.verifier.AuthenticateSubject(tok("s1"), "s1"); err != nil || u.Name != "Ada" {
		t.Fatalf("same subject: %+v err=%v", u, err)
	}
	if _, err := f.verifier.AuthenticateSubject(tok("s2"), "s1"); err == nil {
		t.Fatal("a token naming another subject must be refused")
	}
	if _, err := f.verifier.AuthenticateSubject(tok("s1"), ""); err == nil {
		t.Fatal("no session subject must refuse")
	}
}
