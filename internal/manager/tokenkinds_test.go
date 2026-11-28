package manager

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/apifees"
	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// TestWhichTokensEachGateAccepts pins, for every kind of bearer, what each
// gate that verifies one makes of it. A change to the verifier or to how a
// gate reads the caller must leave this table as it is, unless the change
// means to move a cell, and then the cell moves in the same commit.
//
// A cell is "-" when the gate refuses the token or takes nothing from it,
// otherwise what the gate took: a role, a subject, "ok".
func TestWhichTokensEachGateAccepts(t *testing.T) {
	s, iss := newIdentityServer(t)
	s.appIDOf = func(string) string { return toolAppID }
	const plat = "enclave-os-virtual"
	appRole := func(r string) string { return plat + ":app:" + toolAppHex + ":" + r }
	act := map[string]any{"client_id": "privasys-wallet"}
	past := float64(time.Now().Add(-time.Minute).Unix())

	other := &identityIssuer{key: iss.key, issuer: "https://other.example"}
	forged := func(tok string) string { return tok[:len(tok)-4] + "AAAA" }
	// Every token carries a profile, so a gate that only adds one (a sealed
	// session's) shows whether it took the token.
	mk := func(i *identityIssuer, sub, aud string, extra map[string]any) string {
		claims := map[string]any{}
		for k, v := range withProfile {
			claims[k] = v
		}
		for k, v := range extra {
			claims[k] = v
		}
		return i.token(t, sub, aud, claims)
	}

	tokens := map[string]string{
		"platform manager":      mk(iss, "p1", plat, map[string]any{"roles": []string{"privasys-platform:manager"}}),
		"platform monitoring":   mk(iss, "p1", plat, map[string]any{"roles": []string{"privasys-platform:monitoring"}}),
		"platform app owner":    mk(iss, "p1", plat, map[string]any{"roles": []string{appRole("owner")}}),
		"platform app admin":    mk(iss, "p1", plat, map[string]any{"roles": []string{appRole("admin")}}),
		"platform user":         mk(iss, "p1", plat, nil),
		"platform wallet user":  mk(iss, "p1", plat, map[string]any{"wallet": true}),
		"platform custom role":  mk(iss, "p1", plat, map[string]any{"roles": []string{"drive:reader"}}),
		"platform owners-list":  mk(iss, "owner-sub", plat, nil),
		"app host user":         mk(iss, "p1", surfHost, withProfile),
		"app own client":        mk(iss, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt"}),
		"tool for this app":     mk(iss, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt", "act": act}),
		"tool for another app":  mk(iss, "p1", "app:ffffffffffffffffffffffffffffffff", map[string]any{"typ": "at+jwt", "act": act}),
		"approval, platform":    mk(iss, "p1", plat, map[string]any{"roles": []string{"privasys-platform:manager"}, auth.ApprovalClaim: "x"}),
		"approval, app host":    mk(iss, "p1", surfHost, map[string]any{auth.ApprovalClaim: "x"}),
		"approval, tool":        mk(iss, "p1", "app:"+toolAppHex, map[string]any{"typ": "at+jwt", "act": act, auth.ApprovalClaim: "x"}),
		"expired manager":       mk(iss, "p1", plat, map[string]any{"roles": []string{"privasys-platform:manager"}, "exp": past}),
		"manager without exp":   mk(iss, "p1", plat, map[string]any{"roles": []string{"privasys-platform:manager"}, "exp": nil}),
		"manager, other issuer": mk(other, "p1", plat, map[string]any{"roles": []string{"privasys-platform:manager"}}),
		"manager, forged":       forged(mk(iss, "p1", plat, map[string]any{"roles": []string{"privasys-platform:manager"}})),
		"not a JWT":             "opaque-token",
	}

	bearer := func(tok string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://"+surfHost+"/v1/x", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}
	errCell := func(v string, err error) string {
		if err != nil {
			return "-"
		}
		return v
	}
	st := launcher.FreezeState{AppID: toolAppID, Owners: []string{"owner-sub"}}

	gates := map[string]func(tok string) string{
		"management api": func(tok string) string {
			got := "-"
			s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
				got = r.Context().Value(authResultKey).(*auth.AuthResult).Role
			})(httptest.NewRecorder(), bearer(tok))
			return got
		},
		"configure": func(tok string) string {
			sub, role, err := s.configureGrant(bearer(tok), "c", st)
			return errCell(role+" "+sub, err)
		},
		"route authenticated": func(tok string) string {
			return errCell("ok", s.authorizeOtherRoute(bearer(tok), "c", apifees.RouteAuth{Policy: apifees.PolicyAuthenticated}))
		},
		"route role": func(tok string) string {
			return errCell("ok", s.authorizeOtherRoute(bearer(tok), "c", apifees.RouteAuth{Policy: apifees.PolicyRole, Roles: []string{"drive:reader"}}))
		},
		"payer": func(tok string) string {
			if sub := s.callerIdentity(bearer(tok)); sub != "" {
				return sub
			}
			return "-"
		},
		"holder": func(tok string) string {
			sub, wallet, ok := s.holderCaller(httptest.NewRecorder(), bearer(tok))
			if !ok {
				return "-"
			}
			return fmt.Sprintf("%s wallet=%v", sub, wallet)
		},
		"tool caller": func(tok string) string {
			if sub, via := s.toolCaller(bearer(tok)); sub != "" {
				return sub + " via " + via
			}
			return "-"
		},
		"direct name": func(tok string) string {
			r, ok := s.serveDirect(httptest.NewRecorder(), directRequest(tok))
			if !ok {
				return "-"
			}
			return r.Header.Get("X-Privasys-Sub") + " " + r.Header.Get(AttestationLevelHeader)
		},
		"sealed, session p1": func(tok string) string {
			r := s.assertSealedIdentity(sealedRequest("p1", tok))
			if e := r.Header.Get(emailHeader); e != "" {
				return "profile"
			}
			return "-"
		},
		"sealed, no session subject": func(tok string) string {
			r := s.assertSealedIdentity(sealedRequest("", tok))
			if sub := r.Header.Get("X-Privasys-Sub"); sub != "" {
				return sub
			}
			return "-"
		},
		"vault approval": func(tok string) string {
			c, err := s.verifier.VerifyApprovalToken(tok)
			if err != nil {
				return "-"
			}
			if _, ok := c[auth.ApprovalClaim]; ok {
				return "approval"
			}
			return "token"
		},
	}

	want := map[string]map[string]string{
		"app host user":         {"configure": "-", "direct name": "p1 unverified", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "p1", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "-"},
		"app own client":        {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "-"},
		"approval, app host":    {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "-"},
		"approval, platform":    {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "approval"},
		"approval, tool":        {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "-"},
		"expired manager":       {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "-"},
		"manager without exp":   {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "-"},
		"manager, forged":       {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "-"},
		"manager, other issuer": {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "-"},
		"not a JWT":             {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "-"},
		"platform app admin":    {"configure": "admin p1", "direct name": "-", "holder": "p1 wallet=false", "management api": "-", "payer": "p1", "route authenticated": "ok", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "token"},
		"platform app owner":    {"configure": "owner p1", "direct name": "-", "holder": "p1 wallet=false", "management api": "-", "payer": "p1", "route authenticated": "ok", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "token"},
		"platform custom role":  {"configure": "-", "direct name": "-", "holder": "p1 wallet=false", "management api": "-", "payer": "p1", "route authenticated": "ok", "route role": "ok", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "token"},
		"platform manager":      {"configure": "-", "direct name": "-", "holder": "p1 wallet=false", "management api": "manager", "payer": "p1", "route authenticated": "ok", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "token"},
		"platform monitoring":   {"configure": "-", "direct name": "-", "holder": "p1 wallet=false", "management api": "monitoring", "payer": "p1", "route authenticated": "ok", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "token"},
		"platform owners-list":  {"configure": "owner owner-sub", "direct name": "-", "holder": "owner-sub wallet=false", "management api": "-", "payer": "owner-sub", "route authenticated": "ok", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "-", "tool caller": "-", "vault approval": "token"},
		"platform user":         {"configure": "-", "direct name": "-", "holder": "p1 wallet=false", "management api": "-", "payer": "p1", "route authenticated": "ok", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "token"},
		"platform wallet user":  {"configure": "-", "direct name": "-", "holder": "p1 wallet=true", "management api": "-", "payer": "p1", "route authenticated": "ok", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "token"},
		"tool for another app":  {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "-", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "-", "vault approval": "-"},
		"tool for this app":     {"configure": "-", "direct name": "-", "holder": "-", "management api": "-", "payer": "p1", "route authenticated": "-", "route role": "-", "sealed, no session subject": "-", "sealed, session p1": "profile", "tool caller": "p1 via privasys-wallet", "vault approval": "-"},
	}
	if len(want) != len(tokens) {
		t.Fatalf("the table names %d token kinds, the test makes %d", len(want), len(tokens))
	}
	for tk, tok := range tokens {
		row, ok := want[tk]
		if !ok {
			t.Errorf("%s: not in the table", tk)
			continue
		}
		if len(row) != len(gates) {
			t.Errorf("%s: the table names %d gates, the test has %d", tk, len(row), len(gates))
		}
		for g, fn := range gates {
			if got := fn(tok); got != row[g] {
				t.Errorf("%s at %s: %q, want %q", tk, g, got, row[g])
			}
		}
	}
}
