package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// PeekedToken is what a bearer SAYS about itself, read WITHOUT verifying it.
// Use it only to decide to withhold a token (the safe direction), never to
// grant anything.
type PeekedToken struct {
	Audiences []string
	Roles     []string
	// ActClientID is act.client_id (RFC 8693): the tool acting for the person.
	ActClientID string
	// Approval: the token carries vault_op, a step-up approval for one vault
	// operation, which never reaches an app.
	Approval bool
}

// Peek reads the audiences and roles a JWT claims, unverified. ok is false
// when tokenStr is not a JWT with a JSON payload.
func Peek(tokenStr, roleClaim string) (PeekedToken, bool) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return PeekedToken{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return PeekedToken{}, false
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return PeekedToken{}, false
	}
	var p PeekedToken
	switch aud := claims["aud"].(type) {
	case string:
		p.Audiences = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				p.Audiences = append(p.Audiences, s)
			}
		}
	}
	if roleClaim == "" {
		roleClaim = "roles"
	}
	p.Roles = collectRoles(claims, roleClaim)
	p.ActClientID = actClientID(claims)
	_, p.Approval = claims[ApprovalClaim]
	return p, true
}

// RoleClaim is the claim this verifier reads roles from.
func (v *Verifier) RoleClaim() string {
	if v == nil {
		return "roles"
	}
	return v.oidc.RoleClaim
}

// actClientID is the RFC 8693 actor claim's client_id, or "".
func actClientID(claims map[string]interface{}) string {
	act, ok := claims["act"].(map[string]interface{})
	if !ok {
		return ""
	}
	id, _ := act["client_id"].(string)
	return strings.TrimSpace(id)
}

// AuthenticateToolCaller verifies a TOOL token for one app: signature, issuer
// and expiry as for any bearer; aud exactly and only "app:"+appHex; the typ
// claim "at+jwt"; an act.client_id naming the tool (the identity provider
// writes act only when a tool mints for an app, never for the app's own
// client); and no roles. It returns the subject, which is the person as that
// app knows them, and the acting tool (act.client_id).
func (v *Verifier) AuthenticateToolCaller(tokenStr, appHex string) (sub, via string, err error) {
	if v == nil {
		return "", "", errors.New("auth: no verifier")
	}
	appHex = strings.ToLower(strings.TrimSpace(appHex))
	if appHex == "" {
		return "", "", errors.New("auth: no app to address")
	}
	want := "app:" + appHex
	claims, err := v.verifyClaimsFor(tokenStr, func(claims map[string]interface{}) error {
		switch aud := claims["aud"].(type) {
		case string:
			if aud == want {
				return nil
			}
		case []interface{}:
			if len(aud) == 1 {
				if s, ok := aud[0].(string); ok && s == want {
					return nil
				}
			}
		}
		return fmt.Errorf("auth: tool token not addressed to %s alone", want)
	})
	if err != nil {
		return "", "", err
	}
	if typ, _ := claims["typ"].(string); typ != "at+jwt" {
		return "", "", errors.New("auth: tool token is not an access token (typ)")
	}
	via = actClientID(claims)
	if via == "" {
		return "", "", errors.New("auth: tool token names no acting tool (act.client_id)")
	}
	if roles := collectRoles(claims, v.oidc.RoleClaim); len(roles) > 0 {
		return "", "", errors.New("auth: tool token carries roles")
	}
	sub, _ = claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return "", "", errors.New("auth: tool token has no subject")
	}
	return sub, via, nil
}
