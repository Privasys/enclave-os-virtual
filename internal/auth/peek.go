package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// PeekedToken is what a bearer SAYS about itself, read WITHOUT verifying it.
// Use it only to decide to withhold a token (the safe direction), never to
// grant anything.
type PeekedToken struct {
	Audiences []string
	Roles     []string
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
	return p, true
}

// RoleClaim is the claim this verifier reads roles from.
func (v *Verifier) RoleClaim() string {
	if v == nil {
		return "roles"
	}
	return v.oidc.RoleClaim
}
