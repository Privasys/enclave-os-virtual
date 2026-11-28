package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
)

// Claims is what a verified bearer says.
type Claims struct {
	// Sub is the subject. Never empty: a token naming no one is refused.
	Sub string
	// Roles are every role the token carries, from the configured role
	// claim, "roles" and Keycloak's realm_access.roles.
	Roles []string
	// Wallet: the sign-in was the wallet (the identity provider's `wallet`
	// marker, boolean true or the string "true").
	Wallet bool
	// Email is an address the token says was proved (email_verified); one the
	// holder merely typed is left out. Email and Name are empty unless this
	// token carries them: the identity provider keeps no profile, so only the
	// token minted at the code exchange does, never one minted by refresh.
	Email string
	Name  string
	// Exp is the token's expiry: a connection opened on it (a WebSocket on a
	// direct name) ends then.
	Exp time.Time
	// ActClientID is act.client_id (RFC 8693): the tool acting for the
	// person, or "".
	ActClientID string
	// Containers is the token's "containers" claim, nil when it has none.
	Containers []ContainerPermission

	audiences []string
	typ       string
}

// AudienceRule decides whether a verified token is meant for this caller.
// Signature, issuer, expiry and the refusal of a step-up approval are
// checked before it, the same way for every rule.
type AudienceRule func(c *Claims) error

// PlatformAudience accepts a token minted for the platform: one whose
// audience includes the configured platform audience.
func (v *Verifier) PlatformAudience() AudienceRule {
	want := v.oidc.Audience
	return func(c *Claims) error {
		if want != "" && !slices.Contains(c.audiences, want) {
			return fmt.Errorf("auth: OIDC audience missing %q", want)
		}
		return nil
	}
}

// AppAudience accepts a token an end user presents to ONE app: its audience
// must be one of the app's own, never the platform audience, so a token
// minted for one app cannot be replayed to another.
func AppAudience(audiences []string) AudienceRule {
	return func(c *Claims) error {
		for _, a := range audiences {
			if a != "" && slices.Contains(c.audiences, a) {
				return nil
			}
		}
		return fmt.Errorf("auth: token audience is not this app (%v)", audiences)
	}
}

// SameSubject accepts a token presented inside a session already
// authenticated as sub. The audience is not the check here, the subject is:
// the session has proved who this is, and a token naming that same subject
// can only add what the identity provider said about them.
func SameSubject(sub string) AudienceRule {
	return func(c *Claims) error {
		if sub == "" {
			return errors.New("auth: no subject to check the token against")
		}
		if c.Sub != sub {
			return errors.New("auth: token names another subject")
		}
		return nil
	}
}

// ToolFor accepts a TOOL token for one app: aud exactly and only
// "app:"+appHex, the typ claim "at+jwt", an act.client_id naming the tool
// (the identity provider writes act only when a tool mints for an app, never
// for the app's own client), and no roles. Its subject is the person as that
// app knows them.
func ToolFor(appHex string) AudienceRule {
	appHex = strings.ToLower(strings.TrimSpace(appHex))
	return func(c *Claims) error {
		if appHex == "" {
			return errors.New("auth: no app to address")
		}
		if want := "app:" + appHex; len(c.audiences) != 1 || c.audiences[0] != want {
			return fmt.Errorf("auth: tool token not addressed to %s alone", want)
		}
		if c.typ != "at+jwt" {
			return errors.New("auth: tool token is not an access token (typ)")
		}
		if c.ActClientID == "" {
			return errors.New("auth: tool token names no acting tool (act.client_id)")
		}
		if len(c.Roles) > 0 {
			return errors.New("auth: tool token carries roles")
		}
		return nil
	}
}

// Verify checks a bearer: signature against the issuer's keys, issuer,
// expiry against trusted time, that it names a subject and is not a step-up
// approval, and then the audience rule. It is the one way a bearer is
// verified; VerifyApprovalToken is the one exception.
func (v *Verifier) Verify(tokenStr string, rule AudienceRule) (*Claims, error) {
	if v == nil {
		return nil, errors.New("auth: no verifier")
	}
	raw, err := v.verifySigned(tokenStr)
	if err != nil {
		return nil, err
	}
	if _, ok := raw[ApprovalClaim]; ok {
		return nil, errors.New("auth: a vault approval is not a bearer")
	}
	c := v.claimsOf(raw)
	if strings.TrimSpace(c.Sub) == "" {
		return nil, errors.New("auth: token names no subject")
	}
	if err := rule(c); err != nil {
		return nil, err
	}
	return c, nil
}

// VerifyApprovalToken verifies an identity-provider token minted for the
// platform and returns its claims, for callers that check an operation
// binding rather than a role: a step-up approval carries the operation it
// approves in `vault_op`, and the verifier of that operation recomputes the
// binding itself. Signature, issuer, audience and expiry are checked exactly
// as for any other token, expiry against trusted time.
func (v *Verifier) VerifyApprovalToken(tokenStr string) (map[string]interface{}, error) {
	raw, err := v.verifySigned(tokenStr)
	if err != nil {
		return nil, err
	}
	if err := v.PlatformAudience()(v.claimsOf(raw)); err != nil {
		return nil, err
	}
	return raw, nil
}

// ManagementAccess is the management API's reading of a platform token: the
// manager role (mutating operations) or the monitoring role (read-only), and
// the containers the token is limited to.
func (v *Verifier) ManagementAccess(c *Claims) (*AuthResult, error) {
	role := ""
	switch {
	case slices.Contains(c.Roles, v.oidc.ManagerRole):
		role = "manager"
	case slices.Contains(c.Roles, v.oidc.MonitoringRole):
		role = "monitoring"
	default:
		return nil, fmt.Errorf("auth: OIDC token missing required role (%s or %s)", v.oidc.ManagerRole, v.oidc.MonitoringRole)
	}
	return &AuthResult{Source: "oidc", Role: role, Subject: c.Sub, Containers: c.Containers}, nil
}

// ApprovalClaim marks a step-up approval: the identity provider mints it for
// ONE vault operation, and only VerifyApprovalToken takes it. As an ordinary
// bearer it would let whoever holds an approval act as its owner.
const ApprovalClaim = "vault_op"

// verifySigned checks signature, issuer and expiry, and returns the claims.
func (v *Verifier) verifySigned(tokenStr string) (map[string]interface{}, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("auth: malformed OIDC token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC header decode: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("auth: OIDC header parse: %w", err)
	}
	jwk, err := v.getSigningKey(header.Kid, header.Alg)
	if err != nil {
		return nil, fmt.Errorf("auth: JWKS lookup: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC sig decode: %w", err)
	}
	if err := jwkVerify(header.Alg, jwk, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, fmt.Errorf("auth: OIDC sig: %w", err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth: OIDC claims decode: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("auth: OIDC claims parse: %w", err)
	}
	if iss, _ := claims["iss"].(string); iss != v.oidc.Issuer {
		return nil, fmt.Errorf("auth: OIDC issuer %q != %q", iss, v.oidc.Issuer)
	}
	// exp is required: without it a token would stay valid for as long as
	// the signing key does.
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("auth: OIDC token has no exp claim")
	}
	// Trusted time, never the host clock: a host that rolls its clock back
	// must not get an expired token accepted. No trusted time, no token.
	trusted, err := trustedtime.Now()
	if err != nil {
		return nil, fmt.Errorf("auth: cannot check token expiry: %w", err)
	}
	now := trusted.Unix()
	if now > int64(exp) {
		return nil, errors.New("auth: OIDC token expired")
	}
	if nbf, ok := claims["nbf"].(float64); ok && now < int64(nbf) {
		return nil, errors.New("auth: OIDC token not yet valid")
	}
	return claims, nil
}

// claimsOf reads the typed claims out of verified raw claims.
func (v *Verifier) claimsOf(raw map[string]interface{}) *Claims {
	c := &Claims{
		Roles:       collectRoles(raw, v.oidc.RoleClaim),
		Wallet:      isTrue(raw["wallet"]),
		ActClientID: actClientID(raw),
		audiences:   audiencesOf(raw),
	}
	c.Sub, _ = raw["sub"].(string)
	c.Name, _ = raw["name"].(string)
	c.typ, _ = raw["typ"].(string)
	if isTrue(raw["email_verified"]) {
		c.Email, _ = raw["email"].(string)
	}
	if exp, ok := raw["exp"].(float64); ok {
		c.Exp = time.Unix(int64(exp), 0)
	}
	if containers, ok := raw["containers"]; ok {
		data, _ := json.Marshal(containers)
		_ = json.Unmarshal(data, &c.Containers)
	}
	return c
}

// isTrue accepts boolean true or the string "true", the same rule as the
// wasm runtime.
func isTrue(v interface{}) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true"
	}
	return false
}

func audiencesOf(claims map[string]interface{}) []string {
	switch aud := claims["aud"].(type) {
	case string:
		return []string{aud}
	case []interface{}:
		var out []string
		for _, a := range aud {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
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

// collectRoles gathers every role string from the configured role claim (a
// map of role to metadata, or an array), the standard "roles" array and
// Keycloak's realm_access.roles, de-duplicated in encounter order.
func collectRoles(claims map[string]interface{}, roleClaim string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		if _, dup := seen[s]; s != "" && !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	addArray := func(raw interface{}) {
		if arr, ok := raw.([]interface{}); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok {
					add(s)
				}
			}
		}
	}
	if roleMap, ok := claims[roleClaim].(map[string]interface{}); ok {
		for name := range roleMap {
			add(name)
		}
	}
	addArray(claims[roleClaim])
	addArray(claims["roles"])
	if ra, ok := claims["realm_access"].(map[string]interface{}); ok {
		addArray(ra["roles"])
	}
	return out
}

// Audience is the platform audience, also the namespace prefix of the
// app-scoped roles this verifier's tokens can carry.
func (v *Verifier) Audience() string { return v.oidc.Audience }
