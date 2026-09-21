// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package apppolicy holds the authorisation statements an app's owner makes
// about it, approved by the owner in their wallet, and verified here before
// the runtime enforces them.
//
// Until now the runtime took these from whoever held the platform manager
// role: who owns the app, which peers it may call, and who may call it. The
// control plane distributes that policy, which is fine, but it should not be
// able to author it: an operator could otherwise point an app at a peer of
// their choosing, or name themselves its owner.
//
// A policy document is a small JSON object:
//
//	{"v":1,"app_id":"<32 hex>","seq":4,"issued_at":1789...,
//	 "owners":[...],"dependencies":{...},"allowed_callers":{...},
//	 "constellation":{...}}
//
// It travels with a step-up approval token: the owner approved this exact
// document on their phone, the identity provider signed that approval, and the
// token's `vault_op` binds it to the operation
//
//	handle            app:<app id>:policy
//	measurement       SHA-256 of the document bytes
//	policy_version    the document's seq
//
// which this package recomputes from the document in front of it. The same
// ceremony, and the same binding, that a vault promote uses. A token approving
// one document therefore cannot install another, and a document with no
// approval cannot be installed at all.
//
// The first document an app accepts pins the approver's subject. Afterwards
// only that subject's approvals are accepted, and only with a higher seq, so
// the party distributing policy can neither author nor replay it. The approver
// is changed by a document that names the next one and is approved by the
// current one.
//
// Entries name a peer by app id rather than by measurement wherever the owner
// is content with "any build of that app". That is what keeps this practical:
// a peer's ordinary release does not invalidate the approval, so the wallet is
// not needed on every roll. An owner who wants a specific build still pins
// measurements, and approves again when it moves.
package apppolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// BindingDomain prefixes the operation binding. It matches the identity
// provider's vault-approval domain, because this is that ceremony.
const BindingDomain = "privasys-vault-approval/v1"

// Version is the only document version this runtime accepts.
const Version = 1

// HandleFor is the operation handle an app's policy approvals are bound to.
// The "app:" namespace is disjoint from vault key handles, so a policy
// approval can never stand for a vault operation.
func HandleFor(appID string) string {
	return "app:" + strings.ToLower(appID) + ":policy"
}

// Document is an owner's statement about one app.
type Document struct {
	V        int    `json:"v"`
	AppID    string `json:"app_id"`
	Seq      uint64 `json:"seq"`
	IssuedAt int64  `json:"issued_at,omitempty"`

	// Approver, when set, names the subject who must approve the NEXT
	// document. Omitted keeps the current one. It is how an app changes hands
	// without losing the property that only its owner may change its policy.
	Approver string `json:"approver,omitempty"`

	// Owners are the platform subjects the configure gate admits.
	Owners []string `json:"owners,omitempty"`
	// Dependencies and AllowedCallers are carried verbatim: this package
	// checks who said them, not what they mean. The launcher and the ingress
	// verifier remain the only readers of their contents.
	Dependencies   json.RawMessage `json:"dependencies,omitempty"`
	AllowedCallers json.RawMessage `json:"allowed_callers,omitempty"`
	// Constellation pins where this app's data key lives, so the control
	// plane cannot steer a new key onto a constellation it chose.
	Constellation *Constellation `json:"constellation,omitempty"`
}

// Approved is a document with the owner's approval, as it travels.
type Approved struct {
	Document      json.RawMessage `json:"document"`
	ApprovalToken string          `json:"approval_token"`
}

// Parse decodes the envelope and checks the document's shape. It returns the
// document, the exact bytes it arrived as, and the approval token. The token
// is not verified here: that needs the identity provider's keys.
func Parse(raw []byte) (*Document, []byte, string, error) {
	var env Approved
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, "", fmt.Errorf("apppolicy: parse envelope: %w", err)
	}
	if len(env.Document) == 0 {
		return nil, nil, "", fmt.Errorf("apppolicy: envelope carries no document")
	}
	if strings.TrimSpace(env.ApprovalToken) == "" {
		return nil, nil, "", fmt.Errorf("apppolicy: envelope carries no approval token")
	}
	var doc Document
	dec := json.NewDecoder(bytes.NewReader(env.Document))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, "", fmt.Errorf("apppolicy: parse document: %w", err)
	}
	if doc.V != Version {
		return nil, nil, "", fmt.Errorf("apppolicy: document version %d, want %d", doc.V, Version)
	}
	if doc.AppID == "" {
		return nil, nil, "", fmt.Errorf("apppolicy: document names no app")
	}
	if doc.Seq == 0 {
		return nil, nil, "", fmt.Errorf("apppolicy: document seq must be 1 or more")
	}
	return &doc, append([]byte(nil), env.Document...), strings.TrimSpace(env.ApprovalToken), nil
}

// DocumentDigest is the value the approval binds: the SHA-256 of the exact
// document bytes, lowercase hex.
func DocumentDigest(rawDoc []byte) string {
	sum := sha256.Sum256(rawDoc)
	return hex.EncodeToString(sum[:])
}

// Binding recomputes the operation binding the approver's assertion signed:
// SHA-256 over the domain, handle, measurement, policy version, nonce and
// expiry, newline-joined. The identity provider and the vault compute it the
// same way.
func Binding(handle, measurementHex string, policyVersion uint64, nonce string, exp int64) string {
	input := fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%d",
		BindingDomain, handle, measurementHex, policyVersion, nonce, exp)
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// CheckApproval verifies that the claims of an already-verified approval token
// approve this document, and returns the approving subject.
//
// The caller has checked the token's signature, issuer, audience and expiry.
// What is checked here is that the approval is for THIS document: the binding
// is recomputed from the document in hand plus the token's own nonce and
// expiry, so a token approving anything else fails.
func CheckApproval(doc *Document, rawDoc []byte, claims map[string]interface{}) (string, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("apppolicy: approval names no subject")
	}
	if !hasWebAuthn(claims["amr"]) {
		return "", fmt.Errorf("apppolicy: approval was not a step-up (amr lacks webauthn)")
	}
	vaultOp, _ := claims["vault_op"].(string)
	nonce, _ := claims["nonce"].(string)
	if vaultOp == "" || nonce == "" {
		return "", fmt.Errorf("apppolicy: approval carries no operation binding")
	}
	expF, ok := claims["exp"].(float64)
	if !ok {
		return "", fmt.Errorf("apppolicy: approval carries no expiry")
	}
	want := Binding(HandleFor(doc.AppID), DocumentDigest(rawDoc), doc.Seq, nonce, int64(expF))
	if !strings.EqualFold(want, vaultOp) {
		return "", fmt.Errorf("apppolicy: the approval does not bind this document")
	}
	return sub, nil
}

// hasWebAuthn reports whether the authentication-methods claim records a
// step-up. An approval is a deliberate act at the owner's device, not a
// password session.
func hasWebAuthn(amr interface{}) bool {
	switch v := amr.(type) {
	case string:
		return v == "webauthn"
	case []interface{}:
		for _, m := range v {
			if s, _ := m.(string); s == "webauthn" {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == "webauthn" {
				return true
			}
		}
	}
	return false
}

// Constellation is where an app's data key lives: the vault instances and the
// measurement they must present. An app whose owner has approved one refuses
// to resolve its key anywhere else, whatever the load request says.
type Constellation struct {
	Mrenclave string   `json:"mrenclave"`
	Endpoints []string `json:"endpoints"`
}

// Valid reports whether a constellation is usable: without a measurement and
// at least one endpoint it would pin nothing.
func (c *Constellation) Valid() bool {
	return c != nil && strings.TrimSpace(c.Mrenclave) != "" && len(c.Endpoints) > 0
}

// Matches reports whether a load request's constellation is the approved one.
// Endpoint order is not significant; the set is.
func (c *Constellation) Matches(mrenclave string, endpoints []string) bool {
	if !c.Valid() {
		return true // nothing approved, nothing to contradict
	}
	if !strings.EqualFold(strings.TrimSpace(mrenclave), strings.TrimSpace(c.Mrenclave)) {
		return false
	}
	if len(endpoints) != len(c.Endpoints) {
		return false
	}
	want := make(map[string]int, len(c.Endpoints))
	for _, e := range c.Endpoints {
		want[strings.TrimSpace(e)]++
	}
	for _, e := range endpoints {
		key := strings.TrimSpace(e)
		if want[key] == 0 {
			return false
		}
		want[key]--
	}
	return true
}
