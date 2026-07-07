// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// splitJWT splits a compact JWS into its three segments, or returns nil when it
// is not a well-formed three-part token.
func splitJWT(tokenStr string) []string {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	return parts
}

// voucherType is the JOSE `typ` the IdP stamps on a disclosure voucher, so a
// voucher can never be mistaken for (or minted from) an ordinary access token
// even though both are signed by the same issuer key.
const voucherType = "voucher+jwt"

// VoucherClaims are the fields a verified disclosure voucher carries. It
// authorises the bearer (the wallet, acting for a relying party) to obtain the
// listed attribute claims from this issuing app, and is the settlement handle
// (JTI) the runtime reports back once the app has served the disclosure. It
// deliberately carries NO user identity — billing is per relying party.
type VoucherClaims struct {
	JTI      string   // reservation / settlement handle (unique per mint)
	RPID     string   // the relying party the disclosure is billed to
	Provider string   // provider namespace whose app must serve this
	Claims   []string // authorised attribute keys, e.g. ["privasys:age_over_18"]
	Credits  int64    // reserved price (informational; the ledger is authoritative)
}

// VerifyVoucher verifies a disclosure voucher against the IdP JWKS this verifier
// already trusts (same issuer as platform tokens) and returns its claims. It
// enforces the signature, the issuer, the `voucher+jwt` type and expiry, but
// applies NO audience or role requirement — a voucher is not an access token.
func (v *Verifier) VerifyVoucher(tokenStr string) (*VoucherClaims, error) {
	parts := splitJWT(tokenStr)
	if parts == nil {
		return nil, errors.New("auth: malformed voucher")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth: voucher header decode: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("auth: voucher header parse: %w", err)
	}
	if header.Typ != voucherType {
		return nil, fmt.Errorf("auth: voucher typ %q != %q", header.Typ, voucherType)
	}

	jwk, err := v.getSigningKey(header.Kid, header.Alg)
	if err != nil {
		return nil, fmt.Errorf("auth: voucher JWKS lookup: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("auth: voucher sig decode: %w", err)
	}
	if err := jwkVerify(header.Alg, jwk, signingInput, sigBytes); err != nil {
		return nil, fmt.Errorf("auth: voucher sig: %w", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth: voucher claims decode: %w", err)
	}
	var raw struct {
		Iss      string   `json:"iss"`
		Exp      float64  `json:"exp"`
		JTI      string   `json:"jti"`
		RPID     string   `json:"rp_id"`
		Provider string   `json:"provider"`
		Claims   []string `json:"claims"`
		Credits  int64    `json:"credits"`
	}
	if err := json.Unmarshal(claimsJSON, &raw); err != nil {
		return nil, fmt.Errorf("auth: voucher claims parse: %w", err)
	}
	if raw.Iss != v.oidc.Issuer {
		return nil, fmt.Errorf("auth: voucher issuer %q != %q", raw.Iss, v.oidc.Issuer)
	}
	if raw.Exp != 0 && time.Now().Unix() > int64(raw.Exp) {
		return nil, errors.New("auth: voucher expired")
	}
	if raw.JTI == "" {
		return nil, errors.New("auth: voucher missing jti")
	}
	return &VoucherClaims{
		JTI:      raw.JTI,
		RPID:     raw.RPID,
		Provider: raw.Provider,
		Claims:   raw.Claims,
		Credits:  raw.Credits,
	}, nil
}
