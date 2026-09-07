package launcher

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// bearerExpiry reads the exp claim of a JWT bearer without verifying it (the
// caller only uses it to decide how long the token is worth caching; the
// attestation server does the verification). Returns false for non-JWT
// tokens or tokens without exp.
func bearerExpiry(tok string) (time.Time, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(claims.Exp), 0), true
}
