package launcher

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestBearerExpiry(t *testing.T) {
	exp := time.Now().Add(90 * time.Second).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"x","exp":%d}`, exp)))
	tok := "eyJhbGciOiJSUzI1NiJ9." + payload + ".sig"
	got, ok := bearerExpiry(tok)
	if !ok || got.Unix() != exp {
		t.Fatalf("exp: ok=%v got=%v want=%d", ok, got.Unix(), exp)
	}
	if _, ok := bearerExpiry("opaque-token"); ok {
		t.Fatal("opaque token must not report an expiry")
	}
	if _, ok := bearerExpiry("a." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".b"); ok {
		t.Fatal("token without exp must not report an expiry")
	}
}
