// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessionrelay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// TestEncAuthVerify_HappyPath confirms that an envelope produced with
// the same canonical CBOR + ES256 (R||S) primitives the IdP and
// wallet use is accepted, and that flipping any byte breaks
// verification.
func TestEncAuthVerify_HappyPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	// Synthetic enclave identity.
	encStaticPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encPub := elliptic.Marshal(elliptic.P256(), encStaticPriv.PublicKey.X, encStaticPriv.PublicKey.Y)

	// Synthetic wallet hardware key.
	hwPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hwPub := elliptic.Marshal(elliptic.P256(), hwPriv.PublicKey.X, hwPriv.PublicKey.Y)

	// Synthetic IdP signing key (acts as the "JWKS" for this test).
	idpPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Build canonical CBOR payload.
	payload := EncAuthPayload{
		V: 1, Sub: "user-1", SID: "sid-abc",
		AppID: bytes32(0xa1), EncMeas: bytes32(0xe1),
		EncPub: encPub, QuoteHash: bytes32(0xb2),
		NotBefore: uint64(now.Unix()) - 10,
		NotAfter:  uint64(now.Unix()) + 3600,
		HwPub:     hwPub,
	}
	em, _ := cbor.CTAP2EncOptions().EncMode()
	cborBytes, err := em.Marshal(&payload)
	if err != nil {
		t.Fatal(err)
	}
	hwSig := signRaw64(t, hwPriv, cborBytes)
	idpInput := append(append([]byte(nil), cborBytes...), hwSig...)
	idpSig := signRaw64(t, idpPriv, idpInput)

	env := &EncAuthEnvelope{
		V:       1,
		Payload: base64.RawURLEncoding.EncodeToString(cborBytes),
		HwSig:   base64.RawURLEncoding.EncodeToString(hwSig),
		IdpSig:  base64.RawURLEncoding.EncodeToString(idpSig),
	}

	v := &DefaultEncAuthVerifier{Resolver: JWKSResolverFunc(
		func(_ context.Context, _ string) (*ecdsa.PublicKey, error) {
			return &idpPriv.PublicKey, nil
		},
	)}

	got, err := v.Verify(env, encPub, [32]byte{}, false, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.SID != "sid-abc" || got.Sub != "user-1" {
		t.Fatalf("decoded mismatch: %+v", got)
	}

	// Tamper with payload bytes -> hw_sig fails.
	bad := make([]byte, len(cborBytes))
	copy(bad, cborBytes)
	bad[len(bad)-1] ^= 0x01
	env.Payload = base64.RawURLEncoding.EncodeToString(bad)
	if _, err := v.Verify(env, encPub, [32]byte{}, false, now); err == nil {
		t.Fatal("expected verify failure on tampered payload")
	}
}

// TestEncAuthVerify_EncPubMismatch ensures the enclave refuses
// vouchers issued for a different enclave identity.
func TestEncAuthVerify_EncPubMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	encStaticPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encPub := elliptic.Marshal(elliptic.P256(), encStaticPriv.PublicKey.X, encStaticPriv.PublicKey.Y)

	otherPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub := elliptic.Marshal(elliptic.P256(), otherPriv.PublicKey.X, otherPriv.PublicKey.Y)

	hwPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hwPub := elliptic.Marshal(elliptic.P256(), hwPriv.PublicKey.X, hwPriv.PublicKey.Y)
	idpPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	payload := EncAuthPayload{
		V: 1, Sub: "u", SID: "s",
		AppID: bytes32(1), EncMeas: bytes32(2),
		EncPub: otherPub, QuoteHash: bytes32(3),
		NotBefore: uint64(now.Unix()) - 1,
		NotAfter:  uint64(now.Unix()) + 60,
		HwPub:     hwPub,
	}
	em, _ := cbor.CTAP2EncOptions().EncMode()
	cborBytes, _ := em.Marshal(&payload)
	hwSig := signRaw64(t, hwPriv, cborBytes)
	idpSig := signRaw64(t, idpPriv, append(append([]byte(nil), cborBytes...), hwSig...))
	env := &EncAuthEnvelope{
		V:       1,
		Payload: base64.RawURLEncoding.EncodeToString(cborBytes),
		HwSig:   base64.RawURLEncoding.EncodeToString(hwSig),
		IdpSig:  base64.RawURLEncoding.EncodeToString(idpSig),
	}

	v := &DefaultEncAuthVerifier{Resolver: JWKSResolverFunc(
		func(_ context.Context, _ string) (*ecdsa.PublicKey, error) { return &idpPriv.PublicKey, nil },
	)}
	if _, err := v.Verify(env, encPub, [32]byte{}, false, now); err == nil {
		t.Fatal("expected verify failure on enc_pub mismatch")
	}
}

func signRaw64(t *testing.T, priv *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out
}

func bytes32(v byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = v
	}
	return out
}
