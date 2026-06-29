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
		WorkloadDigest: bytes32(0xa1), EncMeas: bytes32(0xe1),
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

	got, err := v.Verify(env, VerifyContext{EncStaticPub: encPub, Now: now})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.SID != "sid-abc" || got.Sub != "user-1" {
		t.Fatalf("decoded mismatch: %+v", got)
	}

	// Sc 1: armed with the matching workload digest (payload
	// WorkloadDigest = bytes32(0xa1)) is accepted; armed with a different
	// digest is rejected (the app code/config changed).
	if _, err := v.Verify(env, VerifyContext{
		EncStaticPub: encPub, Now: now,
		ExpectedWorkloadDigest: to32(bytes32(0xa1)), HasExpectedWorkloadDigest: true,
	}); err != nil {
		t.Fatalf("verify with matching workload digest: %v", err)
	}
	if _, err := v.Verify(env, VerifyContext{
		EncStaticPub: encPub, Now: now,
		ExpectedWorkloadDigest: to32(bytes32(0xc3)), HasExpectedWorkloadDigest: true,
	}); err == nil {
		t.Fatal("expected verify failure on workload-digest mismatch")
	}

	// Tamper with payload bytes -> hw_sig fails.
	bad := make([]byte, len(cborBytes))
	copy(bad, cborBytes)
	bad[len(bad)-1] ^= 0x01
	env.Payload = base64.RawURLEncoding.EncodeToString(bad)
	if _, err := v.Verify(env, VerifyContext{EncStaticPub: encPub, Now: now}); err == nil {
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
		WorkloadDigest: bytes32(1), EncMeas: bytes32(2),
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
	if _, err := v.Verify(env, VerifyContext{EncStaticPub: encPub, Now: now}); err == nil {
		t.Fatal("expected verify failure on enc_pub mismatch")
	}
}

// TestEncStaticKeyFromSeed_Deterministic confirms Sc 2's identity-key
// rebuild is deterministic (same vault seed -> same enc_pub) and that
// installing it changes the manager's enc_pub, so a voucher bound to the
// old key is rejected after a measurement-driven rotation.
func TestEncStaticKeyFromSeed_Deterministic(t *testing.T) {
	seedA := bytes32(0x11)
	k1, err := EncStaticKeyFromSeed(seedA)
	if err != nil {
		t.Fatalf("from seed: %v", err)
	}
	k2, err := EncStaticKeyFromSeed(seedA)
	if err != nil {
		t.Fatalf("from seed (2): %v", err)
	}
	if !bytesEq(k1.PublicKey().Bytes(), k2.PublicKey().Bytes()) {
		t.Fatal("same seed must yield the same enc_pub")
	}

	seedB := bytes32(0x22)
	kB, err := EncStaticKeyFromSeed(seedB)
	if err != nil {
		t.Fatalf("from seed B: %v", err)
	}
	if bytesEq(k1.PublicKey().Bytes(), kB.PublicKey().Bytes()) {
		t.Fatal("different seeds must yield different enc_pub")
	}

	m := NewManager()
	const host = "app-a.apps-test.privasys.org"
	if err := m.SetEncStaticKeyForHost(host, k1); err != nil {
		t.Fatalf("install key: %v", err)
	}
	if !bytesEq(m.EncStaticPubForHost(host), k1.PublicKey().Bytes()) {
		t.Fatal("installed key must drive that host's enc_pub")
	}
	// A different host is unaffected by host A's install (no key → nil).
	if bytesEq(m.EncStaticPubForHost("app-b.apps-test.privasys.org"), k1.PublicKey().Bytes()) {
		t.Fatal("enc_pub must be per-host")
	}
	if err := m.SetEncStaticKeyForHost(host, nil); err == nil {
		t.Fatal("nil key must be rejected")
	}
	if _, err := EncStaticKeyFromSeed([]byte{1, 2, 3}); err == nil {
		t.Fatal("short seed must be rejected")
	}
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func to32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
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
