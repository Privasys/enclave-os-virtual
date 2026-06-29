// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package sessionrelay

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Known-answer tests for the session-relay crypto contract (§9).
//
// This file is the GO REFERENCE for the cross-implementation vectors.
// The same constants are pinned in:
//   - auth/sdk/scripts/kat.mjs                     (TS / WebCrypto, executable)
//   - enclave-os-mini/enclave/src/sessionrelay.rs  (#[cfg(test)] block)
//
// The private scalars are derived deterministically so the vectors are
// reproducible from the spec alone:
//   sdk_priv = SHA-256("privasys-kat-sdk/v1")
//   enc_priv = SHA-256("privasys-kat-enc/v1")
// (both happen to be valid P-256 scalars; this is asserted below).
//
// Changing ANY pinned constant is a wire-format break: bump the HKDF
// info string / envelope version and add a new vector set instead.

const (
	katSessionIDRawHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"

	// ECDH layer.
	katSdkPubSec1Hex = "04e36eef3794039af0273a59831da695cef92dfeee2d4a4b24e08d5d35aed2f8f877b9a7527733910e82f88a86afa506a47a245a86a2b95d3722c28d8f1ac6bfb4"
	katEncPubSec1Hex = "04dd511dcde3875568de732fde5634d8940b5bcfef668ace46f28bd813a27eb6af695e2fe52acb03f4d158a46335e0a726765540290c28614379953e1ab483d924"
	katSharedXHex    = "c8ea8e6c84d602681a335ae3a8d18d850709405564daf0cf88dbfc5b91fe4603"

	// HKDF layer (salt = raw session-id bytes, ikm = shared X).
	katAeadKeyHex   = "175873bdd2a8c941c0cb5a4dbcd896a016976103df5c3b695ae8581d431e74b2"
	katC2SPrefixHex = "d7e246d2"
	katS2CPrefixHex = "803a6769"

	// AEAD framing layer (ctr = 0 both directions).
	katPath        = "/v1/chat/completions"
	katRequestPT   = `{"kat":"privasys-session-relay"}`
	katResponsePT  = `{"ok":true}`
	katRequestEnv  = "a361760163637472006263745830f6868ef8c27ae5260300135329bbbb941825c36ec5b29143df5110e64cc42a98a26521ac449d50153594ffcfd35f7f92"
	katResponseEnv = "a36176016363747200626374581b27445f008c6ee1a871bff6df237343c1fde2cec805bc23ca31c59c"
)

// katGenerate=true prints the vectors instead of asserting them. Flip
// only when intentionally regenerating (which is a wire-format break).
const katGenerate = false

func katScalars(t *testing.T) (*ecdh.PrivateKey, *ecdh.PrivateKey) {
	t.Helper()
	curve := ecdh.P256()
	sdkScalar := sha256.Sum256([]byte("privasys-kat-sdk/v1"))
	encScalar := sha256.Sum256([]byte("privasys-kat-enc/v1"))
	sdkPriv, err := curve.NewPrivateKey(sdkScalar[:])
	if err != nil {
		t.Fatalf("sdk scalar invalid: %v", err)
	}
	encPriv, err := curve.NewPrivateKey(encScalar[:])
	if err != nil {
		t.Fatalf("enc scalar invalid: %v", err)
	}
	return sdkPriv, encPriv
}

func TestSessionRelayKATs(t *testing.T) {
	sdkPriv, encPriv := katScalars(t)

	shared, err := encPriv.ECDH(sdkPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}

	sidRaw, _ := hex.DecodeString(katSessionIDRawHex)
	sid := base64.RawURLEncoding.EncodeToString(sidRaw)

	sess, err := buildSession(sid, sidRaw, shared, time.Hour, time.Now)
	if err != nil {
		t.Fatalf("buildSession: %v", err)
	}

	aeadKey := hkdf(shared, sidRaw, []byte(hkdfInfo), 32)
	c2s := hkdf(shared, sidRaw, []byte(dirInfoC2S), 4)
	s2c := hkdf(shared, sidRaw, []byte(dirInfoS2C), 4)

	ad := []byte("POST:" + katPath + ":" + sid)
	reqCT := sess.Aead.Seal(nil, makeNonce(sess.C2SPrefix[:], 0), []byte(katRequestPT), ad)
	reqEnv := encodeSealed(sealedEnvelope{V: 1, Ctr: 0, Ct: reqCT})
	respCT := sess.Aead.Seal(nil, makeNonce(sess.S2CPrefix[:], 0), []byte(katResponsePT), ad)
	respEnv := encodeSealed(sealedEnvelope{V: 1, Ctr: 0, Ct: respCT})

	if katGenerate {
		t.Logf("sdk_pub  = %x", sdkPriv.PublicKey().Bytes())
		t.Logf("enc_pub  = %x", encPriv.PublicKey().Bytes())
		t.Logf("shared   = %x", shared)
		t.Logf("aead_key = %x", aeadKey)
		t.Logf("c2s      = %x", c2s)
		t.Logf("s2c      = %x", s2c)
		t.Logf("req_env  = %x", reqEnv)
		t.Logf("resp_env = %x", respEnv)
		t.Fatal("katGenerate is true — pin the printed vectors and set it back to false")
	}

	assertHex(t, "sdk_pub", sdkPriv.PublicKey().Bytes(), katSdkPubSec1Hex)
	assertHex(t, "enc_pub", encPriv.PublicKey().Bytes(), katEncPubSec1Hex)
	assertHex(t, "shared", shared, katSharedXHex)
	assertHex(t, "aead_key", aeadKey, katAeadKeyHex)
	assertHex(t, "c2s_prefix", c2s, katC2SPrefixHex)
	assertHex(t, "s2c_prefix", s2c, katS2CPrefixHex)
	assertHex(t, "c2s_prefix(session)", sess.C2SPrefix[:], katC2SPrefixHex)
	assertHex(t, "s2c_prefix(session)", sess.S2CPrefix[:], katS2CPrefixHex)
	assertHex(t, "request_envelope", reqEnv, katRequestEnv)
	assertHex(t, "response_envelope", respEnv, katResponseEnv)

	// Round-trip through the production decoder + AEAD open.
	env, err := decodeSealed(reqEnv)
	if err != nil {
		t.Fatalf("decodeSealed: %v", err)
	}
	pt, err := sess.Aead.Open(nil, makeNonce(sess.C2SPrefix[:], env.Ctr), env.Ct, ad)
	if err != nil {
		t.Fatalf("aead open: %v", err)
	}
	if !bytes.Equal(pt, []byte(katRequestPT)) {
		t.Fatalf("request plaintext mismatch: %q", pt)
	}
}

// ── EncAuth verification fixture ────────────────────────────────────
//
// ECDSA signing is randomized, so this fixture was generated ONCE (with
// the deterministic scalars below) and the resulting envelope pinned.
// Verification of the pinned envelope is fully deterministic and is
// mirrored in enclave-os-mini's `encauth.rs` tests, proving the Rust
// port (sgx_ecdsa_verify + byte-order conversions) accepts exactly what
// the Go verifier accepts.
//
//	hw_priv  scalar = SHA-256("privasys-kat-hw/v1")
//	idp_priv scalar = SHA-256("privasys-kat-idp/v1")
//	enc_pub          = the session-relay KAT enclave key above
//	now (for tests)  = 1_700_000_100
const (
	katEncAuthIdpPubHex  = "04a818bd9ebbbff1f75be3767981d0b80eac8f2398f0acb54acb621cf12d0f79951cc373bdcdabdff1abc828c47e2b3470f28cbcc24d37adb8913b7d8163560be2"
	katEncAuthHwPubHex   = "04db917ba33058f287bd9c8df0923cd4c0773b9569b145cb1e4f8deff457cdf221ed6c07e0712410b2e1a375892fde29e348058d49b9a4035f1350b9f2cc907436"
	katEncAuthPayloadB64 = "qgEBAmhrYXQtdXNlcgNna2F0LXNpZARYIKGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhBVgg4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eEGWEEE3VEdzeOHVWjecy_eVjTYlAtbz-9mis5G8ovYE6J-tq9pXi_lKssD9NFYpGM14KcmdlVAKQwoYUN5lT4atIPZJAdYILKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKyCBplU_EACRruaygAClhBBNuRe6MwWPKHvZyN8JI81MB3O5VpsUXLHk-N7_RXzfIh7WwH4HEkELLho3WJL94p40gFjUm5pANfE1C58syQdDY"
	katEncAuthHwSigB64   = "KycpT_wNX3KiOcf1BM2c6pwEumKHRRHPw0g3GijHA4ixyE11NLXOWnH9-BKG4emlHi9sx_joU_vkRcy_qKp-rA"
	katEncAuthIdpSigB64  = "YnNICq8sOff-c8cTKWtaywuhAT4cdE24nOGOJR6CdeRI8RpkD6RxBLTbMMlUBQ4kbX_fcBlIHvUbTJqqGunpYA"
	katEncAuthNow        = 1_700_000_100
)

func TestEncAuthFixtureKAT(t *testing.T) {
	if katGenerate {
		generateEncAuthFixture(t)
		return
	}

	idpPubRaw, _ := hexDecode(t, katEncAuthIdpPubHex)
	encPubRaw, _ := hexDecode(t, katEncPubSec1Hex)
	idpPub, err := sec1ToP256(idpPubRaw)
	if err != nil {
		t.Fatalf("idp pub: %v", err)
	}

	env := &EncAuthEnvelope{
		V:       1,
		Payload: katEncAuthPayloadB64,
		HwSig:   katEncAuthHwSigB64,
		IdpSig:  katEncAuthIdpSigB64,
	}
	v := &DefaultEncAuthVerifier{Resolver: JWKSResolverFunc(
		func(_ context.Context, _ string) (*ecdsa.PublicKey, error) { return idpPub, nil },
	)}

	got, err := v.Verify(env, VerifyContext{EncStaticPub: encPubRaw, Now: time.Unix(katEncAuthNow, 0)})
	if err != nil {
		t.Fatalf("pinned fixture rejected: %v", err)
	}
	if got.Sub != "kat-user" || got.SID != "kat-sid" {
		t.Fatalf("decoded mismatch: %+v", got)
	}

	// Any single-byte mutation must be rejected.
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(katEncAuthPayloadB64)
	bad := append([]byte(nil), payloadBytes...)
	bad[len(bad)-1] ^= 0x01
	env2 := *env
	env2.Payload = base64.RawURLEncoding.EncodeToString(bad)
	if _, err := v.Verify(&env2, VerifyContext{EncStaticPub: encPubRaw, Now: time.Unix(katEncAuthNow, 0)}); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func generateEncAuthFixture(t *testing.T) {
	t.Helper()
	hwScalar := sha256.Sum256([]byte("privasys-kat-hw/v1"))
	idpScalar := sha256.Sum256([]byte("privasys-kat-idp/v1"))
	hwPriv := scalarToECDSA(t, hwScalar[:])
	idpPriv := scalarToECDSA(t, idpScalar[:])
	hwPub := elliptic.Marshal(elliptic.P256(), hwPriv.PublicKey.X, hwPriv.PublicKey.Y)
	idpPub := elliptic.Marshal(elliptic.P256(), idpPriv.PublicKey.X, idpPriv.PublicKey.Y)
	encPubRaw, _ := hexDecode(t, katEncPubSec1Hex)

	payload := EncAuthPayload{
		V: 1, Sub: "kat-user", SID: "kat-sid",
		WorkloadDigest: bytes32(0xa1), EncMeas: bytes32(0xe1),
		EncPub: encPubRaw, QuoteHash: bytes32(0xb2),
		NotBefore: 1_700_000_000,
		NotAfter:  4_000_000_000, // far future so the pinned fixture stays valid
		HwPub:     hwPub,
	}
	em, _ := cbor.CTAP2EncOptions().EncMode()
	cborBytes, err := em.Marshal(&payload)
	if err != nil {
		t.Fatal(err)
	}
	hwSig := signRaw64(t, hwPriv, cborBytes)
	idpSig := signRaw64(t, idpPriv, append(append([]byte(nil), cborBytes...), hwSig...))

	t.Logf("idp_pub  = %x", idpPub)
	t.Logf("hw_pub   = %x", hwPub)
	t.Logf("payload  = %s", base64.RawURLEncoding.EncodeToString(cborBytes))
	t.Logf("hw_sig   = %s", base64.RawURLEncoding.EncodeToString(hwSig))
	t.Logf("idp_sig  = %s", base64.RawURLEncoding.EncodeToString(idpSig))
	t.Fatal("katGenerate is true — pin the printed fixture and set it back to false")
}

func scalarToECDSA(t *testing.T, scalar []byte) *ecdsa.PrivateKey {
	t.Helper()
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(scalar)
	if d.Sign() == 0 || d.Cmp(curve.Params().N) >= 0 {
		t.Fatal("scalar out of range")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = d
	priv.X, priv.Y = curve.ScalarBaseMult(d.Bytes())
	return priv
}

func hexDecode(t *testing.T, s string) ([]byte, error) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad pinned hex: %v", err)
	}
	return b, nil
}

func assertHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("%s: bad pinned hex: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch:\n  got  %x\n  want %x", name, got, want)
	}
}
