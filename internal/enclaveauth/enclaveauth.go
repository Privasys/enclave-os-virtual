// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// Package enclaveauth authenticates the manager's own calls to the control
// plane by attestation instead of a stored bearer.
//
// The manager holds two things the control plane can check: the per-enclave
// intermediate CA delivered when the enclave was approved, which is unique to
// this enclave, and a TDX quote, which proves a live TD running a measured
// image. Neither alone is enough. The CA is a file on /data, so a copy of it
// would otherwise be as good as the bearer it replaces; the quote says nothing
// about WHICH enclave, because two hosts running the same image present the
// same measurements. Together they say "this enclave, running now".
//
// Each request carries:
//
//	X-Enclave-Id          the enclave row this call claims to be
//	X-Enclave-Identity    base64(DER) of a short-lived leaf, issued by that
//	                      enclave's CA, whose key never leaves this process
//	X-Enclave-Challenge   base64 of 32 bytes: 8 big-endian unix seconds, then random
//	X-Enclave-Evidence    base64 of a TDX quote whose report_data binds the leaf
//	                      key to that challenge (RA-TLS v2 header identity)
//	X-Enclave-Ts          unix seconds, repeated in the signature
//	X-Enclave-Nonce       base64 of 16 random bytes, one per request
//	X-Enclave-Sig         base64 ECDSA-P256 signature over the canonical string
//
// The signature is what makes a captured request useless: the headers commit
// to the method, the path and the body, so replaying them elsewhere fails, and
// the nonce stops a replay of the same request. The bearer it replaces could be
// lifted from a log and used for anything.
//
// Validity and timestamps come from trusted time, so a host that rolled its
// clock back cannot choose the window its enclave appears to be alive in.
package enclaveauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-os-virtual/internal/tdx"
	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
)

// SignatureDomain prefixes the canonical string a signature covers. It is part
// of the wire contract with the control plane: change it on both sides only.
const SignatureDomain = "privasys-enclave-auth/v1"

// Header names, also part of the contract.
const (
	HeaderEnclaveID = "X-Enclave-Id"
	HeaderIdentity  = "X-Enclave-Identity"
	HeaderChallenge = "X-Enclave-Challenge"
	HeaderEvidence  = "X-Enclave-Evidence"
	HeaderTimestamp = "X-Enclave-Ts"
	HeaderNonce     = "X-Enclave-Nonce"
	HeaderSignature = "X-Enclave-Sig"
)

// identityLifetime bounds how long one leaf and its evidence are reused. The
// control plane refuses a challenge older than five minutes, so this stays
// well inside that: a quote costs milliseconds, and reusing one for longer buys
// nothing.
const identityLifetime = 3 * time.Minute

// NonceLen is the per-request nonce length in bytes.
const NonceLen = 16

// identity is one minted leaf with the evidence that binds it.
type identity struct {
	certDER   []byte
	key       *ecdsa.PrivateKey
	challenge []byte
	quote     []byte
	mintedAt  time.Time
}

// Signer mints and reuses an attested identity, and signs requests with it.
type Signer struct {
	enclaveID string
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey

	mu  sync.Mutex
	cur *identity

	// quoteFn is tdx.GetQuote, replaced in tests.
	quoteFn func([64]byte) ([]byte, error)
	// nowFn is trustedtime.Now, replaced in tests.
	nowFn func() (time.Time, error)
}

// New loads the per-enclave CA and returns a Signer. A missing CA, a missing
// enclave id, or a CA whose key is not P-256 is an error: the caller decides
// whether to run without attested control-plane auth during migration.
func New(caCertPath, caKeyPath, enclaveID string) (*Signer, error) {
	if enclaveID == "" {
		return nil, fmt.Errorf("enclaveauth: enclave id is required")
	}
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: read CA key: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: parse CA pair: %w", err)
	}
	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: parse CA certificate: %w", err)
	}
	caKey, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("enclaveauth: CA key is %T, want an ECDSA key", pair.PrivateKey)
	}
	return &Signer{
		enclaveID: enclaveID,
		caCert:    caCert,
		caKey:     caKey,
		quoteFn:   tdx.GetQuote,
		nowFn:     trustedtime.Now,
	}, nil
}

// mint issues a leaf from the enclave CA and quotes its key against a fresh
// challenge. The leaf carries no evidence extension: this is RA-TLS v2, where
// the quote travels beside the certificate.
func (s *Signer) mint(now time.Time) (*identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: generate identity key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: marshal SPKI: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkixName(s.enclaveID),
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: issue identity: %w", err)
	}

	// The challenge carries the time the evidence was produced, in the bytes
	// the quote commits to, so the control plane can trust it.
	challenge := make([]byte, ratls.ContextLen)
	binary.BigEndian.PutUint64(challenge[:8], uint64(now.Unix()))
	if _, err := rand.Read(challenge[8:]); err != nil {
		return nil, fmt.Errorf("enclaveauth: challenge: %w", err)
	}
	want := ratls.ClientReportData(spki, challenge, ratls.HeaderIdentityHctx[:], nil)
	var reportData [64]byte
	copy(reportData[:], want)
	quote, err := s.quoteFn(reportData)
	if err != nil {
		return nil, fmt.Errorf("enclaveauth: quote: %w", err)
	}
	return &identity{certDER: der, key: key, challenge: challenge, quote: quote, mintedAt: now}, nil
}

// current returns a usable identity, minting one when none is held or the held
// one is older than identityLifetime.
func (s *Signer) current() (*identity, time.Time, error) {
	now, err := s.nowFn()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("enclaveauth: no trusted time: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Reuse while the held identity is younger than its lifetime. A negative
	// age means time went backwards under us, so mint again rather than sign
	// with an identity from a future we no longer believe.
	if s.cur != nil {
		if age := now.Sub(s.cur.mintedAt); age >= 0 && age < identityLifetime {
			return s.cur, now, nil
		}
	}
	id, err := s.mint(now)
	if err != nil {
		return nil, time.Time{}, err
	}
	s.cur = id
	return id, now, nil
}

// CanonicalString is the exact text a signature covers. The control plane
// rebuilds it from the request it received, so any change to the method, the
// path or the body invalidates the signature.
func CanonicalString(method, path, ts, nonceB64 string, body []byte) string {
	sum := sha256.Sum256(body)
	return SignatureDomain + "\n" + method + "\n" + path + "\n" + ts + "\n" + nonceB64 + "\n" + hex.EncodeToString(sum[:])
}

// Sign attaches the attested identity and a signature over this request. body
// is the exact body being sent, or nil.
func (s *Signer) Sign(req *http.Request, body []byte) error {
	id, now, err := s.current()
	if err != nil {
		return err
	}
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("enclaveauth: nonce: %w", err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)
	ts := fmt.Sprintf("%d", now.Unix())

	digest := sha256.Sum256([]byte(CanonicalString(req.Method, req.URL.Path, ts, nonceB64, body)))
	sig, err := ecdsa.SignASN1(rand.Reader, id.key, digest[:])
	if err != nil {
		return fmt.Errorf("enclaveauth: sign: %w", err)
	}

	req.Header.Set(HeaderEnclaveID, s.enclaveID)
	req.Header.Set(HeaderIdentity, base64.StdEncoding.EncodeToString(id.certDER))
	req.Header.Set(HeaderChallenge, base64.StdEncoding.EncodeToString(id.challenge))
	req.Header.Set(HeaderEvidence, base64.StdEncoding.EncodeToString(id.quote))
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderNonce, nonceB64)
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	return nil
}

// pkixName labels the leaf with the enclave it belongs to. The control plane
// does not read it: identity comes from the CA that issued the leaf.
func pkixName(enclaveID string) pkix.Name {
	return pkix.Name{CommonName: "enclave " + enclaveID}
}

// caCertPEM is the enclave CA in PEM form, for callers that need to show it.
func (s *Signer) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})
}
