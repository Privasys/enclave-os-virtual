package vaultkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/oids"
	"github.com/Privasys/enclave-os-virtual/internal/tdx"
)

// tdxQuoteOID is the Intel-standard X.509 extension OID carrying a raw
// TDX quote (same arc the Caddy RA-TLS issuer uses on serving certs).
var tdxQuoteOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 5, 5, 1, 6}

// mintIdentity builds a one-shot RA-TLS client certificate bound to the
// vault's challenge nonce:
//
//	ReportData = SHA-512( SHA-256(SPKI_DER) || challenge )
//
// (the platform-wide binding formula; the vault recomputes it in
// verify_challenge_binding). The self-signed leaf carries the raw TDX
// quote plus the container's image digest at OID 3.2 and (for MR_APP keys)
// its app-id at OID 3.6, which is what the vault's Principal::Tee profile
// pins (the enclave-upgrade + MR_APP design).
func mintIdentity(challenge, imageDigest, appID []byte) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: generate identity key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: marshal SPKI: %w", err)
	}

	spkiHash := sha256.Sum256(spki)
	preimage := make([]byte, 0, len(spkiHash)+len(challenge))
	preimage = append(preimage, spkiHash[:]...)
	preimage = append(preimage, challenge...)
	reportData := sha512.Sum512(preimage)

	quote, err := tdx.GetQuote(reportData)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: TDX quote: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, fmt.Errorf("vaultkey: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "enclave-os-virtual vault client"},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			oids.Extension(tdxQuoteOID, quote),
			oids.Extension(oids.ContainerImageDigest, imageDigest),
		},
	}
	// MR_APP: bind this identity to the specific app. Omitted (MR_ENCLAVE) when
	// the platform did not supply an app-id, keeping old deployments working.
	if len(appID) > 0 {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions,
			oids.Extension(oids.ContainerAppId, appID))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: create certificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}
