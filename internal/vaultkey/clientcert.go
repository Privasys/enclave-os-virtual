package vaultkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-os-virtual/internal/oids"
	"github.com/Privasys/enclave-os-virtual/internal/tdx"
)

// RA-TLS v2 client identity of a container (and of the manager's own vault
// leg): a leaf key, the container's code digest (OID 4.2) and app id (OID
// 4.1), no evidence. Evidence is minted per connection, after the handshake,
// with report_data committing to the leaf key, the vault's client_context and
// the connection's exporter value (ClientEvidence).

// identityLifetime is the validity of a minted client identity.
const identityLifetime = time.Hour

// Identity is a minted client identity with its SPKI hash.
type Identity struct {
	Cert     *tls.Certificate
	SPKIHash [32]byte
	NotAfter time.Time
}

// MintIdentity mints a client identity carrying imageDigest and appID. The
// measured manager is the sole minter, so the app id it stamps is trustworthy.
func MintIdentity(imageDigest, appID []byte) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: generate identity key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: marshal SPKI: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, fmt.Errorf("vaultkey: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "enclave-os-virtual client"},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.Add(identityLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			oids.Extension(oids.WorkloadCodeHash, imageDigest),
		},
	}
	if len(appID) > 0 {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, oids.Extension(oids.WorkloadAppID, appID))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: create certificate: %w", err)
	}
	return &Identity{
		Cert:     &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		SPKIHash: sha256.Sum256(spki),
		NotAfter: tmpl.NotAfter,
	}, nil
}

// EncodeIdentityPEM PEM-encodes a minted identity's certificate and private key
// so it can be handed to the calling container (over loopback, inside the TD).
func EncodeIdentityPEM(cert *tls.Certificate) (certPEM, keyPEM []byte, err error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("vaultkey: empty identity certificate")
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("vaultkey: marshal identity key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// identityCache keeps the manager's own client identities (one per
// digest+appID) for their validity.
var identityCache = struct {
	mu sync.Mutex
	m  map[string]*Identity
}{m: map[string]*Identity{}}

// clientCertificateFn returns the GetClientCertificate callback for the
// manager's vault leg: the cached identity for (imageDigest, appID), minted
// on first use and re-minted when it nears expiry.
func clientCertificateFn(imageDigest, appID []byte) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	key := string(imageDigest) + "|" + string(appID)
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		identityCache.mu.Lock()
		defer identityCache.mu.Unlock()
		if id := identityCache.m[key]; id != nil && time.Now().Add(time.Minute).Before(id.NotAfter) {
			return id.Cert, nil
		}
		id, err := MintIdentity(imageDigest, appID)
		if err != nil {
			return nil, err
		}
		identityCache.m[key] = id
		return id.Cert, nil
	}
}

// clientEvidenceFn returns the ClientEvidenceSource of the manager's own vault
// leg: a TDX quote over the report_data the SDK computed for the connection.
func clientEvidenceFn() ratls.ClientEvidenceSource {
	return func(req ratls.ClientEvidenceRequest) (*ratls.ClientEvidence, error) {
		var rd [64]byte
		copy(rd[:], req.ReportData)
		quote, err := tdx.GetQuote(rd)
		if err != nil {
			return nil, fmt.Errorf("vaultkey: TDX quote: %w", err)
		}
		return &ratls.ClientEvidence{
			TEE:       "tdx",
			Quote:     quote,
			QuoteTime: time.Now().UTC().Format(ratls.QuoteTimeLayout),
		}, nil
	}
}
