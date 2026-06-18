//go:build ratls

package vaultkey

import (
	"crypto/tls"
	"errors"
)

// clientCertificateFn returns the GetClientCertificate callback. The
// vault sends its challenge nonce in the TLS CertificateRequest
// extension 0xFFBB; the Privasys Go fork surfaces it as
// CertificateRequestInfo.RATLSChallenge.
func clientCertificateFn(imageDigest, appID []byte) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if len(info.RATLSChallenge) == 0 {
			return nil, errors.New("vaultkey: vault sent no RA-TLS challenge (bidirectional challenge-response is required)")
		}
		return mintIdentity(info.RATLSChallenge, imageDigest, appID)
	}, nil
}
