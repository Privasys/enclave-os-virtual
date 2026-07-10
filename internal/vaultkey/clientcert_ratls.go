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
		// Fold the live session channel binder (TLS 1.3) into the quote so the
		// client cert commits to this exact vault handshake (mutual channel
		// binding). The vault recomputes it from its own key schedule.
		return mintIdentity(info.RATLSChallenge, info.RATLSChannelBinder, imageDigest, appID)
	}, nil
}
