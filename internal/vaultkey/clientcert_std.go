//go:build !ratls

package vaultkey

import (
	"crypto/tls"
	"errors"
)

// clientCertificateFn requires the Privasys Go fork: the vault's
// challenge nonce arrives in the TLS CertificateRequest extension
// 0xFFBB, which upstream Go does not surface. Build the manager with
// the fork and `-tags ratls`.
func clientCertificateFn(_ []byte) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	return nil, errors.New("vaultkey: built without the ratls tag — vault-backed volume keys require the Privasys Go fork (build with -tags ratls)")
}
