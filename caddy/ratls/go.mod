module github.com/Privasys/enclave-os-virtual/caddy/ratls

go 1.25.0

// This module requires the Privasys/go fork (https://github.com/Privasys/go/tree/ratls)
// which adds tls.ClientHelloInfo.RATLSChallenge for RA-TLS challenge-response attestation.
// Build with: GOROOT=~/go-ratls xcaddy build --with github.com/Privasys/enclave-os-virtual/caddy/ratls=.
// Upstream PR: https://github.com/golang/go/pull/77714

require (
	github.com/caddyserver/caddy/v2 v2.9.1
	github.com/caddyserver/certmagic v0.25.1
	github.com/google/go-tdx-guest v0.3.1
	go.uber.org/zap v1.27.0
)
