package manager

import (
	"testing"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
)

// A step-up approval (vault_op) is for one vault operation: it is never an
// ordinary bearer on any manager path, and never reaches an app, even a
// first-party one that still receives ordinary platform tokens.
func TestAVaultApprovalIsNotABearer(t *testing.T) {
	s, iss := newIdentityServer(t)
	approval := iss.token(t, "owner-1", "enclave-os-virtual", map[string]any{"typ": "at+jwt", "vault_op": "promote:apps.privasys.org/x/storage-kek/v1"})
	plain := iss.token(t, "owner-1", "enclave-os-virtual", nil)

	for name, rule := range map[string]auth.AudienceRule{
		"platform": s.verifier.PlatformAudience(),
		"app":      auth.AppAudience([]string{"enclave-os-virtual"}),
		"subject":  auth.SameSubject("owner-1"),
	} {
		if _, err := s.verifier.Verify(approval, rule); err == nil {
			t.Fatalf("Verify (%s) accepted a vault approval", name)
		}
	}
	// The approval path still takes it, and the same token without vault_op
	// is still an ordinary bearer.
	if c, err := s.verifier.VerifyApprovalToken(approval); err != nil || c["vault_op"] == nil {
		t.Fatalf("VerifyApprovalToken: %v %v", c, err)
	}
	if _, err := s.verifier.Verify(plain, s.verifier.PlatformAudience()); err != nil {
		t.Fatalf("an ordinary bearer was refused: %v", err)
	}

	// Withheld from every app, the first-party allowlist included.
	platformApproval := iss.token(t, "owner-1", "privasys-platform", map[string]any{"vault_op": "promote:x"})
	for _, app := range []string{"", "cf7a0d58-5468-4168-84c3-41ebe0ce4025", "e9de5530-41c3-471e-9566-c5c9a6d963bc", "someotherapp"} {
		if !withholdToken(platformApproval, "roles", app) {
			t.Fatalf("a vault approval reached app %q", app)
		}
	}
}
