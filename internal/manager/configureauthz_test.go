// Copyright (c) Privasys. All rights reserved.

package manager

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// authorizeConfigure had no test coverage at all until the 2026-09-17
// disclosure, which is a large part of why a fail-open branch sat in it for
// two months. These cover the branch that was reported plus the shape of the
// gate around it, so the refusal cannot quietly become an admission again.

func gateServer(t *testing.T) *Server {
	t.Helper()
	return &Server{log: zap.NewNop()}
}

func req(t *testing.T, bearer string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/configure", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

// The reported finding: a container loaded with neither an app id nor an
// owners team used to be admitted with only a warning, so any caller reached
// its configure surface. It must now be refused.
func TestAuthorizeConfigure_RefusesLoadWithNoAppIDAndNoOwners(t *testing.T) {
	s := gateServer(t)

	err := s.authorizeConfigure(req(t, ""), "legacy-app", launcher.FreezeState{})
	if err == nil {
		t.Fatal("a load with no app id and no owners was admitted; this is the reported fail-open")
	}
	// The operator has to be able to act on this, so the remedy is in the text.
	if !strings.Contains(err.Error(), "redeploy") {
		t.Fatalf("refusal should name the remedy, got: %v", err)
	}
}

// Presenting a bearer must not change that: there is nothing to authorise
// against, so the answer is the same.
func TestAuthorizeConfigure_RefusesNoAppIDAndNoOwnersEvenWithBearer(t *testing.T) {
	s := gateServer(t)

	if err := s.authorizeConfigure(req(t, "any.token.here"), "legacy-app", launcher.FreezeState{}); err == nil {
		t.Fatal("a bearer must not rescue a load that carries no app id and no owners")
	}
}

// A container that DOES carry an envelope takes the normal path. With no
// verifier wired it still fails closed, but for the verifier reason rather
// than the legacy one — proving the early return is gone rather than merely
// reworded.
func TestAuthorizeConfigure_WithEnvelopeTakesTheVerifierPath(t *testing.T) {
	s := gateServer(t)

	err := s.authorizeConfigure(req(t, ""), "real-app", launcher.FreezeState{
		AppID: "00112233445566778899aabbccddeeff",
	})
	if err == nil {
		t.Fatal("expected a refusal with no verifier configured")
	}
	if strings.Contains(err.Error(), "redeploy") {
		t.Fatalf("a container WITH an app id hit the legacy branch: %v", err)
	}
	if !strings.Contains(err.Error(), "verifier") {
		t.Fatalf("expected the no-verifier refusal, got: %v", err)
	}
}

// Owners alone is still an envelope: the transitional sub fallback applies, so
// it must not be treated as a legacy load either.
func TestAuthorizeConfigure_OwnersOnlyIsNotALegacyLoad(t *testing.T) {
	s := gateServer(t)

	err := s.authorizeConfigure(req(t, ""), "owners-only", launcher.FreezeState{
		Owners: []string{"sub-1"},
	})
	if err == nil {
		t.Fatal("expected a refusal with no verifier configured")
	}
	if strings.Contains(err.Error(), "redeploy") {
		t.Fatalf("a container with an owners team hit the legacy branch: %v", err)
	}
}
