package manager

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// Without a pin store the route says so rather than pretending to accept
// policy: a runtime that cannot remember a pin cannot enforce one.
func TestPolicyRouteWithoutAStore(t *testing.T) {
	s := &Server{log: zap.NewNop()}
	r := httptest.NewRequest(http.MethodPut, "/api/v1/containers/app/policy", strings.NewReader("{}"))
	r.SetPathValue("name", "app")
	w := httptest.NewRecorder()
	s.handleSetAppPolicy(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

// A container with no app id has no policy identity, so a document cannot be
// addressed to it.
func TestPolicyRouteWithoutAnAppID(t *testing.T) {
	s := &Server{log: zap.NewNop(), policy: newPolicyStore("", stubVerifier{}, zap.NewNop())}
	r := httptest.NewRequest(http.MethodPut, "/api/v1/containers/app/policy", strings.NewReader("{}"))
	r.SetPathValue("name", "app")
	w := httptest.NewRecorder()
	s.handleSetAppPolicy(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

// An app that has pinned no policy is still governed by the control plane,
// which is what keeps existing apps working.
func TestPolicyPinnedIsFalseUntilADocumentIsAccepted(t *testing.T) {
	s := &Server{log: zap.NewNop(), policy: newPolicyStore("", stubVerifier{}, zap.NewNop())}
	if s.policyPinned("app") {
		t.Error("an app with no document reported as pinned")
	}
	s2 := &Server{log: zap.NewNop()}
	if s2.policyPinned("app") {
		t.Error("a runtime without a pin store reported an app as pinned")
	}
}

// stubVerifier stands in for the OIDC verifier; these tests never get as far
// as checking a token.
type stubVerifier struct{}

func (stubVerifier) VerifyApprovalToken(string) (map[string]interface{}, error) {
	return nil, nil
}
