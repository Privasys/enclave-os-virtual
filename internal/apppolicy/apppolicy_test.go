package apppolicy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIdP stands in for the identity provider: it hands back the claims of a
// token it minted. The real verifier checks the signature, issuer, audience
// and expiry; what these tests exercise is everything after that.
type fakeIdP struct {
	tokens map[string]map[string]interface{}
	fail   bool
}

func newIdP() *fakeIdP {
	return &fakeIdP{tokens: make(map[string]map[string]interface{})}
}

func (f *fakeIdP) VerifyApprovalToken(token string) (map[string]interface{}, error) {
	if f.fail {
		return nil, fmt.Errorf("signature check failed")
	}
	claims, ok := f.tokens[token]
	if !ok {
		return nil, fmt.Errorf("unknown token")
	}
	return claims, nil
}

// approve mints a token whose binding covers this document, as the identity
// provider does once the owner has approved it on their phone.
func (f *fakeIdP) approve(t *testing.T, sub string, docJSON string) string {
	t.Helper()
	var doc Document
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		t.Fatal(err)
	}
	nonce := fmt.Sprintf("nonce-%d", len(f.tokens))
	exp := int64(1789000000)
	token := fmt.Sprintf("token-%d", len(f.tokens))
	f.tokens[token] = map[string]interface{}{
		"sub":      sub,
		"amr":      []interface{}{"webauthn"},
		"nonce":    nonce,
		"exp":      float64(exp),
		"vault_op": Binding(HandleFor(doc.AppID), DocumentDigest([]byte(docJSON)), doc.Seq, nonce, exp),
	}
	return token
}

func envelope(t *testing.T, docJSON, token string) []byte {
	t.Helper()
	raw, err := json.Marshal(Approved{Document: json.RawMessage(docJSON), ApprovalToken: token})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const testApp = "11112222333344445555666677778888"

func docJSON(seq uint64, extra string) string {
	return fmt.Sprintf(`{"v":1,"app_id":%q,"seq":%d%s}`, testApp, seq, extra)
}

func newStore(t *testing.T, idp *fakeIdP) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "pins.json"), idp)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The first document pins the approver; afterwards nobody else's approval will
// do, which is what stops the party distributing policy from writing it.
func TestFirstDocumentPinsTheApprover(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)

	if s.Pinned(testApp) {
		t.Fatal("a fresh app is already pinned")
	}
	doc := docJSON(1, "")
	if _, _, err := s.Accept(envelope(t, doc, idp.approve(t, "owner-1", doc))); err != nil {
		t.Fatalf("first document refused: %v", err)
	}
	if s.Approver(testApp) != "owner-1" {
		t.Fatalf("approver = %q", s.Approver(testApp))
	}
	next := docJSON(2, "")
	if _, _, err := s.Accept(envelope(t, next, idp.approve(t, "someone-else", next))); err == nil {
		t.Fatal("another subject's approval was accepted")
	}
}

// An approval is for one document. Pairing it with another must fail, which is
// what stops a distributor swapping the policy under a valid approval.
func TestApprovalDoesNotTransferToAnotherDocument(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	approved := docJSON(1, `,"owners":["a"]`)
	token := idp.approve(t, "owner-1", approved)

	other := docJSON(1, `,"owners":["attacker"]`)
	if _, _, err := s.Accept(envelope(t, other, token)); err == nil {
		t.Fatal("an approval for one document installed another")
	}
	if _, _, err := s.Accept(envelope(t, approved, token)); err != nil {
		t.Fatalf("the approved document was refused: %v", err)
	}
}

func TestSequenceMustAdvance(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	five := docJSON(5, "")
	if _, _, err := s.Accept(envelope(t, five, idp.approve(t, "owner-1", five))); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{4, 5} {
		d := docJSON(seq, "")
		if _, _, err := s.Accept(envelope(t, d, idp.approve(t, "owner-1", d))); err == nil {
			t.Errorf("seq %d was accepted after 5", seq)
		}
	}
	six := docJSON(6, "")
	if _, _, err := s.Accept(envelope(t, six, idp.approve(t, "owner-1", six))); err != nil {
		t.Errorf("seq 6 refused: %v", err)
	}
}

// An app changes hands when the current owner approves a document naming the
// next approver.
func TestApproverHandover(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	first := docJSON(1, "")
	if _, _, err := s.Accept(envelope(t, first, idp.approve(t, "owner-1", first))); err != nil {
		t.Fatal(err)
	}
	handover := docJSON(2, `,"approver":"owner-2"`)
	// The incoming owner cannot hand the app to themselves.
	if _, _, err := s.Accept(envelope(t, handover, idp.approve(t, "owner-2", handover))); err == nil {
		t.Fatal("the incoming approver approved their own handover")
	}
	if _, _, err := s.Accept(envelope(t, handover, idp.approve(t, "owner-1", handover))); err != nil {
		t.Fatalf("handover refused: %v", err)
	}
	if got := s.Approver(testApp); got != "owner-2" {
		t.Fatalf("approver after handover = %q", got)
	}
	after := docJSON(3, "")
	if _, _, err := s.Accept(envelope(t, after, idp.approve(t, "owner-1", after))); err == nil {
		t.Error("the previous owner still approved policy")
	}
	if _, _, err := s.Accept(envelope(t, after, idp.approve(t, "owner-2", after))); err != nil {
		t.Errorf("the new owner was refused: %v", err)
	}
}

// A session token is not an approval: the ceremony has to have happened at the
// owner's device.
func TestApprovalMustBeAStepUp(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	doc := docJSON(1, "")
	token := idp.approve(t, "owner-1", doc)
	idp.tokens[token]["amr"] = []interface{}{"pwd"}
	if _, _, err := s.Accept(envelope(t, doc, token)); err == nil {
		t.Fatal("a token with no step-up was accepted")
	}
}

func TestUnverifiableTokenIsRefused(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	doc := docJSON(1, "")
	token := idp.approve(t, "owner-1", doc)
	idp.fail = true
	if _, _, err := s.Accept(envelope(t, doc, token)); err == nil {
		t.Fatal("a token the identity provider rejected was accepted")
	}
}

func TestPinsSurviveReload(t *testing.T) {
	idp := newIdP()
	path := filepath.Join(t.TempDir(), "pins.json")
	s, err := NewStore(path, idp)
	if err != nil {
		t.Fatal(err)
	}
	doc := docJSON(2, "")
	if _, _, err := s.Accept(envelope(t, doc, idp.approve(t, "owner-1", doc))); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(path, idp)
	if err != nil {
		t.Fatal(err)
	}
	if again.Approver(testApp) != "owner-1" {
		t.Fatal("the pin did not survive a reload")
	}
	if _, _, err := again.Accept(envelope(t, doc, idp.approve(t, "owner-1", doc))); err == nil {
		t.Error("the reloaded store forgot the sequence")
	}
}

func TestMalformedEnvelopesAreRefused(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	doc := docJSON(1, "")
	good := idp.approve(t, "owner-1", doc)
	cases := map[string][]byte{
		"not json":       []byte(`{`),
		"no document":    []byte(`{"approval_token":"t"}`),
		"no token":       envelope(t, doc, ""),
		"unknown token":  envelope(t, doc, "made-up"),
		"wrong version":  envelope(t, `{"v":2,"app_id":"x","seq":1}`, good),
		"no app":         envelope(t, `{"v":1,"app_id":"","seq":1}`, good),
		"seq zero":       envelope(t, `{"v":1,"app_id":"x","seq":0}`, good),
		"unknown field":  envelope(t, `{"v":1,"app_id":"x","seq":1,"surprise":1}`, good),
		"edited in situ": envelope(t, strings.Replace(doc, `"seq":1`, `"seq":9`, 1), good),
	}
	for name, raw := range cases {
		if _, _, err := s.Accept(raw); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The constellation an owner approves is where the app's key may live, and
// nowhere else. A document that names none leaves the approved one in place.
func TestConstellationIsPinnedAndKept(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)

	withVault := docJSON(1, `,"constellation":{"mrenclave":"abc123","endpoints":["v1:8443","v2:8443"]}`)
	if _, _, err := s.Accept(envelope(t, withVault, idp.approve(t, "owner-1", withVault))); err != nil {
		t.Fatal(err)
	}
	c := s.ConstellationFor(testApp)
	if !c.Valid() || c.Mrenclave != "abc123" || len(c.Endpoints) != 2 {
		t.Fatalf("constellation not pinned: %+v", c)
	}

	// Order does not matter; membership does.
	if !c.Matches("ABC123", []string{"v2:8443", "v1:8443"}) {
		t.Error("the approved constellation did not match itself reordered")
	}
	for name, try := range map[string][]string{
		"an extra endpoint": {"v1:8443", "v2:8443", "v3:8443"},
		"one endpoint":      {"v1:8443"},
		"another vault":     {"v1:8443", "evil:8443"},
	} {
		if c.Matches("abc123", try) {
			t.Errorf("%s matched the approved constellation", name)
		}
	}
	if c.Matches("deadbeef", []string{"v1:8443", "v2:8443"}) {
		t.Error("another measurement matched")
	}

	// A later document about peers alone must not unpin the vault.
	peers := docJSON(2, `,"dependencies":{"entries":[]}`)
	if _, _, err := s.Accept(envelope(t, peers, idp.approve(t, "owner-1", peers))); err != nil {
		t.Fatal(err)
	}
	if got := s.ConstellationFor(testApp); !got.Valid() || got.Mrenclave != "abc123" {
		t.Errorf("the approved constellation was lost: %+v", got)
	}

	// An app whose owner approved none is unconstrained.
	var none *Constellation
	if !none.Matches("anything", []string{"any:8443"}) {
		t.Error("an app with no approved constellation was constrained")
	}
}
