package apppolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	if _, _, err := s.Accept(envelope(t, doc, idp.approve(t, "owner-1", doc)), testApp); err != nil {
		t.Fatalf("first document refused: %v", err)
	}
	if s.Approver(testApp) != "owner-1" {
		t.Fatalf("approver = %q", s.Approver(testApp))
	}
	next := docJSON(2, "")
	if _, _, err := s.Accept(envelope(t, next, idp.approve(t, "someone-else", next)), testApp); err == nil {
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
	if _, _, err := s.Accept(envelope(t, other, token), testApp); err == nil {
		t.Fatal("an approval for one document installed another")
	}
	if _, _, err := s.Accept(envelope(t, approved, token), testApp); err != nil {
		t.Fatalf("the approved document was refused: %v", err)
	}
}

func TestSequenceMustAdvance(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	five := docJSON(5, "")
	if _, _, err := s.Accept(envelope(t, five, idp.approve(t, "owner-1", five)), testApp); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{4, 5} {
		d := docJSON(seq, "")
		if _, _, err := s.Accept(envelope(t, d, idp.approve(t, "owner-1", d)), testApp); err == nil {
			t.Errorf("seq %d was accepted after 5", seq)
		}
	}
	six := docJSON(6, "")
	if _, _, err := s.Accept(envelope(t, six, idp.approve(t, "owner-1", six)), testApp); err != nil {
		t.Errorf("seq 6 refused: %v", err)
	}
}

// An app changes hands when the current owner approves a document naming the
// next approver.
func TestApproverHandover(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	first := docJSON(1, "")
	if _, _, err := s.Accept(envelope(t, first, idp.approve(t, "owner-1", first)), testApp); err != nil {
		t.Fatal(err)
	}
	handover := docJSON(2, `,"approver":"owner-2"`)
	// The incoming owner cannot hand the app to themselves.
	if _, _, err := s.Accept(envelope(t, handover, idp.approve(t, "owner-2", handover)), testApp); err == nil {
		t.Fatal("the incoming approver approved their own handover")
	}
	if _, _, err := s.Accept(envelope(t, handover, idp.approve(t, "owner-1", handover)), testApp); err != nil {
		t.Fatalf("handover refused: %v", err)
	}
	if got := s.Approver(testApp); got != "owner-2" {
		t.Fatalf("approver after handover = %q", got)
	}
	after := docJSON(3, "")
	if _, _, err := s.Accept(envelope(t, after, idp.approve(t, "owner-1", after)), testApp); err == nil {
		t.Error("the previous owner still approved policy")
	}
	if _, _, err := s.Accept(envelope(t, after, idp.approve(t, "owner-2", after)), testApp); err != nil {
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
	if _, _, err := s.Accept(envelope(t, doc, token), testApp); err == nil {
		t.Fatal("a token with no step-up was accepted")
	}
}

func TestUnverifiableTokenIsRefused(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	doc := docJSON(1, "")
	token := idp.approve(t, "owner-1", doc)
	idp.fail = true
	if _, _, err := s.Accept(envelope(t, doc, token), testApp); err == nil {
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
	if _, _, err := s.Accept(envelope(t, doc, idp.approve(t, "owner-1", doc)), testApp); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(path, idp)
	if err != nil {
		t.Fatal(err)
	}
	if again.Approver(testApp) != "owner-1" {
		t.Fatal("the pin did not survive a reload")
	}
	if _, _, err := again.Accept(envelope(t, doc, idp.approve(t, "owner-1", doc)), testApp); err == nil {
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
		if _, _, err := s.Accept(raw, testApp); err == nil {
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
	if _, _, err := s.Accept(envelope(t, withVault, idp.approve(t, "owner-1", withVault)), testApp); err != nil {
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
	if _, _, err := s.Accept(envelope(t, peers, idp.approve(t, "owner-1", peers)), testApp); err != nil {
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

// The identity provider puts the binding in `vault_op` as unpadded base64url.
// The fake above mints its tokens with Binding itself, so it cannot catch a
// change of encoding: this vector comes from the identity provider's own
// computation.
func TestBindingMatchesTheIdentityProvider(t *testing.T) {
	got := Binding("app:f36925ff3553469987f9908a2d530ff7:policy",
		"d14a59e695616fe837847654828bcbd8e8e56bdc8512077f39d213814bd53a45", 1, "bm9uY2U", 1793116800)
	if want := "4MoJ5Gksw4iT95c430SJJiI9MVWR9u64HPnp4yL9p24"; got != want {
		t.Fatalf("Binding = %s, want the identity provider's %s", got, want)
	}
}

func TestValidateDomains(t *testing.T) {
	ok := [][]string{nil, {"app.example.com"}, {"a.example.com", "b-2.example.org"}}
	for _, d := range ok {
		if err := ValidateDomains(d); err != nil {
			t.Errorf("ValidateDomains(%v) = %v, want nil", d, err)
		}
	}
	bad := [][]string{
		{"*.example.com"}, {"App.example.com"}, {"example"}, {"example.com."},
		{"-a.example.com"}, {"a.example.com", "a.example.com"}, {"a_b.example.com"},
	}
	for _, d := range bad {
		if err := ValidateDomains(d); err == nil {
			t.Errorf("ValidateDomains(%v) = nil, want an error", d)
		}
	}
}

// A document delivered to another app is refused before anything is pinned,
// however validly it was approved.
func TestDocumentForAnotherAppPinsNothing(t *testing.T) {
	idp := newIdP()
	s := newStore(t, idp)
	doc := docJSON(1, "")
	raw := envelope(t, doc, idp.approve(t, "owner-1", doc))
	for _, target := range []string{"99998888777766665555444433332222", ""} {
		if _, _, err := s.Accept(raw, target); err == nil {
			t.Fatalf("a document for %s was accepted for %q", testApp, target)
		}
	}
	if s.Pinned(testApp) {
		t.Fatal("a refused document pinned its app")
	}
	if _, _, err := s.Accept(raw, testApp); err != nil {
		t.Fatalf("the same document for its own app: %v", err)
	}
}

// A direct domain has one owner on a host, durably: the first accepted
// policy naming it owns it, another app's policy naming it is refused (and
// pins nothing), the owner keeps it across its own updates, and once the
// owner's policy drops it another app may take it. Ownership survives a
// reload of the store.
func TestDirectDomainHasOneOwnerInTheStore(t *testing.T) {
	idp := newIdP()
	path := filepath.Join(t.TempDir(), "pins.json")
	s, err := NewStore(path, idp)
	if err != nil {
		t.Fatal(err)
	}
	const other = "99998888777766665555444433332222"
	docFor := func(app string, seq uint64, domains string) string {
		return fmt.Sprintf(`{"v":1,"app_id":%q,"seq":%d,"domains":%s}`, app, seq, domains)
	}
	accept := func(app string, seq uint64, domains string) error {
		d := docFor(app, seq, domains)
		_, _, err := s.Accept(envelope(t, d, idp.approve(t, "owner-"+app[:4], d)), app)
		return err
	}

	if err := accept(testApp, 1, `["shop.example.com"]`); err != nil {
		t.Fatal(err)
	}
	if err := accept(other, 1, `["shop.example.com","mine.example.com"]`); !errors.Is(err, ErrDomainTaken) {
		t.Fatalf("another app's claim: %v", err)
	}
	if s.Pinned(other) {
		t.Fatal("a refused claim pinned its app")
	}
	if got := s.DomainOwner("shop.example.com"); got != testApp {
		t.Fatalf("owner = %q", got)
	}
	if err := accept(testApp, 2, `["shop.example.com","b.example.com"]`); err != nil {
		t.Fatalf("the owner's own update: %v", err)
	}

	s, err = NewStore(path, idp)
	if err != nil {
		t.Fatal(err)
	}
	if err := accept(other, 2, `["shop.example.com"]`); !errors.Is(err, ErrDomainTaken) {
		t.Fatalf("after a reload: %v", err)
	}
	if err := accept(testApp, 3, `["b.example.com"]`); err != nil {
		t.Fatal(err)
	}
	if err := accept(other, 3, `["shop.example.com"]`); err != nil {
		t.Fatalf("a released domain: %v", err)
	}
	if got := s.DomainOwner("shop.example.com"); got != other {
		t.Fatalf("owner after release = %q", got)
	}
}

// Pins from a runtime before one-owner-per-domain may name one domain twice.
// Such a domain has no owner (nobody serves it, rather than a random one of
// them), it is listed as contested, a holder can still update the rest of
// its policy, and no third app can claim it.
func TestContestedDomainHasNoOwner(t *testing.T) {
	idp := newIdP()
	path := filepath.Join(t.TempDir(), "pins.json")
	const other, third = "99998888777766665555444433332222", "aaaabbbbccccddddeeeeffff00001111"
	pins := fmt.Sprintf(`{%q:{"approver":"owner-1111","seq":1,"domains":["shop.example.com"]},%q:{"approver":"owner-9999","seq":1,"domains":["shop.example.com"]}}`, testApp, other)
	if err := os.WriteFile(path, []byte(pins), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(path, idp)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if got := s.DomainOwner("shop.example.com"); got != "" {
			t.Fatalf("a contested domain has owner %q", got)
		}
	}
	if c := s.ContestedDomains(); len(c["shop.example.com"]) != 2 {
		t.Fatalf("contested = %v", c)
	}
	d := fmt.Sprintf(`{"v":1,"app_id":%q,"seq":2,"domains":["shop.example.com","b.example.com"]}`, testApp)
	if _, _, err := s.Accept(envelope(t, d, idp.approve(t, "owner-1111", d)), testApp); err != nil {
		t.Fatalf("a holder's update that keeps the contested domain: %v", err)
	}
	d = fmt.Sprintf(`{"v":1,"app_id":%q,"seq":1,"domains":["shop.example.com"]}`, third)
	if _, _, err := s.Accept(envelope(t, d, idp.approve(t, "owner-aaaa", d)), third); !errors.Is(err, ErrDomainTaken) {
		t.Fatalf("a third app's claim: %v", err)
	}
}
