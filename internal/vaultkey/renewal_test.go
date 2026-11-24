package vaultkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"
	"go.uber.org/zap"
)

const testMre = "1111111111111111111111111111111111111111111111111111111111111111"

// fakeVault is one vault: its identity, the policies it holds, and what was
// created on it.
type fakeVault struct {
	member, billing string
	v1              bool
	policies        map[string]json.RawMessage
	versions        map[string]uint32
	policyErr       error
	created         map[string]*vault.Renewal // handle → renewal (nil: v1 create)
	deleted         map[string]bool
	deleteErr       error
	shares          map[string][]byte // handle → share payload
}

type fakeConn struct{ v *fakeVault }

func (c fakeConn) ExportKey(_ context.Context, handle string, _ ...vault.ApprovalToken) ([]byte, error) {
	if s, ok := c.v.shares[handle]; ok && !c.v.deleted[handle] {
		return s, nil
	}
	return nil, errors.New("key not found")
}
func (c fakeConn) CreateKey(_ context.Context, handle string, m []byte, _ string) (uint64, error) {
	c.v.created[handle] = nil
	c.v.shares[handle] = m
	return 1, nil
}
func (c fakeConn) CreateKeyRenewal(_ context.Context, handle string, m []byte, _ string, r vault.Renewal) (uint64, error) {
	if c.v.v1 {
		return 0, vault.ErrUnsupported
	}
	c.v.created[handle] = &r
	c.v.shares[handle] = m
	return 1, nil
}
func (c fakeConn) GetPolicyRaw(_ context.Context, handle string) (json.RawMessage, uint32, error) {
	if c.v.policyErr != nil {
		return nil, 0, c.v.policyErr
	}
	p, ok := c.v.policies[handle]
	if !ok {
		return nil, 0, errors.New("key not found")
	}
	return p, c.v.versions[handle], nil
}
func (c fakeConn) GetVaultIdentity(context.Context) (vault.VaultIdentity, error) {
	if c.v.v1 {
		return vault.VaultIdentity{}, vault.ErrUnsupported
	}
	return vault.VaultIdentity{MemberID: c.v.member, BillingID: c.v.billing, MRENCLAVE: testMre}, nil
}
func (c fakeConn) GetKeyInfo(_ context.Context, handle string) (vault.KeyInfo, error) {
	if _, ok := c.v.created[handle]; !ok {
		return vault.KeyInfo{}, errors.New("key not found")
	}
	return vault.KeyInfo{Handle: handle}, nil
}
// RetireKey applies the vault's member rule: in place (successor held here)
// this vault must be among the successor's members, on a move it must not.
func (c fakeConn) RetireKey(_ context.Context, handle, successor string, members []string) (bool, error) {
	if c.v.v1 {
		return false, vault.ErrUnsupported
	}
	if c.v.deleteErr != nil {
		return false, c.v.deleteErr
	}
	_, here := c.v.created[successor]
	if here != slices.Contains(members, c.v.member) {
		return false, fmt.Errorf("successor_members inconsistent with this vault (here=%v)", here)
	}
	if c.v.deleted == nil {
		c.v.deleted = map[string]bool{}
	}
	if c.v.deleted[handle] {
		return false, nil
	}
	c.v.deleted[handle] = true
	return true, nil
}
func (c fakeConn) Close() error { return nil }

// fleet installs fake vaults behind dial for the test.
func fleet(t *testing.T, vaults map[string]*fakeVault) {
	t.Helper()
	for _, v := range vaults {
		if v.created == nil {
			v.created = map[string]*vault.Renewal{}
		}
		if v.shares == nil {
			v.shares = map[string][]byte{}
		}
	}
	prev := dial
	dial = func(_ context.Context, ep string, _ vault.DialOptions) (vaultConn, error) {
		v, ok := vaults[ep]
		if !ok {
			return nil, fmt.Errorf("unreachable %s", ep)
		}
		return fakeConn{v}, nil
	}
	t.Cleanup(func() { dial = prev })
}

func cfgOf(eps ...string) Config {
	return Config{Endpoints: eps, Threshold: 2, MrenclaveHex: testMre, AttestationServerURL: "https://as.test", AttestationToken: "t"}
}

const policy = `{"version":1,"principals":{"owner":"o"},"operations":[],"future_field":{"kept":true}}`

func source(member string) *fakeVault {
	return &fakeVault{member: member, billing: "b1",
		policies: map[string]json.RawMessage{"k/v1": json.RawMessage(policy)},
		versions: map[string]uint32{"k/v1": 7}}
}

var material = bytes.Repeat([]byte{9}, dekSize)

func TestRenewInPlaceSendsOnlyThePredecessor(t *testing.T) {
	vs := map[string]*fakeVault{"a": source("m1"), "b": source("m2"), "c": source("m3")}
	fleet(t, vs)
	c := cfgOf("a", "b", "c")
	if _, _, err := Renew(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", "g", material, nil, nil); err != nil {
		t.Fatal(err)
	}
	for ep, v := range vs {
		r := v.created["k/v2"]
		if r == nil || r.Predecessor != "k/v1" || r.Policy != nil || r.KeyCheck != nil {
			t.Fatalf("%s: in-place create = %+v", ep, r)
		}
	}
}

func TestRenewMoveCarriesThePolicyVerbatim(t *testing.T) {
	vs := map[string]*fakeVault{
		"a": source("m1"), "b": source("m2"), "c": source("m3"),
		"x": {member: "n1", billing: "b1"}, "y": {member: "n2", billing: "b1"},
	}
	fleet(t, vs)
	if _, _, err := Renew(context.Background(), zap.NewNop(), cfgOf("a", "b", "c"), cfgOf("x", "y"), "k/v1", "k/v2", "g", material, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, ep := range []string{"x", "y"} {
		r := vs[ep].created["k/v2"]
		if r == nil || r.Predecessor != "" || string(r.Policy) != policy || r.PolicyVersion != 7 || r.SourceBillingID != "b1" || r.KeyCheck == nil {
			t.Fatalf("%s: carried create = %+v", ep, r)
		}
	}
}

func TestRotateNeverGoesInPlace(t *testing.T) {
	vs := map[string]*fakeVault{"a": source("m1"), "b": source("m2")}
	fleet(t, vs)
	c := cfgOf("a", "b")
	if _, _, _, err := Rotate(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", "g", nil, nil); err != nil {
		t.Fatal(err)
	}
	r := vs["a"].created["k/v2"]
	if r == nil || r.Predecessor != "" || string(r.Policy) != policy || r.KeyCheck == nil {
		t.Fatalf("rotation create = %+v", r)
	}
}

func TestMoveRefusesDisagreeingSources(t *testing.T) {
	stale := source("m2")
	stale.versions["k/v1"] = 6
	vs := map[string]*fakeVault{"a": source("m1"), "b": stale, "x": {member: "n1", billing: "b1"}, "y": {member: "n2", billing: "b1"}}
	fleet(t, vs)
	_, _, err := Renew(context.Background(), zap.NewNop(), cfgOf("a", "b"), cfgOf("x", "y"), "k/v1", "k/v2", "g", material, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("err = %v", err)
	}
	if len(vs["x"].created) != 0 {
		t.Fatal("created on the target despite disagreement")
	}
}

func TestMoveNeedsThresholdSources(t *testing.T) {
	down := source("m2")
	down.policyErr = errors.New("timeout")
	vs := map[string]*fakeVault{"a": source("m1"), "b": down, "x": {member: "n1", billing: "b1"}, "y": {member: "n2", billing: "b1"}}
	fleet(t, vs)
	if _, _, err := Renew(context.Background(), zap.NewNop(), cfgOf("a", "b"), cfgOf("x", "y"), "k/v1", "k/v2", "g", material, nil, nil); err == nil {
		t.Fatal("moved on one source answer with threshold 2")
	}
}

func TestMoveRefusesAnotherBillingConfiguration(t *testing.T) {
	vs := map[string]*fakeVault{"a": source("m1"), "b": source("m2"), "x": {member: "n1", billing: "prod"}, "y": {member: "n2", billing: "prod"}}
	fleet(t, vs)
	_, _, err := Renew(context.Background(), zap.NewNop(), cfgOf("a", "b"), cfgOf("x", "y"), "k/v1", "k/v2", "g", material, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "billing") {
		t.Fatalf("err = %v", err)
	}
}

func TestV1TargetKeepsTheGrantCreate(t *testing.T) {
	vs := map[string]*fakeVault{"a": {v1: true}, "b": {v1: true}}
	fleet(t, vs)
	c := cfgOf("a", "b")
	if _, _, err := Renew(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", "g", material, nil, nil); err != nil {
		t.Fatal(err)
	}
	if r, ok := vs["a"].created["k/v2"]; !ok || r != nil {
		t.Fatalf("v1 create = %+v, %v", r, ok)
	}
}

func v1Source() *fakeVault {
	v := source("")
	v.v1 = true
	return v
}

func TestV1SourceWithoutIssuerIsRefused(t *testing.T) {
	vs := map[string]*fakeVault{"a": v1Source(), "b": v1Source(), "x": {member: "n1", billing: "b1"}, "y": {member: "n2", billing: "b1"}}
	fleet(t, vs)
	_, _, err := Renew(context.Background(), zap.NewNop(), cfgOf("a", "b"), cfgOf("x", "y"), "k/v1", "k/v2", "g", material, nil, nil)
	if !errors.Is(err, ErrV1Source) {
		t.Fatalf("err = %v", err)
	}
}

// Security: a missing issuer or audience refuses the move; no id is derived
// from an empty string and nothing is created.
func TestV1SourceWithHalfTheIssuerIsRefused(t *testing.T) {
	for _, half := range [][2]string{{"https://privasys.id", ""}, {"", "privasys-platform-test"}} {
		vs := map[string]*fakeVault{"a": v1Source(), "b": v1Source(), "x": {member: "n1", billing: "b1"}, "y": {member: "n2", billing: "b1"}}
		fleet(t, vs)
		src := cfgOf("a", "b")
		src.V1Issuer, src.V1Audience = half[0], half[1]
		_, _, _, err := Rotate(context.Background(), zap.NewNop(), src, cfgOf("x", "y"), "k/v1", "k/v2", "g", nil, nil)
		if !errors.Is(err, ErrV1Source) || len(vs["x"].created) != 0 {
			t.Fatalf("%q: err = %v, created = %v", half, err, vs["x"].created)
		}
	}
}

func TestV1SourceCarriesTheDerivedBillingID(t *testing.T) {
	dev := vault.ImplicitBillingID("https://privasys.id", "privasys-platform-test")
	vs := map[string]*fakeVault{"a": v1Source(), "b": v1Source(), "x": {member: "n1", billing: dev}, "y": {member: "n2", billing: dev}}
	fleet(t, vs)
	src := cfgOf("a", "b")
	src.V1Issuer, src.V1Audience = "https://privasys.id", "privasys-platform-test"
	if _, _, err := Renew(context.Background(), zap.NewNop(), src, cfgOf("x", "y"), "k/v1", "k/v2", "g", material, nil, nil); err != nil {
		t.Fatal(err)
	}
	r := vs["x"].created["k/v2"]
	if r == nil || r.SourceBillingID != dev || string(r.Policy) != policy || r.PolicyVersion != 7 {
		t.Fatalf("carried create = %+v", r)
	}
}

func TestV1DevSourceCannotMoveIntoProd(t *testing.T) {
	prod := vault.ImplicitBillingID("https://privasys.id", "privasys-platform")
	vs := map[string]*fakeVault{"a": v1Source(), "b": v1Source(), "x": {member: "n1", billing: prod}, "y": {member: "n2", billing: prod}}
	fleet(t, vs)
	src := cfgOf("a", "b")
	src.V1Issuer, src.V1Audience = "https://privasys.id", "privasys-platform-test"
	if _, _, err := Renew(context.Background(), zap.NewNop(), src, cfgOf("x", "y"), "k/v1", "k/v2", "g", material, nil, nil); err == nil {
		t.Fatal("a dev key moved into prod")
	}
}

// The interim id must equal the vault's own (enclave-os-vault v2.rs).
func TestImplicitBillingIDMatchesTheVault(t *testing.T) {
	got := vault.ImplicitBillingID("https://privasys.id", "privasys-platform")
	sum := sha256.Sum256([]byte("privasys-billing-implicit-v0\nhttps://privasys.id\nprivasys-platform"))
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("ImplicitBillingID = %s", got)
	}
}

func TestMixedBuildConstellationIsRefused(t *testing.T) {
	vs := map[string]*fakeVault{"a": {v1: true}, "b": source("m2")}
	fleet(t, vs)
	c := cfgOf("a", "b")
	if _, _, err := Renew(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", "g", material, nil, nil); err == nil {
		t.Fatal("renewed on a half-v1 constellation")
	}
}

func TestDuplicateMemberIsRefused(t *testing.T) {
	vs := map[string]*fakeVault{"a": source("m1"), "b": source("m1")}
	fleet(t, vs)
	c := cfgOf("a", "b")
	if _, _, err := Renew(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", "g", material, nil, nil); err == nil {
		t.Fatal("two endpoints with one member id accepted")
	}
}

// seed stores a 2-of-n split of key under handle on the given vaults.
func seed(t *testing.T, handle string, key []byte, vs ...*fakeVault) {
	t.Helper()
	shares, err := vault.ShamirSplit(key, 2, len(vs))
	if err != nil {
		t.Fatal(err)
	}
	gen := bytes.Repeat([]byte{byte(len(handle))}, generationSize)
	for i, v := range vs {
		v.created[handle] = &vault.Renewal{}
		v.shares[handle] = encodeShare(gen, shares[i])
	}
}

func inPlace(t *testing.T) (map[string]*fakeVault, Config) {
	vs := map[string]*fakeVault{"a": source("m1"), "b": source("m2")}
	fleet(t, vs)
	seed(t, "k/v1", material, vs["a"], vs["b"])
	seed(t, "k/v2", material, vs["a"], vs["b"])
	return vs, cfgOf("a", "b")
}

func noneDeleted(vs map[string]*fakeVault) bool {
	for _, v := range vs {
		if len(v.deleted) != 0 {
			return false
		}
	}
	return true
}

func TestRetireInPlaceDeletesOnEveryVault(t *testing.T) {
	vs, c := inPlace(t)
	if err := RetirePredecessor(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", nil, nil); err != nil {
		t.Fatal(err)
	}
	if !vs["a"].deleted["k/v1"] || !vs["b"].deleted["k/v1"] {
		t.Fatal("predecessor not deleted on every vault")
	}
	// Retried: already gone counts as done.
	if err := RetirePredecessor(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", nil, nil); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestRetireSkipsWhenAVaultLacksTheSuccessor(t *testing.T) {
	vs, c := inPlace(t)
	delete(vs["b"].created, "k/v2") // b does not confirm it
	if err := RetirePredecessor(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", nil, nil); !errors.Is(err, ErrNotRetired) || !noneDeleted(vs) {
		t.Fatalf("err = %v", err)
	}
}

func TestRetireRefusesASuccessorWithAnotherValue(t *testing.T) {
	vs, c := inPlace(t)
	seed(t, "k/v2", bytes.Repeat([]byte{7}, dekSize), vs["a"], vs["b"])
	if err := RetirePredecessor(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", nil, nil); !errors.Is(err, ErrNotRetired) || !noneDeleted(vs) {
		t.Fatalf("err = %v", err)
	}
}

func TestRetireReportsAPartialDelete(t *testing.T) {
	vs, c := inPlace(t)
	vs["b"].deleteErr = errors.New("timeout")
	if err := RetirePredecessor(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", nil, nil); !errors.Is(err, ErrNotRetired) {
		t.Fatalf("err = %v", err)
	}
}

// formats §9.1: after a move the old generation is never retired by the app.
func TestRetireNeverRunsAfterAMove(t *testing.T) {
	vs := map[string]*fakeVault{"a": source("m1"), "b": source("m2"), "x": {member: "n1", billing: "b1"}, "y": {member: "n2", billing: "b1"}}
	fleet(t, vs)
	seed(t, "k/v1", material, vs["a"], vs["b"])
	seed(t, "k/v2", material, vs["x"], vs["y"])
	err := RetirePredecessor(context.Background(), zap.NewNop(), cfgOf("a", "b"), cfgOf("x", "y"), "k/v1", "k/v2", nil, nil)
	if !errors.Is(err, ErrNotRetired) || !strings.Contains(err.Error(), "moved") || !noneDeleted(vs) {
		t.Fatalf("err = %v", err)
	}
}

func TestRetireLeavesAV1ConstellationAlone(t *testing.T) {
	vs := map[string]*fakeVault{"a": v1Source(), "b": v1Source()}
	fleet(t, vs)
	seed(t, "k/v1", material, vs["a"], vs["b"])
	seed(t, "k/v2", material, vs["a"], vs["b"])
	c := cfgOf("a", "b")
	if err := RetirePredecessor(context.Background(), zap.NewNop(), c, c, "k/v1", "k/v2", nil, nil); !errors.Is(err, ErrNotRetired) || !noneDeleted(vs) {
		t.Fatalf("err = %v", err)
	}
}
