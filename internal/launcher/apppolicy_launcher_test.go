package launcher

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"go.uber.org/zap"

	"enclave-os-mini/clients/go/ratls"
	"github.com/Privasys/enclave-os-virtual/internal/apppolicy"
	"github.com/Privasys/enclave-os-virtual/internal/manifest"
)

// recordingRouter captures what the launcher installs for a host.
type recordingRouter struct {
	host      string
	policy    *ratls.DependencySet
	platforms []string
	calls     int
}

func (r *recordingRouter) RegisterAppHost(string, string) {}
func (r *recordingRouter) UnregisterAppHost(string)       {}
func (r *recordingRouter) RegisterIngressPolicy(hostname string, policy *ratls.DependencySet, platforms []string) {
	r.host, r.policy, r.platforms, r.calls = hostname, policy, platforms, r.calls+1
}
func (r *recordingRouter) SetSessionRelayIdentityKeySeed(string, []byte) error { return nil }
func (r *recordingRouter) SetExpectedWorkloadDigest(string, [32]byte)          {}
func (r *recordingRouter) SetStaticUnsealedPrefixes(string, []string)          {}

func TestAppIDOfResolvesALoadedContainer(t *testing.T) {
	l := New(Config{}, zap.NewNop())
	raw, _ := hex.DecodeString("11112222333344445555666677778888")
	l.appIDs["app"] = raw

	if got := l.AppIDOf("app"); got != "11112222333344445555666677778888" {
		t.Errorf("app id = %q", got)
	}
	if got := l.AppIDOf("other"); got != "" {
		t.Errorf("unknown container gave %q, want empty", got)
	}
}

// An owner's signed allowed callers take effect on the running host, so the
// app does not have to be redeployed for the policy to apply.
func TestSetIngressAllowedCallersInstallsOnTheHost(t *testing.T) {
	l := New(Config{}, zap.NewNop())
	router := &recordingRouter{}
	l.appHostRouter = router
	l.specs["app"] = manifest.Container{Hostname: "app.example.org"}

	set := &ratls.DependencySet{Entries: []ratls.DependencyEntry{{AppID: "aaaa"}}}
	if err := l.SetIngressAllowedCallers("app", set, []string{"platform-1"}); err != nil {
		t.Fatal(err)
	}
	if router.calls != 1 || router.host != "app.example.org" {
		t.Fatalf("router calls=%d host=%q", router.calls, router.host)
	}
	if router.policy == nil || len(router.policy.Entries) != 1 {
		t.Fatal("the policy was not installed")
	}
	if len(router.platforms) != 1 || router.platforms[0] != "platform-1" {
		t.Errorf("platforms = %v", router.platforms)
	}
	if got := l.specs["app"].IngressAllowedCallers; got == nil || len(got.Entries) != 1 {
		t.Error("the spec did not keep the new callers")
	}

	// An empty set disables ingress verification rather than admitting nobody
	// by accident.
	if err := l.SetIngressAllowedCallers("app", &ratls.DependencySet{}, nil); err != nil {
		t.Fatal(err)
	}
	if router.policy != nil {
		t.Error("an empty set left a policy installed")
	}
	if err := l.SetIngressAllowedCallers("missing", set, nil); err == nil {
		t.Error("an unknown container was accepted")
	}
}

func TestSetConfigOwnersReplacesTheTeam(t *testing.T) {
	l := New(Config{}, zap.NewNop())
	l.configOwners["app"] = []string{"old"}
	l.SetConfigOwners("app", []string{"new-a", "new-b"})
	got := l.configOwners["app"]
	if len(got) != 2 || got[0] != "new-a" {
		t.Errorf("owners = %v", got)
	}
}

// The certificate advertises which owner-signed document the app enforces, so
// a verifier can tell a current policy from an older one a host restored.
func TestAppPolicyStampIsAdvertised(t *testing.T) {
	l := New(Config{}, zap.NewNop())
	l.specs["app"] = manifest.Container{Hostname: "app.example.org"}

	var digest [32]byte
	copy(digest[:], []byte("a-document-digest-32-bytes-long!!"))
	if err := l.SetAppPolicyStamp("app", 7, digest); err != nil {
		t.Fatal(err)
	}
	got, ok := l.appPolicy["app"]
	if !ok {
		t.Fatal("no stamp recorded")
	}
	if len(got) != 40 {
		t.Fatalf("stamp is %d bytes, want 8 + 32", len(got))
	}
	if seq := binary.BigEndian.Uint64(got[:8]); seq != 7 {
		t.Errorf("seq in the stamp = %d", seq)
	}
	if string(got[8:]) != string(digest[:]) {
		t.Error("the document digest was not carried")
	}
	// A newer document replaces the stamp: the certificate must not keep
	// advertising the older one.
	var next [32]byte
	copy(next[:], []byte("the-next-document-digest-32-byte!"))
	if err := l.SetAppPolicyStamp("app", 8, next); err != nil {
		t.Fatal(err)
	}
	if seq := binary.BigEndian.Uint64(l.appPolicy["app"][:8]); seq != 8 {
		t.Errorf("stamp did not advance: %d", seq)
	}
	if err := l.SetAppPolicyStamp("missing", 1, digest); err == nil {
		t.Error("an unknown container was accepted")
	}
}

// approvedFor is a stand-in for the policy store.
type approvedFor map[string]*apppolicy.Constellation

func (a approvedFor) ConstellationFor(appID string) *apppolicy.Constellation { return a[appID] }

// A load must not resolve a key on a constellation the owner never approved,
// whatever the request says.
func TestApprovedConstellationRefusesAnotherVault(t *testing.T) {
	l := New(Config{}, zap.NewNop())
	const appID = "11112222333344445555666677778888"
	l.SetApprovedConstellations(approvedFor{appID: {
		Mrenclave: "abc123",
		Endpoints: []string{"v1:8443", "v2:8443"},
	}})

	if err := l.checkApprovedConstellation(appID, "abc123", []string{"v2:8443", "v1:8443"}); err != nil {
		t.Fatalf("the approved constellation was refused: %v", err)
	}
	err := l.checkApprovedConstellation(appID, "abc123", []string{"v1:8443", "evil:8443"})
	if err == nil {
		t.Fatal("a substituted endpoint was accepted")
	}
	if !strings.Contains(err.Error(), "owner approved") {
		t.Errorf("the error does not say why: %v", err)
	}
	if err := l.checkApprovedConstellation(appID, "deadbeef", []string{"v1:8443", "v2:8443"}); err == nil {
		t.Error("another vault measurement was accepted")
	}
	// An app with no approved constellation, and a container with no app id,
	// are both unconstrained.
	if err := l.checkApprovedConstellation("99999999999999999999999999999999", "x", []string{"y"}); err != nil {
		t.Errorf("an app with no approved constellation was refused: %v", err)
	}
	if err := l.checkApprovedConstellation("", "x", []string{"y"}); err != nil {
		t.Errorf("a container with no app id was refused: %v", err)
	}
}
