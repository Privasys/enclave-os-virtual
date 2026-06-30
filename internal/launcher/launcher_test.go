package launcher

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/manifest"
	"github.com/Privasys/enclave-os-virtual/internal/sessionrelay"
	"go.uber.org/zap"
)

// fakeAppHostRouter satisfies AppHostRouter for tests. The no-op methods cover
// routing side effects; SetExpectedWorkloadDigest records its argument so tests
// can assert the arm actually fired (not silently skipped).
type fakeAppHostRouter struct {
	gotDigest    [32]byte
	gotDigestSet bool
}

func (*fakeAppHostRouter) RegisterAppHost(string, string)                      {}
func (*fakeAppHostRouter) UnregisterAppHost(string)                            {}
func (*fakeAppHostRouter) SetSessionRelayIdentityKeySeed(string, []byte) error { return nil }
func (f *fakeAppHostRouter) SetExpectedWorkloadDigest(_ string, d [32]byte) {
	f.gotDigest = d
	f.gotDigestSet = true
}

// TestArmSessionRelayWorkloadDigestNoSelfDeadlock pins the regression where
// Load (holding l.mu for writing) called armSessionRelayWorkloadDigest, which
// re-acquired l.mu.RLock(). sync.RWMutex is not reentrant, so the writer
// blocked forever on its own read lock — wedging every subsequent Load/Unload
// behind the held write lock and silently preventing any public-hostname app
// from coming up on the host. armSessionRelayWorkloadDigest must read the
// launcher maps WITHOUT re-locking, since its sole caller already holds the
// write lock.
func TestArmSessionRelayWorkloadDigestNoSelfDeadlock(t *testing.T) {
	const name, host = "app1", "app1.apps.privasys.org"
	// NB: no containerTrees seeded — the arm must compute the root from the
	// spec, not depend on recomputeAttestation having populated the tree.
	l := &Launcher{
		log:              zap.NewNop(),
		appHostRouter:    &fakeAppHostRouter{},
		specs:            map[string]manifest.Container{name: {Image: "ghcr.io/privasys/apps/app1@sha256:" + strings.Repeat("a", 64)}},
		imageDigests:     map[string][]byte{name: bytes.Repeat([]byte{1}, 32)},
		volumeEncryption: map[string]string{name: "ephemeral"},
	}

	done := make(chan struct{})
	go func() {
		l.mu.Lock()
		l.armSessionRelayWorkloadDigest(name, host) // must not re-lock l.mu
		l.mu.Unlock()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("armSessionRelayWorkloadDigest self-deadlocked while its caller held l.mu (write)")
	}
}

// TestArmSessionRelayWorkloadDigestFires pins the SECOND regression: the arm
// read l.containerTrees, which on Load is only populated AFTER this point, so
// it silently returned without ever calling SetExpectedWorkloadDigest — Sc 1
// (wake on a code/config change) never armed live. The arm must compute the
// config-merkle root from the spec and set the digest, with the same value the
// attested leaf carries (image ref stripped of any @sha256:… suffix).
func TestArmSessionRelayWorkloadDigestFires(t *testing.T) {
	const name, host = "app1", "app1.apps.privasys.org"
	imageDigest := bytes.Repeat([]byte{1}, 32)
	spec := manifest.Container{Image: "ghcr.io/privasys/apps/app1@sha256:" + strings.Repeat("a", 64)}
	r := &fakeAppHostRouter{}
	l := &Launcher{
		log:              zap.NewNop(),
		appHostRouter:    r,
		specs:            map[string]manifest.Container{name: spec},
		imageDigests:     map[string][]byte{name: imageDigest},
		volumeEncryption: map[string]string{name: "ephemeral"},
	}

	l.mu.Lock()
	l.armSessionRelayWorkloadDigest(name, host)
	l.mu.Unlock()

	if !r.gotDigestSet {
		t.Fatal("arm silently skipped: SetExpectedWorkloadDigest was never called")
	}
	root := spec.ContainerMerkleTree(imageDigest).Root()
	want := sessionrelay.WorkloadDigest(map[string]string{
		sessionrelay.WorkloadConfigMerkleRoot: hex.EncodeToString(root[:]),
		sessionrelay.WorkloadCodeHash:         hex.EncodeToString(imageDigest),
		sessionrelay.WorkloadImageRef:         "ghcr.io/privasys/apps/app1", // @sha256:… stripped
		sessionrelay.WorkloadKeySource:        "ephemeral",
	})
	if r.gotDigest != want {
		t.Fatalf("armed digest mismatch:\n got %x\nwant %x", r.gotDigest, want)
	}
}

func TestLoadRequestRuntimeEnv(t *testing.T) {
	req := LoadRequest{
		Name:  "test",
		Image: "example.com/img@sha256:abcd",
		Port:  8000,
	}
	if env := req.runtimeEnv(); len(env) != 0 {
		t.Fatalf("expected empty runtime env, got %v", env)
	}
}

func TestVaultFieldsNotInSpec(t *testing.T) {
	req := LoadRequest{
		Name:                   "test",
		Image:                  "example.com/img@sha256:abcd",
		Port:                   8000,
		KeyHandle:              "apps.privasys.org/app/storage-kek/v1",
		VaultEndpoints:         []string{"141.94.219.130:8443"},
		VaultMrenclave:         "015ff920efbe97be7593a657169d10fb9f7ab285805c7b02d81a807431c427ae",
		VaultAttestationServer: "https://as.privasys.org/verify",
	}

	spec := req.toContainerSpec()

	// The vault addressing fields are deployment plumbing, not workload
	// identity: they must not leak into the attested container spec.
	// (The resulting key origin IS attested, via OID 3.4.)
	if _, ok := spec.Env["KEY_HANDLE"]; ok {
		t.Fatal("vault fields should not be in the attested spec env")
	}
}

func TestValidateLoadRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     LoadRequest
		wantErr bool
	}{
		{
			name:    "valid",
			req:     LoadRequest{Name: "a", Image: "img@sha256:abc", Port: 443},
			wantErr: false,
		},
		{
			name: "valid with key handle",
			req: LoadRequest{
				Name: "a", Image: "img@sha256:abc", Port: 443,
				Storage:   "1G",
				KeyHandle: "apps.privasys.org/a/storage-kek/v1",
			},
			wantErr: false,
		},
		{
			name:    "missing name",
			req:     LoadRequest{Image: "img", Port: 443},
			wantErr: true,
		},
		{
			name:    "missing image",
			req:     LoadRequest{Name: "a", Port: 443},
			wantErr: true,
		},
		{
			name:    "bad port",
			req:     LoadRequest{Name: "a", Image: "img", Port: 0},
			wantErr: true,
		},
		{
			name:    "reserved platform port 8080",
			req:     LoadRequest{Name: "a", Image: "img@sha256:abc", Port: 8080},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseRegistryAuth(t *testing.T) {
	// Canonical JSON shape.
	a, err := parseRegistryAuth([]byte(`{"username":"u","password":"p"}`))
	if err != nil || a.Username != "u" || a.Password != "p" {
		t.Fatalf("json cred: got %+v err=%v", a, err)
	}
	// Surrounding whitespace is tolerated.
	if a, err := parseRegistryAuth([]byte("  {\"password\":\"p\"}\n")); err != nil || a.Password != "p" {
		t.Fatalf("whitespace json cred: got %+v err=%v", a, err)
	}
	// Bare token becomes the password.
	b, err := parseRegistryAuth([]byte("ghp_rawtoken"))
	if err != nil || b.Password != "ghp_rawtoken" || b.Username == "" {
		t.Fatalf("bare token: got %+v err=%v", b, err)
	}
	// Empty / no-password are rejected.
	if _, err := parseRegistryAuth([]byte("   ")); err == nil {
		t.Fatal("expected error for empty credential")
	}
	if _, err := parseRegistryAuth([]byte(`{"username":"u"}`)); err == nil {
		t.Fatal("expected error for credential with no password")
	}
}

func TestPinnedDigestBytes(t *testing.T) {
	hexDigest := "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
	got, err := pinnedDigestBytes("registry.example.com/app@sha256:" + hexDigest)
	if err != nil || len(got) != 32 {
		t.Fatalf("valid pinned ref: got %x err=%v", got, err)
	}
	if _, err := pinnedDigestBytes("registry.example.com/app:latest"); err == nil {
		t.Fatal("expected error for unpinned ref")
	}
	if _, err := pinnedDigestBytes("app@sha256:zzzz"); err == nil {
		t.Fatal("expected error for invalid digest hex")
	}
}
