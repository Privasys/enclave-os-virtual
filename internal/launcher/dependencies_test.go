package launcher

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ratls "enclave-os-mini/clients/go/ratls"
	"github.com/Privasys/enclave-os-virtual/internal/caddy"
	"github.com/Privasys/enclave-os-virtual/internal/manifest"
	"github.com/Privasys/enclave-os-virtual/internal/merkle"
	"go.uber.org/zap"
)

const depOID61 = "1.3.6.1.4.1.65230.7.1" // attested dependency set (scheme v2)

func depTestSet() *ratls.DependencySet {
	return &ratls.DependencySet{Entries: []ratls.DependencyEntry{{
		AppID: "82cb3965811d4ad298cac29e4837fd45",
		Measurements: []ratls.DepMeasurement{{TDX: &ratls.DepTdxMeasurement{
			MRTD:  strings.Repeat("ab", 48),
			RTMR1: strings.Repeat("cd", 48),
			RTMR2: strings.Repeat("ef", 48),
		}}},
		RequiredOids: []ratls.ExpectedOid{{
			OID:           "1.3.6.1.4.1.65230.4.2",
			ExpectedValue: bytes.Repeat([]byte{7}, 32),
		}},
	}}}
}

func depTestLauncher(t *testing.T, extDir string, deps *ratls.DependencySet) *Launcher {
	t.Helper()
	const name, host = "app1", "app1.apps.privasys.org"
	imageDigest := bytes.Repeat([]byte{1}, 32)
	spec := manifest.Container{
		Name:         name,
		Hostname:     host,
		Port:         10101,
		Image:        "ghcr.io/privasys/apps/app1@sha256:" + strings.Repeat("a", 64),
		Dependencies: deps,
	}
	return &Launcher{
		log:              zap.NewNop(),
		cfg:              Config{ExtensionsDir: extDir},
		caddyClient:      &caddy.Client{},
		specs:            map[string]manifest.Container{name: spec},
		containerTrees:   map[string]*merkle.Tree{name: spec.ContainerMerkleTree(imageDigest)},
		imageDigests:     map[string][]byte{name: imageDigest},
		volumeEncryption: map[string]string{name: "ephemeral"},
	}
}

func readExtValue(t *testing.T, extDir, host, oid string) ([]byte, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(extDir, host+".json"))
	if err != nil {
		t.Fatalf("read extensions file: %v", err)
	}
	var f struct {
		Extensions []struct {
			OID   string `json:"oid"`
			Value string `json:"value"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse extensions file: %v", err)
	}
	for _, e := range f.Extensions {
		if e.OID == oid {
			v, err := base64.StdEncoding.DecodeString(e.Value)
			if err != nil {
				t.Fatalf("decode extension value: %v", err)
			}
			return v, true
		}
	}
	return nil, false
}

// TestWriteContainerExtensionsStampsDependencySet pins the WS2 core: a spec
// with a dependency set gets OID 65230.7.1 on its serving-cert extensions,
// value byte-identical to the SDK's canonical encoding.
func TestWriteContainerExtensionsStampsDependencySet(t *testing.T) {
	dir := t.TempDir()
	set := depTestSet()
	l := depTestLauncher(t, dir, set)

	l.mu.Lock()
	err := l.writeContainerExtensions("app1", "app1.apps.privasys.org", 10101)
	l.mu.Unlock()
	if err != nil {
		t.Fatalf("writeContainerExtensions: %v", err)
	}

	got, found := readExtValue(t, dir, "app1.apps.privasys.org", depOID61)
	if !found {
		t.Fatal("OID 7.1 missing from the extensions file")
	}
	if want := ratls.EncodeDependencySet(*set); !bytes.Equal(got, want) {
		t.Fatalf("7.1 value != canonical SDK encoding:\n got %x\nwant %x", got, want)
	}
}

// TestWriteContainerExtensionsOmits61WhenNoDeps: no declared set → no 7.1
// extension (absence, not an empty value).
func TestWriteContainerExtensionsOmits61WhenNoDeps(t *testing.T) {
	dir := t.TempDir()
	l := depTestLauncher(t, dir, nil)

	l.mu.Lock()
	err := l.writeContainerExtensions("app1", "app1.apps.privasys.org", 10101)
	l.mu.Unlock()
	if err != nil {
		t.Fatalf("writeContainerExtensions: %v", err)
	}
	if _, found := readExtValue(t, dir, "app1.apps.privasys.org", depOID61); found {
		t.Fatal("OID 7.1 present with no declared dependencies")
	}
}

// TestSetDependenciesReMintsInPlace: installing a set on a running container
// rewrites the extensions file (the live re-mint), and clearing it with an
// explicit empty set removes the extension and nils the stored set.
func TestSetDependenciesReMintsInPlace(t *testing.T) {
	dir := t.TempDir()
	l := depTestLauncher(t, dir, nil)

	set := depTestSet()
	encoded, err := l.SetDependencies("app1", set)
	if err != nil {
		t.Fatalf("SetDependencies: %v", err)
	}
	if want := ratls.EncodeDependencySet(*set); !bytes.Equal(encoded, want) {
		t.Fatalf("returned encoding mismatch")
	}
	got, found := readExtValue(t, dir, "app1.apps.privasys.org", depOID61)
	if !found || !bytes.Equal(got, encoded) {
		t.Fatalf("re-minted file missing/mismatched 7.1 (found=%v)", found)
	}
	stored, err := l.GetDependencies("app1")
	if err != nil || stored == nil || len(stored.Entries) != 1 {
		t.Fatalf("GetDependencies after install: %+v err=%v", stored, err)
	}

	// Explicit clear: empty entries → extension gone, stored set nil.
	cleared, err := l.SetDependencies("app1", &ratls.DependencySet{})
	if err != nil {
		t.Fatalf("SetDependencies(clear): %v", err)
	}
	if cleared != nil {
		t.Fatalf("clear should return nil encoding, got %x", cleared)
	}
	if _, found := readExtValue(t, dir, "app1.apps.privasys.org", depOID61); found {
		t.Fatal("OID 7.1 still present after explicit clear")
	}
	stored, err = l.GetDependencies("app1")
	if err != nil || stored != nil {
		t.Fatalf("GetDependencies after clear: %+v err=%v", stored, err)
	}
}

// TestSetDependenciesUnknownContainer fails closed.
func TestSetDependenciesUnknownContainer(t *testing.T) {
	l := depTestLauncher(t, t.TempDir(), nil)
	if _, err := l.SetDependencies("ghost", depTestSet()); err == nil {
		t.Fatal("expected error for unknown container")
	}
}
