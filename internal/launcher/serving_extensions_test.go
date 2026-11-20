package launcher

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A change to what the leaf attests after load (here the volume key moving to
// a new generation) reaches a direct adopter name too: its extensions stay
// identical to the platform hostname's, so a client attesting either name
// sees the same workload.
func TestServingExtensionsCoverDirectNames(t *testing.T) {
	dir := t.TempDir()
	l := depTestLauncher(t, dir, nil)
	const host, direct = "app1.apps.privasys.org", "app1.example.org"
	l.directDomains = map[string][]string{"app1": {direct}}

	l.mu.Lock()
	l.volumeEncryption["app1"] = "vault:apps.privasys.org/app1/storage-kek/v5"
	err := l.writeServingExtensions("app1")
	l.volumeEncryption["app1"] = "vault:apps.privasys.org/app1/storage-kek/v6"
	if err == nil {
		err = l.writeServingExtensions("app1")
	}
	l.mu.Unlock()
	if err != nil {
		t.Fatalf("writeServingExtensions: %v", err)
	}

	onHost, err := os.ReadFile(filepath.Join(dir, host+".json"))
	if err != nil {
		t.Fatal(err)
	}
	onDirect, err := os.ReadFile(filepath.Join(dir, direct+".json"))
	if err != nil {
		t.Fatalf("direct name has no extensions file: %v", err)
	}
	if !bytes.Equal(onHost, onDirect) {
		t.Fatalf("direct name's extensions differ from the hostname's:\nhost   %s\ndirect %s", onHost, onDirect)
	}
	got, ok := readExtValue(t, dir, direct, "1.3.6.1.4.1.65230.6.1")
	if !ok || string(got) != "vault:apps.privasys.org/app1/storage-kek/v6" {
		t.Fatalf("direct name's key source = %q, want the v6 generation", got)
	}
}

type digestRouter struct {
	recordingRouter
	digests map[string][32]byte
}

func (r *digestRouter) SetExpectedWorkloadDigest(host string, d [32]byte) { r.digests[host] = d }

// A volume key moving to a new generation in place re-arms the voucher
// digest with the new key source, so the wallet's next sign-in matches.
func TestRearmWorkloadDigestFollowsKeySource(t *testing.T) {
	l := depTestLauncher(t, t.TempDir(), nil)
	r := &digestRouter{digests: map[string][32]byte{}}
	l.appHostRouter = r
	const host = "app1.apps.privasys.org"

	l.mu.Lock()
	l.volumeEncryption["app1"] = "vault:apps.privasys.org/app1/storage-kek/v1"
	l.armSessionRelayWorkloadDigest("app1", host)
	before := r.digests[host]
	l.volumeEncryption["app1"] = "vault:apps.privasys.org/app1/storage-kek/v2"
	l.rearmWorkloadDigest("app1")
	after := r.digests[host]
	l.armSessionRelayWorkloadDigest("app1", host) // what a fresh Load arms
	l.mu.Unlock()

	if after == before {
		t.Fatal("digest not re-armed after the key source changed")
	}
	if after != r.digests[host] {
		t.Fatal("re-armed digest differs from what a fresh load arms")
	}
}
