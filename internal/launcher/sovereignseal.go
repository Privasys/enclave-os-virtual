package launcher

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Version-bound sovereign sealing keys (the sovereign-data framework,
// Phase 1, TDX half). An app flags data as user-owned and keeps each data
// owner's wallet-delivered key element W sealed under S_N, a key only the
// currently-running app VERSION can obtain:
//
//	branch = HKDF(volume DEK, salt="privasys-sovereign-seal/v1", info="branch")
//	S_N    = HKDF(branch,     salt=nil, info="privasys-sovereign-seal/v1|<hex image digest>")
//
// The manager is the in-TD custodian of the volume DEK, so it enforces the
// version separation: it derives S_N ONLY for the image digest it is
// currently running for that container (the digest it attests at OID 3.2).
// v{N+1} asks and receives S_{N+1}; it has no path to S_N, so the kept W is
// unreadable to upgraded code until the data owner's wallet re-delivers it —
// an app upgrade is a consent boundary. The branch is one-way from the DEK
// (serving S_N can never reveal the DEK), and it is derived at Load while
// the DEK is briefly in hand, so serving S_N needs no vault round-trip.
//
// sovereignSealInfo is wire format for every blob sealed under an S_N:
// changing it (or the derivation shape above) orphans all such blobs.
const sovereignSealInfo = "privasys-sovereign-seal/v1"

// deriveSovereignBranch derives the per-app sealing branch from the volume
// DEK as resolved at Load (the hex string ResolveOrProvision returns; a
// non-hex BYOK key is used raw). Returns nil only on an empty key.
func deriveSovereignBranch(keyHex string) []byte {
	if keyHex == "" {
		return nil
	}
	secret, err := hex.DecodeString(keyHex)
	if err != nil || len(secret) == 0 {
		secret = []byte(keyHex)
	}
	branch, err := hkdf.Key(sha256.New, secret, []byte(sovereignSealInfo), "branch", 32)
	if err != nil {
		// Only reachable on an invalid length/hash; fail closed.
		return nil
	}
	return branch
}

// SovereignSealKey derives the named container's CURRENT version-bound
// sovereign sealing key S_N and returns it with the image digest it is
// bound to. Fails closed for a container the launcher is not running or
// one without a vault-backed encrypted volume (an ephemeral DEK would make
// S_N die with the VM, so it is refused rather than served misleadingly).
func (l *Launcher) SovereignSealKey(name string) (key, imageDigest []byte, err error) {
	l.mu.RLock()
	branch := l.sovereignBranches[name]
	digest := l.imageDigests[name]
	l.mu.RUnlock()
	if len(digest) == 0 {
		return nil, nil, fmt.Errorf("launcher: unknown container %q", name)
	}
	if len(branch) == 0 {
		return nil, nil, fmt.Errorf("launcher: container %q has no vault-backed encrypted volume; sovereign sealing requires one", name)
	}
	k, err := hkdf.Key(sha256.New, branch, nil, sovereignSealInfo+"|"+hex.EncodeToString(digest), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("launcher: derive sovereign seal key: %w", err)
	}
	return k, digest, nil
}
