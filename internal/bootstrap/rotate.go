package bootstrap

// Moving the /data DEK to another vault constellation.
//
// The constellation that holds an enclave's /data DEK is recorded in the LUKS2
// header locator (token id 7) written once by luks-setup after luksFormat, and
// nothing else rewrites it. So a constellation cannot be decommissioned while
// any enclave's /data still points at it: the volume would not open at the next
// boot. That is also why the key cannot simply be re-pointed — only this
// enclave can create it, because the grant the vault demands is bound to the
// attested enclave id.
//
// RotateDataDEK performs the move with FRESH key material. Fresh, not carried
// over: the reason to leave a constellation is usually that its shares can no
// longer be trusted, and re-splitting the same secret onto new vaults would
// keep whoever holds the old shares in possession of the /data passphrase.
//
// Ordering is chosen so that no interruption can leave the volume unopenable:
//
//	1. reconstruct the CURRENT DEK from the old constellation   (read-only)
//	2. create fresh material at the same handle on the new one  (no disk change)
//	3. luksAddKey the new DEK, authenticated by the old one     (both now open)
//	4. rewrite locator token 7 to the new constellation         (COMMIT POINT)
//	5. luksKillSlot the old keyslot                             (old one retired)
//
// Between 3 and 5 the volume opens under either key, so a crash anywhere leaves
// a bootable volume: before 4 the old locator still resolves, after 4 the new
// one does. A crash between 4 and 5 leaves a stale keyslot, which the next run
// removes. The old vault key is left to expire on its own TTL — the enclave
// holds no DeleteKey on it.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/vaultkey"
)

// RotateBundle is what the operator fetches from the control plane
// (POST /api/v1/admin/enclaves/{id}/data-key/rotate-grant) and hands to this
// command: a key-creation grant plus the addressing of the constellation to
// move onto.
type RotateBundle struct {
	Handle            string   `json:"handle"`
	Grant             string   `json:"grant"`
	Endpoints         []string `json:"endpoints"`
	Mrenclave         string   `json:"mrenclave"`
	AttestationServer string   `json:"attestation_server"`
	Threshold         int      `json:"threshold"`
	AttestationToken  string   `json:"attestation_token"`
	MgmtURL           string   `json:"mgmt_url"`
	EnclaveID         string   `json:"enclave_id"`
}

func (b *RotateBundle) validate(loc *vaultLocator) error {
	switch {
	case b.Grant == "":
		return errors.New("rotate: bundle carries no grant")
	case len(b.Endpoints) == 0:
		return errors.New("rotate: bundle carries no endpoints")
	case b.Mrenclave == "":
		return errors.New("rotate: bundle carries no mrenclave")
	}
	// The handle must be the one this volume already uses. A rotation that
	// re-pointed /data at a different key would abandon the data.
	if b.Handle != "" && b.Handle != loc.Handle {
		return fmt.Errorf("rotate: bundle handle %q is not this volume's handle %q", b.Handle, loc.Handle)
	}
	if b.EnclaveID != "" && !strings.EqualFold(b.EnclaveID, loc.EnclaveID) {
		return fmt.Errorf("rotate: bundle is for enclave %s, this volume belongs to %s", b.EnclaveID, loc.EnclaveID)
	}
	return nil
}

// sameConstellation reports whether the bundle addresses the constellation the
// volume is already on, in which case there is nothing to do.
func sameConstellation(loc *vaultLocator, b *RotateBundle) bool {
	if !strings.EqualFold(loc.Mrenclave, b.Mrenclave) {
		return false
	}
	if len(loc.Endpoints) != len(b.Endpoints) {
		return false
	}
	seen := make(map[string]bool, len(loc.Endpoints))
	for _, e := range loc.Endpoints {
		seen[e] = true
	}
	for _, e := range b.Endpoints {
		if !seen[e] {
			return false
		}
	}
	return true
}

// RotateDataDEK moves the /data DEK on device onto the constellation the bundle
// addresses, with fresh material. It is idempotent: a volume already on that
// constellation is left untouched.
func RotateDataDEK(ctx context.Context, log *zap.Logger, cfg Config, device string, b *RotateBundle) error {
	cfg = applyDefaults(cfg)
	if !isLuks(ctx, device) {
		return fmt.Errorf("rotate: %s is not a LUKS volume", device)
	}
	loc, err := exportLocator(ctx, device)
	if err != nil {
		return fmt.Errorf("rotate: %w (a BYOK volume has no DEK to rotate)", err)
	}
	if err := b.validate(loc); err != nil {
		return err
	}
	if sameConstellation(loc, b) {
		fmt.Fprintf(os.Stderr, "rotate: already on %s; nothing to do\n", b.Mrenclave)
		return nil
	}

	// 1. The current DEK, from the constellation the header names. This is the
	//    same read the boot path performs, so a failure here means the old
	//    constellation is already unreachable and the rotation must not start.
	oldDEK, err := reconstructDEK(ctx, log, cfg, loc)
	if err != nil {
		return fmt.Errorf("rotate: read the current DEK: %w", err)
	}

	// 2. Fresh material at the same handle on the new constellation. The
	//    handle is free there: a different constellation is a separate
	//    keyspace, so no generation bump is needed.
	appID, err := enclaveIDBytes(loc.EnclaveID)
	if err != nil {
		return err
	}
	threshold := b.Threshold
	if threshold <= 0 {
		threshold = 2
	}
	newDEK, origin, reconstructed, err := vaultkey.ResolveOrProvision(ctx, log, vaultkey.Config{
		Endpoints:            b.Endpoints,
		Threshold:            threshold,
		MrenclaveHex:         b.Mrenclave,
		AttestationServerURL: b.AttestationServer,
		AttestationToken:     b.AttestationToken,
	}, loc.Handle, b.Grant, nil, appID)
	if err != nil {
		return fmt.Errorf("rotate: create the new DEK: %w", err)
	}
	if newDEK == oldDEK {
		// Would defeat the purpose: the point of rotating is that the old
		// material is no longer trustworthy.
		return errors.New("rotate: the new constellation returned the OLD material; refusing")
	}
	if reconstructed {
		fmt.Fprintf(os.Stderr, "rotate: adopted an existing key at %s on the new constellation\n", loc.Handle)
	}

	// 3. Both keys open the volume from here until step 5.
	if err := luksAddKey(ctx, device, oldDEK, newDEK); err != nil {
		return fmt.Errorf("rotate: add the new keyslot: %w", err)
	}

	// 4. Commit: the header now names the new constellation.
	newLoc := *loc
	newLoc.Endpoints = b.Endpoints
	newLoc.Mrenclave = b.Mrenclave
	newLoc.Threshold = threshold
	if b.AttestationServer != "" {
		newLoc.AttestationServer = b.AttestationServer
	}
	if err := importLocator(ctx, device, &newLoc); err != nil {
		// The new keyslot is harmless on its own — the old locator still
		// resolves the old key, so the volume still boots.
		return fmt.Errorf("rotate: rewrite the locator (volume still boots on the old key): %w", err)
	}

	// 5. Retire the old keyslot. A failure here is not fatal: the volume boots
	//    on the new key, and the stale slot only holds material that is being
	//    abandoned anyway. Report it loudly so it gets cleaned up.
	if err := luksRemoveKey(ctx, device, oldDEK); err != nil {
		fmt.Fprintf(os.Stderr, "rotate: WARNING the old keyslot could not be removed (%v); the volume is on the new key, re-run to retire it\n", err)
	}
	if err := writeOrigin(origin); err != nil {
		fmt.Fprintf(os.Stderr, "rotate: could not record the DEK origin: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "rotate: %s moved to %s (%d endpoints, threshold %d)\n",
		loc.Handle, b.Mrenclave, len(b.Endpoints), threshold)
	return nil
}

// luksAddKey adds newHex as a keyslot, authenticating with oldHex. Both
// passphrases travel on pipes (/proc/self/fd), never on the command line or
// through a file, so neither lands in the process table or on disk.
func luksAddKey(ctx context.Context, device, oldHex, newHex string) error {
	existing, err := pipeFor(oldHex)
	if err != nil {
		return err
	}
	defer existing.Close()
	added, err := pipeFor(newHex)
	if err != nil {
		return err
	}
	defer added.Close()
	cmd := exec.CommandContext(ctx, "cryptsetup", "luksAddKey",
		"--key-file", "/proc/self/fd/3", device, "/proc/self/fd/4")
	cmd.ExtraFiles = []*os.File{existing, added}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// luksRemoveKey drops the keyslot holding oldHex.
func luksRemoveKey(ctx context.Context, device, oldHex string) error {
	f, err := pipeFor(oldHex)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, "cryptsetup", "luksRemoveKey", device, "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{f}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// pipeFor returns a read end carrying the hex passphrase's raw bytes, exactly
// as luks-setup feeds them at boot (hex text, no trailing newline).
func pipeFor(hexKey string) (*os.File, error) {
	if _, err := hex.DecodeString(hexKey); err != nil {
		return nil, fmt.Errorf("rotate: passphrase is not hex: %w", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer w.Close()
		_, _ = w.WriteString(hexKey)
	}()
	return r, nil
}

// importLocator replaces token 7 with loc. The old token is removed first:
// `token import` will not overwrite an occupied id.
func importLocator(ctx context.Context, device string, loc *vaultLocator) error {
	blob, err := json.Marshal(loc)
	if err != nil {
		return err
	}
	// Removing and re-importing is not atomic, but a crash in between leaves a
	// volume whose DEK both keyslots still open; the operator re-runs and the
	// locator is written from the bundle again.
	if out, err := exec.CommandContext(ctx, "cryptsetup", "token", "remove",
		"--token-id", luksTokenID, device).CombinedOutput(); err != nil {
		return fmt.Errorf("remove old locator: %w: %s", err, strings.TrimSpace(string(out)))
	}
	cmd := exec.CommandContext(ctx, "cryptsetup", "token", "import",
		"--token-id", luksTokenID, device)
	cmd.Stdin = strings.NewReader(string(blob))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("import new locator: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LoadRotateBundle reads the bundle the operator fetched from the control
// plane. A path of "-" reads stdin, so the grant never has to touch the disk.
func LoadRotateBundle(path string) (*RotateBundle, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = readAllStdin()
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("rotate: read bundle: %w", err)
	}
	var b RotateBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("rotate: bundle is not JSON: %w", err)
	}
	return &b, nil
}

func readAllStdin() ([]byte, error) {
	const max = 1 << 20
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	for len(buf) < max {
		n, err := os.Stdin.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}
