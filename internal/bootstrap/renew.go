package bootstrap

// Renewing the /data DEK before the vaults' fixed 90-day expiry.
//
// A vault key's expiry is set at creation and cannot be extended, so the only
// way to keep /data openable past day 90 is to create the SAME key again under
// the next handle generation (…/manager/data/v1 → v2) and point the LUKS2
// header locator at it. Unlike a rotation, nothing about the disk changes: the
// keyslot holds the same passphrase, so there is no window where the volume
// opens under one key only. The new generation may live on another
// constellation (the active one), which is how an enclave leaves a retiring
// constellation without the owner.
//
// The header locator is the one thing that moves. It is replaced through a
// spare token id so that no crash can leave the header without a locator:
// the new locator is imported at luksSpareTokenID first, then token 7 is
// replaced, then the spare is removed, and exportLocator falls back to the
// spare when token 7 is missing.

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/vaultkey"
)

// luksSpareTokenID holds a locator only while the header's is being replaced.
const luksSpareTokenID = "8"

// nextGeneration returns handle with its trailing /v<N> bumped to /v<N+1>.
func nextGeneration(handle string) (string, error) {
	i := strings.LastIndex(handle, "/v")
	if i < 0 {
		return "", fmt.Errorf("handle %q has no /v<N> generation", handle)
	}
	n, err := strconv.Atoi(handle[i+2:])
	if err != nil || n < 1 {
		return "", fmt.Errorf("handle %q has no /v<N> generation", handle)
	}
	return handle[:i] + "/v" + strconv.Itoa(n+1), nil
}

// RenewDataDEK re-creates the /data DEK on device under the bundle's handle
// (the next generation of the one in the header), with the same material, on
// the constellation the bundle addresses, then points the header at it.
// Idempotent: a header already on the bundle's handle is left alone. Returns
// the handles before and after.
func RenewDataDEK(ctx context.Context, log *zap.Logger, cfg Config, device string, b *RotateBundle) (string, string, error) {
	cfg = applyDefaults(cfg)
	if !isLuks(ctx, device) {
		return "", "", fmt.Errorf("renew: %s is not a LUKS volume", device)
	}
	loc, err := exportLocator(ctx, device)
	if err != nil {
		return "", "", fmt.Errorf("renew: %w (a BYOK volume has no vault key to renew)", err)
	}
	switch {
	case b.Grant == "":
		return "", "", errors.New("renew: bundle carries no grant")
	case len(b.Endpoints) == 0 || b.Mrenclave == "":
		return "", "", errors.New("renew: bundle carries no constellation")
	case b.EnclaveID != "" && !strings.EqualFold(b.EnclaveID, loc.EnclaveID):
		return "", "", fmt.Errorf("renew: bundle is for enclave %s, this volume belongs to %s", b.EnclaveID, loc.EnclaveID)
	}
	if b.Handle == loc.Handle {
		return loc.Handle, loc.Handle, nil // already renewed
	}
	next, err := nextGeneration(loc.Handle)
	if err != nil {
		return "", "", fmt.Errorf("renew: %w", err)
	}
	if b.Handle != next {
		return "", "", fmt.Errorf("renew: bundle handle %q is not the next generation of %q", b.Handle, loc.Handle)
	}

	oldHex, err := reconstructDEK(ctx, log, cfg, loc)
	if err != nil {
		return "", "", fmt.Errorf("renew: read the current DEK: %w", err)
	}
	oldDEK, err := hex.DecodeString(oldHex)
	if err != nil {
		return "", "", fmt.Errorf("renew: %w", err)
	}
	appID, err := enclaveIDBytes(loc.EnclaveID)
	if err != nil {
		return "", "", err
	}
	threshold := b.Threshold
	if threshold <= 0 {
		threshold = 2
	}
	// A retried renew finds the new handle created already: it must hold the
	// same key, which the comparison below checks either way.
	newHex, origin, _, err := vaultkey.ResolveOrProvision(ctx, log, vaultkey.Config{
		Endpoints:            b.Endpoints,
		Threshold:            threshold,
		MrenclaveHex:         b.Mrenclave,
		AttestationServerURL: b.AttestationServer,
		AttestationToken:     b.AttestationToken,
		Material:             oldDEK,
	}, b.Handle, b.Grant, nil, appID)
	if err != nil {
		return "", "", fmt.Errorf("renew: create the new generation: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(newHex), []byte(oldHex)) != 1 {
		return "", "", fmt.Errorf("renew: %s holds a different key than %s; header left on the old handle", b.Handle, loc.Handle)
	}

	newLoc := *loc
	newLoc.Handle, newLoc.Endpoints, newLoc.Mrenclave, newLoc.Threshold = b.Handle, b.Endpoints, b.Mrenclave, threshold
	if b.AttestationServer != "" {
		newLoc.AttestationServer = b.AttestationServer
	}
	if err := replaceLocator(ctx, device, &newLoc); err != nil {
		return "", "", fmt.Errorf("renew: point the header at %s (the old handle still opens the volume): %w", b.Handle, err)
	}
	if err := writeOrigin(origin); err != nil {
		log.Warn("renew: could not record the DEK origin", zap.Error(err))
	}
	log.Info("data key renewed", zap.String("from", loc.Handle), zap.String("to", b.Handle), zap.String("mrenclave", b.Mrenclave))
	return loc.Handle, b.Handle, nil
}

// replaceLocator swaps the header's locator for loc without ever leaving the
// header with none: spare first, then token 7, then the spare goes.
func replaceLocator(ctx context.Context, device string, loc *vaultLocator) error {
	blob, err := json.Marshal(loc)
	if err != nil {
		return err
	}
	_ = exec.CommandContext(ctx, "cryptsetup", "token", "remove", "--token-id", luksSpareTokenID, device).Run()
	if err := tokenImport(ctx, device, luksSpareTokenID, blob); err != nil {
		return fmt.Errorf("stage the new locator: %w", err)
	}
	if out, err := exec.CommandContext(ctx, "cryptsetup", "token", "remove", "--token-id", luksTokenID, device).CombinedOutput(); err != nil {
		return fmt.Errorf("remove the old locator: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if err := tokenImport(ctx, device, luksTokenID, blob); err != nil {
		return fmt.Errorf("import the new locator (the spare token still holds it): %w", err)
	}
	_ = exec.CommandContext(ctx, "cryptsetup", "token", "remove", "--token-id", luksSpareTokenID, device).Run()
	return nil
}

func tokenImport(ctx context.Context, device, id string, blob []byte) error {
	cmd := exec.CommandContext(ctx, "cryptsetup", "token", "import", "--token-id", id, device)
	cmd.Stdin = strings.NewReader(string(blob))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
