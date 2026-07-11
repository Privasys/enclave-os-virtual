package bootstrap

// Vault-backed /data DEK resolution (`manager-bootstrap dek`, run by
// luks-setup BEFORE data.mount).
//
// The DEK never exists outside TEE memory: it lives as k-of-n Shamir shares
// on the vault constellation, exactly like container volume keys — this is
// the same internal/vaultkey code path the launcher uses, with the manager's
// own attested identity (OID 3.6 = enclave id) in place of an app's.
//
// Boot discrimination, in order:
//  1. The volume is LUKS and carries our LUKS2 header locator token
//     (privasys-vault, token id 7): reconstruct. The locator is non-secret
//     addressing (handle + constellation + mgmt URL + enclave id) that
//     travels WITH the disk, so a /data PD survives metadata edits and
//     machine moves. The attestation bearer comes from the
//     quote-authenticated boot-attestation-token endpoint.
//  2. The volume is not LUKS yet and a bootstrap token is present: first
//     boot of a pre-approved enclave. Redeem, create the DEK on the
//     constellation (grant from the redeem payload), stash the payload for
//     the post-mount persist, and emit the locator for luks-setup to import
//     into the header after luksFormat.
//  3. Neither: not vault-managed (legacy BYOK volume) — ErrNotVaultManaged,
//     luks-setup falls back to the metadata passphrase.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/vaultkey"
)

// ErrNotVaultManaged signals luks-setup to fall back to the BYOK path.
var ErrNotVaultManaged = errors.New("volume is not vault-managed")

// luksTokenID is the fixed LUKS2 header token slot for the locator (clear of
// slot 0 conventions used by systemd-cryptenroll and friends).
const luksTokenID = "7"

// LuksTokenPath is where the first-boot path writes the locator JSON for
// luks-setup to import into the LUKS2 header right after luksFormat.
const LuksTokenPath = "/run/enclave/luks-token.json"

// dekOriginPath / keySourcePath mirror luks-setup's BYOK outputs (the
// manager attests the DEK origin at OID 2.6).
const (
	dekOriginPath = "/run/luks/dek-origin"
	keySourcePath = "/run/luks/key-source"
)

// vaultLocator is the non-secret LUKS2 header token addressing the DEK.
// "type" and "keyslots" are the fields cryptsetup requires of any token.
type vaultLocator struct {
	Type              string   `json:"type"`
	Keyslots          []string `json:"keyslots"`
	Handle            string   `json:"handle"`
	Endpoints         []string `json:"endpoints"`
	Mrenclave         string   `json:"mrenclave"`
	AttestationServer string   `json:"attestation_server"`
	Threshold         int      `json:"threshold"`
	MgmtURL           string   `json:"mgmt_url"`
	EnclaveID         string   `json:"enclave_id"`
}

// ResolveDataDEK returns the hex LUKS passphrase for the /data volume on
// device. ErrNotVaultManaged means BYOK fallback; any other error must fail
// the boot (never format or open with a guessed key).
func ResolveDataDEK(ctx context.Context, log *zap.Logger, cfg Config, device string) (string, error) {
	cfg = applyDefaults(cfg)

	if isLuks(ctx, device) {
		locator, err := exportLocator(ctx, device)
		if err != nil {
			if BootstrapToken() != "" {
				// A formatted volume with no locator but a bootstrap token in
				// metadata: NEVER redeem here — the single-use token would be
				// consumed without keying this volume. Likely a BYOK-era disk
				// on a re-provisioned VM.
				fmt.Fprintf(os.Stderr, "manager-bootstrap: volume %s is LUKS without a vault locator; ignoring bootstrap-token (BYOK fallback)\n", device)
			}
			return "", ErrNotVaultManaged
		}
		return reconstructDEK(ctx, log, cfg, locator)
	}

	token := BootstrapToken()
	if token == "" {
		return "", ErrNotVaultManaged
	}
	return firstBootDEK(ctx, log, cfg, token)
}

// reconstructDEK rebuilds the DEK from the constellation on a reboot.
// Retries: this is boot-critical and both mgmt (bearer) and the vaults are
// remote; transient unavailability must not fail an otherwise healthy boot.
func reconstructDEK(ctx context.Context, log *zap.Logger, cfg Config, loc *vaultLocator) (string, error) {
	appID, err := enclaveIDBytes(loc.EnclaveID)
	if err != nil {
		return "", err
	}
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(10 * time.Second):
			}
		}
		bearer, err := FetchBootAttestationToken(ctx, cfg, loc.MgmtURL, loc.EnclaveID)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "manager-bootstrap: boot bearer: %v (retrying)\n", err)
			continue
		}
		dek, origin, reconstructed, err := vaultkey.ResolveOrProvision(ctx, log, vaultkey.Config{
			Endpoints:            loc.Endpoints,
			Threshold:            loc.Threshold,
			MrenclaveHex:         loc.Mrenclave,
			AttestationServerURL: loc.AttestationServer,
			AttestationToken:     bearer,
		}, loc.Handle, "" /* reconstruct only: no grant */, nil, appID)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "manager-bootstrap: DEK reconstruction: %v (retrying)\n", err)
			continue
		}
		if !reconstructed {
			// Cannot happen without a grant, but the invariant matters: a
			// formatted volume must never see a freshly generated DEK.
			return "", errors.New("dek: constellation returned a new key for an existing volume")
		}
		if err := writeOrigin(origin); err != nil {
			return "", err
		}
		return dek, nil
	}
	return "", fmt.Errorf("dek: giving up after retries: %w", lastErr)
}

// firstBootDEK redeems the pre-approval and creates the DEK on the
// constellation. Only ever called on a NOT-yet-LUKS device, so a fresh DEK
// is correct; ResolveOrProvision guarantees k vaults hold shares before
// returning it.
func firstBootDEK(ctx context.Context, log *zap.Logger, cfg Config, token string) (string, error) {
	payload, err := Redeem(ctx, cfg, token)
	if err != nil {
		return "", err
	}
	if payload.DataKey == nil {
		return "", errors.New("dek: redeem payload carries no data_key bundle (the platform could not mint the manager data-key grant — re-run pre-approval)")
	}
	appID, err := enclaveIDBytes(payload.EnclaveID)
	if err != nil {
		return "", err
	}
	dk := payload.DataKey
	dek, origin, _, err := vaultkey.ResolveOrProvision(ctx, log, vaultkey.Config{
		Endpoints:            dk.Endpoints,
		Threshold:            dk.Threshold,
		MrenclaveHex:         dk.Mrenclave,
		AttestationServerURL: dk.AttestationServer,
		AttestationToken:     payload.AttestationToken,
	}, dk.Handle, dk.Grant, nil, appID)
	if err != nil {
		return "", fmt.Errorf("dek: provision: %w", err)
	}

	// Park the registration payload for the post-mount persist run, and the
	// locator for luks-setup to import into the LUKS2 header after format.
	if err := StashRedeemed(payload); err != nil {
		return "", fmt.Errorf("dek: stash redeem payload: %w", err)
	}
	mgmtURL := payload.ManagerEnv["MGMT_URL"]
	if mgmtURL == "" {
		mgmtURL = cfg.ManagementURL
	}
	locator, _ := json.Marshal(vaultLocator{
		Type:              "privasys-vault",
		Keyslots:          []string{},
		Handle:            dk.Handle,
		Endpoints:         dk.Endpoints,
		Mrenclave:         dk.Mrenclave,
		AttestationServer: dk.AttestationServer,
		Threshold:         dk.Threshold,
		MgmtURL:           mgmtURL,
		EnclaveID:         payload.EnclaveID,
	})
	if err := os.MkdirAll(filepath.Dir(LuksTokenPath), 0o700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(LuksTokenPath, locator, 0o600); err != nil {
		return "", fmt.Errorf("dek: write locator: %w", err)
	}
	if err := writeOrigin(origin); err != nil {
		return "", err
	}
	return dek, nil
}

func writeOrigin(origin string) error {
	if err := os.MkdirAll(filepath.Dir(dekOriginPath), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(dekOriginPath, []byte(origin+"\n"), 0o644); err != nil {
		return err
	}
	return writeFileAtomic(keySourcePath, []byte("vault\n"), 0o644)
}

// enclaveIDBytes converts the enclave UUID into the 16 raw bytes stamped at
// OID 3.6 of the manager's vault client identity (same encoding as an app id).
func enclaveIDBytes(id string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("dek: bad enclave id %q", id)
	}
	return b, nil
}

func isLuks(ctx context.Context, device string) bool {
	return exec.CommandContext(ctx, "cryptsetup", "isLuks", device).Run() == nil
}

// exportLocator reads the privasys-vault locator token from the LUKS2 header.
func exportLocator(ctx context.Context, device string) (*vaultLocator, error) {
	out, err := exec.CommandContext(ctx, "cryptsetup", "token", "export", "--token-id", luksTokenID, device).Output()
	if err != nil {
		return nil, fmt.Errorf("no locator token: %w", err)
	}
	var loc vaultLocator
	if err := json.Unmarshal(out, &loc); err != nil {
		return nil, fmt.Errorf("locator token unreadable: %w", err)
	}
	if loc.Type != "privasys-vault" || loc.Handle == "" || len(loc.Endpoints) == 0 ||
		loc.MgmtURL == "" || loc.EnclaveID == "" {
		return nil, errors.New("locator token incomplete")
	}
	return &loc, nil
}
