// Package vaultkey resolves per-container volume keys from the Enclave
// Vaults constellation (enclave-upgrade plan, Phase B).
//
// The DEK for a container's LUKS volume never exists outside TEE
// memory: it is either reconstructed from k-of-n Shamir shares held by
// the vault constellation, or — on the very first boot of a freshly
// reserved key handle — generated here and pushed to the constellation
// as shares via the one-shot ProvideMaterial fill (two-phase create,
// vault-v0.20.x). The platform only ever supplies the handle and the
// constellation endpoints; it never sees key material.
//
// # Share payload format
//
// ProvideMaterial is one-shot per vault, so a partially failed fill
// followed by a retry would leave vaults holding shares of DIFFERENT
// DEK generations — and Shamir reconstruction over mixed generations
// yields garbage silently. Each vault's share payload is therefore
// prefixed with a random 16-byte generation id:
//
//	payload = generation(16) || X(1) || data(len(secret))
//
// Reconstruction groups shares by generation and uses the largest
// group that meets the threshold.
package vaultkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	ratls "enclave-os-mini/clients/go/ratls"
	vault "github.com/Privasys/enclave-vaults-client/go/vault"
	"go.uber.org/zap"
)

// generationSize is the length of the generation-id prefix on each
// share payload.
const generationSize = 16

// dekSize is the volume DEK length in bytes (LUKS passphrase = hex of it).
const dekSize = 32

// Config addresses the vault constellation. Supplied per LoadRequest by
// the platform; none of it is secret or trusted (each vault is verified
// by attestation at dial time).
type Config struct {
	// Endpoints is the constellation, "host:port" each.
	Endpoints []string
	// Threshold is the Shamir k (any k of len(Endpoints) shares
	// reconstruct). Zero means 2.
	Threshold int
	// MrenclaveHex pins the vault enclave build (64 hex chars).
	MrenclaveHex string
	// AttestationServerURL is the quote-verification endpoint used to
	// verify each vault's quote (e.g. "https://as.privasys.org/verify").
	AttestationServerURL string
	// MgmtURL, EnclaveID and EnclaveToken let the manager fetch a
	// short-lived OIDC bearer for the attestation-server quote
	// verification (the manager has no OIDC key of its own; the platform
	// mints the token on demand, authenticated by the per-enclave
	// credential). All come from the manager's env (MGMT_URL, ENCLAVE_ID,
	// ENCLAVE_TOKEN), delivered at approval.
	MgmtURL      string
	EnclaveID    string
	EnclaveToken string
}

func (c Config) threshold() int {
	if c.Threshold <= 0 {
		return 2
	}
	return c.Threshold
}

func (c Config) validate() error {
	if len(c.Endpoints) == 0 {
		return errors.New("vaultkey: no vault endpoints configured")
	}
	if c.threshold() > len(c.Endpoints) {
		return fmt.Errorf("vaultkey: threshold %d exceeds %d endpoints", c.threshold(), len(c.Endpoints))
	}
	if _, err := hex.DecodeString(c.MrenclaveHex); err != nil || len(c.MrenclaveHex) != 64 {
		return fmt.Errorf("vaultkey: vault_mrenclave must be 64 hex chars")
	}
	if c.AttestationServerURL == "" {
		return errors.New("vaultkey: attestation server URL is required")
	}
	if c.MgmtURL == "" || c.EnclaveID == "" || c.EnclaveToken == "" {
		return errors.New("vaultkey: MgmtURL, EnclaveID and EnclaveToken are required (to fetch the attestation-server token)")
	}
	return nil
}

// fetchAttestationToken gets a short-lived OIDC bearer from the
// management service (authed by the per-enclave credential) for the
// attestation-server quote verification. The credential auth resolves
// the enclave row from the enclave_id in the body.
func fetchAttestationToken(ctx context.Context, cfg Config) (string, error) {
	url := strings.TrimRight(cfg.MgmtURL, "/") + "/api/v1/enclave/attestation-token"
	reqBody, _ := json.Marshal(map[string]string{"enclave_id": cfg.EnclaveID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(reqBody)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.EnclaveToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("attestation-token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("attestation-token: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("attestation-token: bad response")
	}
	return out.Token, nil
}

// dialOptions builds the per-vault dial options: pin the vault
// MRENCLAVE, verify its quote at the attestation server, and present a
// freshly minted challenge-bound client identity carrying the
// container's image digest (OID 3.2) so the vault's Principal::Tee
// profile matches.
func dialOptions(cfg Config, imageDigest []byte, attToken string) (vault.DialOptions, error) {
	mre, err := hex.DecodeString(cfg.MrenclaveHex)
	if err != nil {
		return vault.DialOptions{}, fmt.Errorf("vaultkey: bad mrenclave hex: %w", err)
	}
	certFn, err := clientCertificateFn(imageDigest)
	if err != nil {
		return vault.DialOptions{}, err
	}
	return vault.DialOptions{
		VaultPolicy: &ratls.VerificationPolicy{
			TEE:       ratls.TeeTypeSGX,
			MRENCLAVE: mre,
			// The SDK does not plumb a per-connection challenge nonce
			// yet, so the client->vault direction uses deterministic
			// ReportData binding. The vault->client direction (the one
			// the key release depends on) is full challenge-response,
			// enforced by the vault.
			ReportData: ratls.ReportDataDeterministic,
			QuoteVerification: &ratls.QuoteVerificationConfig{
				Endpoint: cfg.AttestationServerURL,
				// The attestation server requires an OIDC bearer; the
				// manager fetched one from mgmt-service (it has no OIDC
				// key of its own).
				Token: attToken,
			},
		},
		GetClientCertificate: certFn,
	}, nil
}

// encodeShare builds the per-vault ProvideMaterial payload.
func encodeShare(generation []byte, s *vault.Share) []byte {
	out := make([]byte, 0, generationSize+1+len(s.Data))
	out = append(out, generation...)
	out = append(out, vault.ShareToBytes(s)...)
	return out
}

// decodeShare splits a payload back into (generation, share).
func decodeShare(payload []byte) (string, *vault.Share, error) {
	if len(payload) < generationSize+2 {
		return "", nil, fmt.Errorf("share payload too short (%d bytes)", len(payload))
	}
	s, err := vault.ShareFromBytes(payload[generationSize:])
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(payload[:generationSize]), s, nil
}

// bestGroup picks the largest same-generation share group meeting the
// threshold. Pure; unit-tested.
func bestGroup(byGen map[string][]*vault.Share, threshold int) []*vault.Share {
	var best []*vault.Share
	for _, shares := range byGen {
		if len(shares) >= threshold && len(shares) > len(best) {
			best = shares
		}
	}
	return best
}

// ResolveOrProvision returns the LUKS passphrase (hex of the 32-byte
// DEK) and the attested key-origin string for the given handle.
//
// It first tries to reconstruct the DEK from the constellation. When
// the handle is reserved but unfilled (two-phase create), it generates
// the DEK here, fills the constellation, and only returns once at
// least k vaults hold a share of the SAME generation — so a volume is
// never formatted with a key the constellation cannot give back.
func ResolveOrProvision(ctx context.Context, log *zap.Logger, cfg Config, handle string, imageDigest []byte) (string, string, error) {
	if err := cfg.validate(); err != nil {
		return "", "", err
	}
	if handle == "" {
		return "", "", errors.New("vaultkey: empty key handle")
	}
	log = log.Named("vaultkey").With(zap.String("handle", handle))

	attToken, err := fetchAttestationToken(ctx, cfg)
	if err != nil {
		return "", "", fmt.Errorf("vaultkey: %w", err)
	}
	opts, err := dialOptions(cfg, imageDigest, attToken)
	if err != nil {
		return "", "", err
	}

	// ---- Phase 1: try to collect existing shares -----------------------
	byGen := make(map[string][]*vault.Share)
	pending := 0
	notFound := 0
	var lastErr error
	for _, ep := range cfg.Endpoints {
		material, err := exportFrom(ctx, ep, opts, handle)
		switch {
		case err == nil:
			gen, share, derr := decodeShare(material)
			if derr != nil {
				log.Warn("undecodable share", zap.String("vault", ep), zap.Error(derr))
				continue
			}
			byGen[gen] = append(byGen[gen], share)
		case strings.Contains(err.Error(), "not yet provided"):
			pending++
		case strings.Contains(err.Error(), "key not found"):
			notFound++
		default:
			lastErr = err
			log.Warn("vault unavailable", zap.String("vault", ep), zap.Error(err))
		}
	}

	if best := bestGroup(byGen, cfg.threshold()); best != nil {
		dek, err := vault.ShamirReconstruct(best)
		if err != nil {
			return "", "", fmt.Errorf("vaultkey: reconstruct: %w", err)
		}
		if len(dek) != dekSize {
			return "", "", fmt.Errorf("vaultkey: reconstructed DEK has %d bytes, want %d", len(dek), dekSize)
		}
		log.Info("volume DEK reconstructed from constellation",
			zap.Int("shares", len(best)))
		return hex.EncodeToString(dek), "vault:" + handle, nil
	}

	if pending == 0 {
		if notFound == len(cfg.Endpoints) {
			return "", "", fmt.Errorf("vaultkey: handle %q is not reserved on any vault (the platform must CreateKeyPending it before deploy)", handle)
		}
		return "", "", fmt.Errorf("vaultkey: cannot reconstruct (no share group meets threshold %d) and no vault reports pending material; last error: %v", cfg.threshold(), lastErr)
	}

	// ---- Phase 2: first boot — generate + fill -------------------------
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return "", "", fmt.Errorf("vaultkey: generate DEK: %w", err)
	}
	generation := make([]byte, generationSize)
	if _, err := rand.Read(generation); err != nil {
		return "", "", fmt.Errorf("vaultkey: generate generation id: %w", err)
	}
	shares, err := vault.ShamirSplit(dek, cfg.threshold(), len(cfg.Endpoints))
	if err != nil {
		return "", "", fmt.Errorf("vaultkey: shamir split: %w", err)
	}

	acks := 0
	for i, ep := range cfg.Endpoints {
		payload := encodeShare(generation, shares[i])
		// One retry per vault: transient dial failures are common right
		// after a vault restart. The payload is identical, so a retry
		// can never split generations.
		var perr error
		for attempt := 0; attempt < 2; attempt++ {
			perr = provideTo(ctx, ep, opts, handle, payload)
			if perr == nil {
				acks++
				break
			}
			if strings.Contains(perr.Error(), "already provided") {
				// Holds a share of an older generation (earlier partial
				// fill). Not part of this generation's quorum.
				break
			}
		}
		if perr != nil {
			log.Warn("share fill failed", zap.String("vault", ep), zap.Error(perr))
		}
	}
	if acks < cfg.threshold() {
		// The volume has NOT been formatted with this DEK; failing the
		// load here is safe and the reconciler will retry the whole
		// resolution with a fresh generation.
		return "", "", fmt.Errorf("vaultkey: only %d of %d vaults accepted a share (threshold %d) — refusing to use an unrecoverable DEK", acks, len(cfg.Endpoints), cfg.threshold())
	}
	log.Info("volume DEK generated in-enclave and filled into constellation",
		zap.Int("acks", acks), zap.Int("threshold", cfg.threshold()))
	return hex.EncodeToString(dek), "vault:" + handle, nil
}

func exportFrom(ctx context.Context, endpoint string, opts vault.DialOptions, handle string) ([]byte, error) {
	c, err := vault.Dial(ctx, vault.VaultRegistration{ID: endpoint, Endpoint: endpoint, Status: "static"}, opts)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.ExportKey(ctx, handle)
}

func provideTo(ctx context.Context, endpoint string, opts vault.DialOptions, handle string, material []byte) error {
	c, err := vault.Dial(ctx, vault.VaultRegistration{ID: endpoint, Endpoint: endpoint, Status: "static"}, opts)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.ProvideMaterial(ctx, handle, material)
	return err
}
