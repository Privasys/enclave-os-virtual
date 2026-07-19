// Package vaultkey resolves per-container volume keys from the Enclave
// Vaults constellation (the enclave-upgrade design, Phase B).
//
// The DEK for a container's LUKS volume never exists outside TEE
// memory: it is either reconstructed from k-of-n Shamir shares held by
// the vault constellation, or — on the very first boot of a key handle —
// generated here and created on the constellation as shares in a single
// CreateKey call per vault, presenting a platform-minted key-creation
// grant. The platform supplies the handle, the constellation endpoints
// and the grant; it never sees key material.
//
// # Share payload format
//
// CreateKey is one-shot per vault (it rejects a duplicate handle), so a
// partially failed create followed by a retry would leave vaults holding
// shares of DIFFERENT DEK generations — and Shamir reconstruction over
// mixed generations yields garbage silently. Each vault's share payload
// is therefore prefixed with a random 16-byte generation id:
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
	// AttestationToken is a pre-fetched bearer for the attestation-server
	// quote verification. Set on the boot path (manager /data unlock),
	// where the per-enclave credential is still locked inside /data and
	// the bearer comes from the quote-authenticated redeem /
	// boot-attestation-token endpoints instead. When set, MgmtURL /
	// EnclaveID / EnclaveToken are not required and no fetch happens.
	AttestationToken string
	// BeforeProvision, when set, runs after Phase 1 has established that the
	// handle exists on NO vault and before Phase 2 creates it. Returning an
	// error aborts with that error and the key is never created.
	//
	// This is the hook for work that must not be stranded by a half-done
	// provision: creating a key the caller then cannot back with storage
	// poisons the handle permanently, because the next attempt reconstructs it
	// (expectExisting) and fails closed against the absent volume — and a
	// production enclave has no SSH to repair it by hand. Callers that back a
	// key with a resource should reserve that resource here, so a failure
	// leaves NO key and the retry starts clean.
	BeforeProvision func() error
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
	if c.AttestationToken == "" && (c.MgmtURL == "" || c.EnclaveID == "" || c.EnclaveToken == "") {
		return errors.New("vaultkey: either AttestationToken or MgmtURL+EnclaveID+EnclaveToken is required (for the attestation-server quote verification)")
	}
	return nil
}

// FetchAttestationToken gets a short-lived OIDC bearer from the management
// service (authed by the per-enclave credential) for attestation-server quote
// verification. Exported so other in-enclave verification paths — e.g. the
// manager's ingress mutual-RA-TLS verifier, which verifies a caller's quote at
// the attestation server — obtain the token the same way as the vault path.
func FetchAttestationToken(ctx context.Context, mgmtURL, enclaveID, enclaveToken string) (string, error) {
	return fetchAttestationToken(ctx, Config{MgmtURL: mgmtURL, EnclaveID: enclaveID, EnclaveToken: enclaveToken})
}

// attestationToken returns the pre-fetched bearer, or fetches one from the
// management service with the per-enclave credential.
func attestationToken(ctx context.Context, cfg Config) (string, error) {
	if cfg.AttestationToken != "" {
		return cfg.AttestationToken, nil
	}
	return fetchAttestationToken(ctx, cfg)
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
func dialOptions(cfg Config, imageDigest, appID []byte, attToken string) (vault.DialOptions, error) {
	mre, err := hex.DecodeString(cfg.MrenclaveHex)
	if err != nil {
		return vault.DialOptions{}, fmt.Errorf("vaultkey: bad mrenclave hex: %w", err)
	}
	certFn, err := clientCertificateFn(imageDigest, appID)
	if err != nil {
		return vault.DialOptions{}, err
	}
	// One challenge nonce per resolution. Sent in the ClientHello: it (1)
	// binds the vault's server quote to this connection via
	// challenge-response, and (2) puts the vault into bidirectional-
	// challenge mode so it issues its own challenge in the
	// CertificateRequest — which the Tee client cert (clientCertificateFn)
	// requires in order to be accepted.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return vault.DialOptions{}, fmt.Errorf("vaultkey: generate challenge nonce: %w", err)
	}
	return vault.DialOptions{
		Challenge: nonce,
		VaultPolicy: &ratls.VerificationPolicy{
			TEE:       ratls.TeeTypeSGX,
			MRENCLAVE: mre,
			// Challenge-response: the vault binds our ClientHello nonce
			// into its server-cert ReportData, proving the quote is fresh
			// and bound to this connection (not a relayed capture).
			ReportData: ratls.ReportDataChallengeResponse,
			Nonce:      nonce,
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

// encodeShare builds the per-vault CreateKey material payload.
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
// It first tries to reconstruct the DEK from the constellation. When the
// handle does not exist yet (first boot), it generates the DEK here and
// creates the key on each vault with a share as material, presenting the
// platform-minted grant, and only returns once at least k vaults hold a
// share of the SAME generation — so a volume is never formatted with a
// key the constellation cannot give back. A grant is required to create.
// The third return is reconstructed: true when the DEK was rebuilt from an
// existing key on the constellation (so an on-disk volume MUST exist), false
// when the key was freshly created (first deploy — a fresh volume is correct).
func ResolveOrProvision(ctx context.Context, log *zap.Logger, cfg Config, handle, grant string, imageDigest, appID []byte) (string, string, bool, error) {
	if err := cfg.validate(); err != nil {
		return "", "", false, err
	}
	if handle == "" {
		return "", "", false, errors.New("vaultkey: empty key handle")
	}
	log = log.Named("vaultkey").With(zap.String("handle", handle))

	attToken, err := attestationToken(ctx, cfg)
	if err != nil {
		return "", "", false, fmt.Errorf("vaultkey: %w", err)
	}
	opts, err := dialOptions(cfg, imageDigest, appID, attToken)
	if err != nil {
		return "", "", false, err
	}

	// ---- Phase 1: try to collect existing shares -----------------------
	byGen := make(map[string][]*vault.Share)
	notFound := 0
	denied := 0
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
		case strings.Contains(err.Error(), "key not found"):
			notFound++
		case strings.Contains(err.Error(), "policy.principals"):
			// The key EXISTS on this vault but our TEE is not in its policy
			// (the upgrade gate). The vault holds material we are simply not
			// authorised to export.
			denied++
		default:
			lastErr = err
			log.Warn("vault unavailable", zap.String("vault", ep), zap.Error(err))
		}
	}

	if best := bestGroup(byGen, cfg.threshold()); best != nil {
		dek, err := vault.ShamirReconstruct(best)
		if err != nil {
			return "", "", false, fmt.Errorf("vaultkey: reconstruct: %w", err)
		}
		if len(dek) != dekSize {
			return "", "", false, fmt.Errorf("vaultkey: reconstructed DEK has %d bytes, want %d", len(dek), dekSize)
		}
		log.Info("volume DEK reconstructed from constellation",
			zap.Int("shares", len(best)))
		return hex.EncodeToString(dek), "vault:" + handle, true, nil
	}

	// The key EXISTS (some vault denied our export on policy grounds) but we
	// could not assemble a quorum we are authorised to read. This is the
	// upgrade gate, NOT a first boot. Fail CLOSED — never fall through to
	// create: a fresh DEK created onto the absent vaults would split the key's
	// generations and permanently corrupt it (the volume was formatted with the
	// original DEK). The app/data owner must promote this measurement first.
	if denied > 0 {
		return "", "", false, fmt.Errorf("vaultkey: key %q exists but this measurement is not authorised to reconstruct it (%d/%d vaults denied on policy) — the owner must approve (promote) this version before it can run", handle, denied, len(cfg.Endpoints))
	}

	// First boot requires a clean slate: every vault must agree the handle is
	// absent. A partial set (some shares present below quorum, or an unreachable
	// vault) is NOT a first boot — creating a fresh generation could split the
	// key — so fail and let the reconciler retry.
	if notFound != len(cfg.Endpoints) {
		if len(byGen) > 0 {
			return "", "", false, fmt.Errorf("vaultkey: key %q exists on some vaults but no share group meets threshold %d — refusing to create a new generation", handle, cfg.threshold())
		}
		return "", "", false, fmt.Errorf("vaultkey: cannot reconstruct (no share group meets threshold %d) and not every vault reports the handle absent; last error: %v", cfg.threshold(), lastErr)
	}
	if grant == "" {
		return "", "", false, fmt.Errorf("vaultkey: handle %q does not exist and no key-creation grant was supplied (the platform must mint one at deploy)", handle)
	}

	// The handle exists nowhere and we are about to create it. This is the last
	// point at which failing leaves no trace: once the key exists, every later
	// attempt reconstructs it and fails closed unless the backing storage is
	// there too.
	if cfg.BeforeProvision != nil {
		if err := cfg.BeforeProvision(); err != nil {
			return "", "", false, fmt.Errorf("vaultkey: refusing to create key %q: %w", handle, err)
		}
	}

	// ---- Phase 2: first boot — generate + create -----------------------
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return "", "", false, fmt.Errorf("vaultkey: generate DEK: %w", err)
	}
	generation := make([]byte, generationSize)
	if _, err := rand.Read(generation); err != nil {
		return "", "", false, fmt.Errorf("vaultkey: generate generation id: %w", err)
	}
	shares, err := vault.ShamirSplit(dek, cfg.threshold(), len(cfg.Endpoints))
	if err != nil {
		return "", "", false, fmt.Errorf("vaultkey: shamir split: %w", err)
	}

	acks := 0
	for i, ep := range cfg.Endpoints {
		payload := encodeShare(generation, shares[i])
		// One retry per vault: transient dial failures are common right
		// after a vault restart. The payload is identical, so a retry
		// can never split generations.
		var cerr error
		for attempt := 0; attempt < 2; attempt++ {
			cerr = createOn(ctx, ep, opts, handle, payload, grant)
			if cerr == nil {
				acks++
				break
			}
			if strings.Contains(cerr.Error(), "already exists") {
				// Holds a share from an earlier partial create. Not counted
				// toward this generation's quorum.
				break
			}
		}
		if cerr != nil {
			log.Warn("share create failed", zap.String("vault", ep), zap.Error(cerr))
		}
	}
	if acks < cfg.threshold() {
		// The volume has NOT been formatted with this DEK; failing the
		// load here is safe and the reconciler will retry the whole
		// resolution with a fresh generation.
		return "", "", false, fmt.Errorf("vaultkey: only %d of %d vaults accepted a share (threshold %d) — refusing to use an unrecoverable DEK", acks, len(cfg.Endpoints), cfg.threshold())
	}
	log.Info("volume DEK generated in-enclave and created on constellation",
		zap.Int("acks", acks), zap.Int("threshold", cfg.threshold()))
	return hex.EncodeToString(dek), "vault:" + handle, false, nil
}

// Export reconstructs an opaque secret (e.g. a private-registry pull
// credential) the app owner created on the constellation, presenting this TEE's
// attested identity so a vault whose key policy grants THIS measurement
// ExportKey will release its share. Unlike a volume DEK the material is plain
// raw shares (no generation prefix, arbitrary length) — the layout the owner's
// CreateKeyShares writes — so this exports k shares and Shamir-reconstructs. It
// never creates: the key must already exist (the owner registered it).
//
// imageDigest/appID stamp this TEE's vault-client identity exactly as for a DEK
// resolution; the credential's policy gates release on the manager measurement.
func Export(ctx context.Context, log *zap.Logger, cfg Config, handle string, imageDigest, appID []byte) ([]byte, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if handle == "" {
		return nil, errors.New("vaultkey: empty key handle")
	}
	log = log.Named("vaultkey").With(zap.String("handle", handle))

	attToken, err := attestationToken(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("vaultkey: %w", err)
	}
	opts, err := dialOptions(cfg, imageDigest, appID, attToken)
	if err != nil {
		return nil, err
	}

	var shares []*vault.Share
	denied, notFound := 0, 0
	var lastErr error
	for _, ep := range cfg.Endpoints {
		material, err := exportFrom(ctx, ep, opts, handle)
		switch {
		case err == nil:
			s, derr := vault.ShareFromBytes(material)
			if derr != nil {
				log.Warn("undecodable share", zap.String("vault", ep), zap.Error(derr))
				continue
			}
			shares = append(shares, s)
		case strings.Contains(err.Error(), "key not found"):
			notFound++
		case strings.Contains(err.Error(), "policy.principals"):
			// The key exists but this measurement is not in its policy.
			denied++
		default:
			lastErr = err
			log.Warn("vault unavailable", zap.String("vault", ep), zap.Error(err))
		}
	}

	if len(shares) >= cfg.threshold() {
		secret, err := vault.ShamirReconstruct(shares[:cfg.threshold()])
		if err != nil {
			return nil, fmt.Errorf("vaultkey: reconstruct: %w", err)
		}
		log.Info("secret reconstructed from constellation", zap.Int("shares", len(shares)))
		return secret, nil
	}
	if denied > 0 {
		return nil, fmt.Errorf("vaultkey: key %q exists but this measurement is not authorised to export it (%d/%d vaults denied on policy) — the owner must grant this manager measurement ExportKey on the credential", handle, denied, len(cfg.Endpoints))
	}
	if notFound == len(cfg.Endpoints) {
		return nil, fmt.Errorf("vaultkey: credential %q does not exist on the constellation — register it before deploying", handle)
	}
	return nil, fmt.Errorf("vaultkey: only %d of %d usable shares (threshold %d); last error: %v", len(shares), len(cfg.Endpoints), cfg.threshold(), lastErr)
}

func exportFrom(ctx context.Context, endpoint string, opts vault.DialOptions, handle string) ([]byte, error) {
	c, err := vault.Dial(ctx, vault.VaultRegistration{ID: endpoint, Endpoint: endpoint, Status: "static"}, opts)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.ExportKey(ctx, handle)
}

func createOn(ctx context.Context, endpoint string, opts vault.DialOptions, handle string, material []byte, grant string) error {
	c, err := vault.Dial(ctx, vault.VaultRegistration{ID: endpoint, Endpoint: endpoint, Status: "static"}, opts)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.CreateKey(ctx, handle, material, grant)
	return err
}
