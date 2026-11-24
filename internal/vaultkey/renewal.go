package vaultkey

// Renewals and rotations that keep the key's policy (vault key ownership,
// formats §9).
//
// The next generation of a key takes its predecessor's policy verbatim; the
// grant only pays. On the same constellation the vault copies the policy
// itself (CreateKey with a predecessor). To another constellation, or for a
// rotation (a new value under the current policy), this enclave reads the
// policy, its version and the source's billing id from the source vaults at
// that moment, over the attested sessions it already uses for its shares, and
// carries them to each target vault. Nothing is read from disk: a stale copy
// would undo a policy update the owner made since.
//
// A v1 constellation (one that does not know GetVaultIdentity) keeps the v1
// create, the grant alone, until it retires.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	vault "github.com/Privasys/enclave-vaults-client/go/vault"
	"go.uber.org/zap"
)

// ErrV1Source is returned when a key would leave a v1 constellation for a v2
// one without the source's issuer and audience, from which its interim
// billing id is derived.
var ErrV1Source = errors.New("vaultkey: the source constellation is v1 and the request names no issuer and audience for it")

// constellation is what the vaults of one Config say about themselves.
type constellation struct {
	v1        bool
	members   []string // sorted member ids; empty when v1
	billingID string
}

func (c constellation) same(o constellation) bool {
	return !c.v1 && !o.v1 && slices.Equal(c.members, o.members)
}

// identify asks every vault of cfg for its identity. Every vault must answer:
// routing a renewal on a partial view could take a move for an in-place
// renewal. A constellation is v1 when every vault reports the request unknown.
func identify(ctx context.Context, cfg Config, opts vault.DialOptions) (constellation, error) {
	var out constellation
	unsupported := 0
	billing := map[string]bool{}
	for _, ep := range cfg.Endpoints {
		c, err := dial(ctx, ep, opts)
		if err != nil {
			return constellation{}, fmt.Errorf("vaultkey: identify %s: %w", ep, err)
		}
		id, err := c.GetVaultIdentity(ctx)
		c.Close()
		switch {
		case err != nil && vault.IsUnsupported(err):
			unsupported++
			continue
		case err != nil:
			return constellation{}, fmt.Errorf("vaultkey: identify %s: %w", ep, err)
		}
		if !strings.EqualFold(id.MRENCLAVE, cfg.MrenclaveHex) {
			return constellation{}, fmt.Errorf("vaultkey: %s reports build %s, expected %s", ep, id.MRENCLAVE, cfg.MrenclaveHex)
		}
		if id.MemberID == "" {
			return constellation{}, fmt.Errorf("vaultkey: %s reports no member id", ep)
		}
		out.members = append(out.members, strings.ToLower(id.MemberID))
		billing[id.BillingID] = true
		out.billingID = id.BillingID
	}
	switch {
	case unsupported == len(cfg.Endpoints):
		return constellation{v1: true}, nil
	case unsupported > 0:
		return constellation{}, fmt.Errorf("vaultkey: %d of %d vaults are v1; a constellation must be one build", unsupported, len(cfg.Endpoints))
	case len(billing) != 1:
		return constellation{}, errors.New("vaultkey: the vaults of one constellation report different billing configurations")
	}
	slices.Sort(out.members)
	if len(slices.Compact(slices.Clone(out.members))) != len(out.members) {
		return constellation{}, errors.New("vaultkey: two endpoints report the same member id")
	}
	return out, nil
}

// carried is a key's policy as its source vaults hold it now.
type carried struct {
	policy        json.RawMessage
	policyVersion uint32
	billingID     string
}

// readCarried reads handle's policy, version and the billing id from EVERY
// source vault, and all must agree (by the policy's JCS digest, as vault
// builds may serialise differently). An owner's policy update lands vault by
// vault, so k agreeing answers could still be the version before it; carrying
// that would undo the update. Any vault that does not answer, or disagrees,
// fails the renewal closed, and it is retried later.
//
// v1Billing, set for a v1 source (which cannot name its billing), is the
// interim billing id derived from the source's issuer and audience.
func readCarried(ctx context.Context, log *zap.Logger, cfg Config, opts vault.DialOptions, handle, v1Billing string) (carried, error) {
	type answer struct {
		c      carried
		digest string
	}
	var answers []answer
	for _, ep := range cfg.Endpoints {
		a, err := func() (answer, error) {
			c, err := dial(ctx, ep, opts)
			if err != nil {
				return answer{}, err
			}
			defer c.Close()
			policy, version, err := c.GetPolicyRaw(ctx, handle)
			if err != nil {
				return answer{}, err
			}
			billing := v1Billing
			if billing == "" {
				id, err := c.GetVaultIdentity(ctx)
				if err != nil {
					return answer{}, err
				}
				billing = id.BillingID
			}
			digest, err := vault.PolicyDigestJSON(policy)
			if err != nil {
				return answer{}, err
			}
			return answer{carried{policy, version, billing}, digest}, nil
		}()
		if err != nil {
			return carried{}, fmt.Errorf("vaultkey: source vault %s did not give the policy of %q (every source vault must): %w", ep, handle, err)
		}
		answers = append(answers, a)
	}
	if len(answers) == 0 {
		return carried{}, errors.New("vaultkey: no source vaults")
	}
	first := answers[0]
	for _, a := range answers[1:] {
		if a.digest != first.digest || a.c.policyVersion != first.c.policyVersion || a.c.billingID != first.c.billingID {
			return carried{}, fmt.Errorf("vaultkey: the source vaults disagree on the policy of %q (versions %d and %d); retry once they converge", handle, first.c.policyVersion, a.c.policyVersion)
		}
	}
	return first.c, nil
}

// Renew re-creates material (the key held under oldHandle on src) under
// newHandle on dst, keeping the key's policy. Same constellation: in place,
// with oldHandle as predecessor. Another one: the policy is carried. Returns
// the hex key dst holds under newHandle (the caller compares it with material:
// a retried renewal finds newHandle created already) and its origin.
func Renew(ctx context.Context, log *zap.Logger, src, dst Config, oldHandle, newHandle, grant string, material, imageDigest, appID []byte) (string, string, error) {
	plan, err := planCarry(ctx, log, src, dst, oldHandle, imageDigest, appID, true)
	if err != nil {
		return "", "", err
	}
	dst.Material = material
	hexKey, origin, _, err := resolveOrProvision(ctx, log, dst, newHandle, grant, imageDigest, appID, plan)
	return hexKey, origin, err
}

// Rotate creates a fresh key at newHandle on dst under the current policy of
// oldHandle on src, read now and carried (never in place: the value is new).
// Same returns as ResolveOrProvision.
func Rotate(ctx context.Context, log *zap.Logger, src, dst Config, oldHandle, newHandle, grant string, imageDigest, appID []byte) (string, string, bool, error) {
	plan, err := planCarry(ctx, log, src, dst, oldHandle, imageDigest, appID, false)
	if err != nil {
		return "", "", false, err
	}
	return resolveOrProvision(ctx, log, dst, newHandle, grant, imageDigest, appID, plan)
}

// planCarry decides how the next key is created on dst. nil: the v1 create.
func planCarry(ctx context.Context, log *zap.Logger, src, dst Config, oldHandle string, imageDigest, appID []byte, inPlaceOK bool) (renewalFor, error) {
	for _, c := range []Config{src, dst} {
		if err := c.validate(); err != nil {
			return nil, err
		}
	}
	srcOpts, err := optsFor(ctx, src, imageDigest, appID)
	if err != nil {
		return nil, err
	}
	dstOpts, err := optsFor(ctx, dst, imageDigest, appID)
	if err != nil {
		return nil, err
	}
	target, err := identify(ctx, dst, dstOpts)
	if err != nil {
		return nil, err
	}
	if target.v1 {
		log.Info("target constellation is v1: the grant carries the policy", zap.String("handle", oldHandle))
		return nil, nil
	}
	source, err := identify(ctx, src, srcOpts)
	if err != nil {
		return nil, err
	}
	v1Billing := ""
	if source.v1 {
		// A v1 vault cannot name its billing. Its interim id is derived from
		// its issuer and audience, which the control plane's constellation
		// entry gives: the control plane also mints the grant that admits the
		// key, so this trusts it with nothing it did not already decide.
		if src.V1Issuer == "" || src.V1Audience == "" {
			return nil, ErrV1Source
		}
		v1Billing = vault.ImplicitBillingID(src.V1Issuer, src.V1Audience)
	}
	if inPlaceOK && source.same(target) {
		return func([]byte) (*vault.Renewal, error) {
			return &vault.Renewal{Predecessor: oldHandle}, nil
		}, nil
	}
	got, err := readCarried(ctx, log, src, srcOpts, oldHandle, v1Billing)
	if err != nil {
		return nil, err
	}
	if got.billingID != target.billingID {
		// The target refuses it too (formats §9); saying so here is clearer.
		return nil, fmt.Errorf("vaultkey: %q is under billing configuration %s and the target under %s; keys do not cross billing configurations", oldHandle, got.billingID, target.billingID)
	}
	return func(key []byte) (*vault.Renewal, error) {
		check, err := vault.NewKeyCheck(key)
		if err != nil {
			return nil, fmt.Errorf("key check: %w", err)
		}
		return &vault.Renewal{
			Policy:          got.policy,
			PolicyVersion:   got.policyVersion,
			SourceBillingID: got.billingID,
			KeyCheck:        &check,
		}, nil
	}, nil
}

func optsFor(ctx context.Context, cfg Config, imageDigest, appID []byte) (vault.DialOptions, error) {
	attToken, err := attestationToken(ctx, cfg)
	if err != nil {
		return vault.DialOptions{}, fmt.Errorf("vaultkey: %w", err)
	}
	return dialOptions(cfg, imageDigest, appID, attToken)
}

// ErrNotRetired means the previous generation was left in place, to expire on
// its own: the successor is not confirmed on every target vault, or not every
// source vault deleted the predecessor. Never a reason to retry the renewal.
var ErrNotRetired = errors.New("vaultkey: previous generation not retired")

// RetirePredecessor deletes oldHandle after a successful in-place renewal to
// newHandle, with no owner approval (formats §9.1). The caller has already
// made newHandle the key its own state points at. A move is never retired
// here. Every vault must hold newHandle (a create succeeds at k acks, and a
// retried renewal can find the successor on only some vaults), and both
// generations, rebuilt now, must hold the same value. A predecessor already
// gone counts as deleted. Returns nil only when every vault has none.
func RetirePredecessor(ctx context.Context, log *zap.Logger, src, dst Config, oldHandle, newHandle string, imageDigest, appID []byte) error {
	if oldHandle == "" || newHandle == "" || oldHandle == newHandle {
		return fmt.Errorf("vaultkey: retire needs two distinct handles")
	}
	for _, c := range []Config{src, dst} {
		if err := c.validate(); err != nil {
			return err
		}
	}
	dstOpts, err := optsFor(ctx, dst, imageDigest, appID)
	if err != nil {
		return err
	}
	srcOpts, err := optsFor(ctx, src, imageDigest, appID)
	if err != nil {
		return err
	}
	// Only in place: a vault retires only a generation it can see superseded
	// on itself (formats §9.1). After a move the old generation expires on its
	// own constellation, or goes when that constellation retires.
	target, err := identify(ctx, dst, dstOpts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRetired, err)
	}
	source, err := identify(ctx, src, srcOpts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotRetired, err)
	}
	switch {
	case target.v1 || source.v1:
		return fmt.Errorf("%w: a v1 constellation does not retire keys", ErrNotRetired)
	case !source.same(target):
		return fmt.Errorf("%w: the key moved; %q expires on its own constellation", ErrNotRetired, oldHandle)
	}
	for _, ep := range dst.Endpoints {
		if err := holds(ctx, ep, dstOpts, newHandle); err != nil {
			return fmt.Errorf("%w: %s does not confirm %q: %v", ErrNotRetired, ep, newHandle, err)
		}
	}
	// Existing is not enough: the successor must hold the predecessor's value.
	// Both are rebuilt now, each from a threshold of its own vaults over their
	// attested connections. A predecessor gone everywhere was already retired.
	// Export only: a retire can never create a key.
	newHex, absent, err := rebuild(ctx, log, dst, dstOpts, newHandle)
	switch {
	case err != nil:
		return fmt.Errorf("%w: rebuild %q: %v", ErrNotRetired, newHandle, err)
	case absent:
		return fmt.Errorf("%w: %q is on no vault", ErrNotRetired, newHandle)
	}
	oldHex, absent, err := rebuild(ctx, log, src, srcOpts, oldHandle)
	switch {
	case err != nil:
		return fmt.Errorf("%w: rebuild %q: %v", ErrNotRetired, oldHandle, err)
	case absent:
		log.Info("previous generation already retired", zap.String("handle", oldHandle))
		return nil
	case subtle.ConstantTimeCompare([]byte(newHex), []byte(oldHex)) != 1:
		return fmt.Errorf("%w: %q does not hold the value of %q", ErrNotRetired, newHandle, oldHandle)
	}
	// Each vault checks it holds the successor, recorded with this predecessor,
	// and that it is one of the successor's members.
	failed := 0
	for _, ep := range src.Endpoints {
		if err := retireOn(ctx, ep, srcOpts, oldHandle, newHandle, target.members); err != nil {
			failed++
			log.Warn("previous generation not deleted", zap.String("vault", ep), zap.String("handle", oldHandle), zap.Error(err))
		}
	}
	if failed > 0 {
		return fmt.Errorf("%w: %d of %d source vaults still hold %q", ErrNotRetired, failed, len(src.Endpoints), oldHandle)
	}
	log.Info("previous generation retired", zap.String("handle", oldHandle), zap.String("successor", newHandle))
	return nil
}

func holds(ctx context.Context, endpoint string, opts vault.DialOptions, handle string) error {
	c, err := dial(ctx, endpoint, opts)
	if err != nil {
		return err
	}
	defer c.Close()
	info, err := c.GetKeyInfo(ctx, handle)
	if err != nil {
		return err
	}
	if info.Handle != handle {
		return fmt.Errorf("answered for %q", info.Handle)
	}
	return nil
}

// retireOn deletes the predecessor on one source vault (RetireKey; a
// predecessor already gone is success). A v1 vault does not know the request.
func retireOn(ctx context.Context, endpoint string, opts vault.DialOptions, oldHandle, newHandle string, members []string) error {
	c, err := dial(ctx, endpoint, opts)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.RetireKey(ctx, oldHandle, newHandle, members)
	return err
}
