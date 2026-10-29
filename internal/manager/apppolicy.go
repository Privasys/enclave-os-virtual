package manager

// Owner-signed app policy.
//
// The control plane distributes policy; the owner authors it. A policy
// document carries the app's owners, its dependency set, its allowed
// callers and its direct domains, signed with the owner's policy key. The first document an app
// accepts pins that key; afterwards nothing the control plane sends can change
// the app's policy without the owner's signature.
//
// Until an app has accepted its first document the manager-role routes still
// apply policy, which is how apps that predate this keep working. Once an app
// is pinned those routes refuse it, and say why.

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"

	"go.uber.org/zap"

	"enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-os-virtual/internal/apppolicy"
)

// maxPolicyBody bounds a policy document.
const maxPolicyBody = 256 << 10

// handleSetAppPolicy handles PUT /api/v1/containers/{name}/policy: a document
// the owner approved in their wallet, replacing what the control plane may
// otherwise set. The request needs no platform role: the owner's approval,
// bound to this exact document, is the authority.
func (s *Server) handleSetAppPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "container name is required")
		return
	}
	if s.policy == nil {
		s.jsonError(w, http.StatusNotImplemented, "owner-approved app policy is not configured on this runtime")
		return
	}
	appID := s.launcher.AppIDOf(name)
	if appID == "" {
		s.jsonError(w, http.StatusConflict, "container carries no app id, so it has no policy identity")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxPolicyBody))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "could not read the policy document")
		return
	}
	doc, rawDoc, err := s.policy.Accept(raw)
	if err != nil {
		s.log.Warn("app policy refused", zap.String("container", name), zap.Error(err))
		s.jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	if doc.AppID != appID {
		s.jsonError(w, http.StatusForbidden, "the document is for a different app")
		return
	}

	// Parse everything first, so a malformed field is refused before any of
	// it is applied.
	var deps *ratls.DependencySet
	if len(doc.Dependencies) > 0 {
		deps = &ratls.DependencySet{}
		if err := json.Unmarshal(doc.Dependencies, deps); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid dependency set: "+err.Error())
			return
		}
	}
	var callers *struct {
		Entries   []ratls.DependencyEntry `json:"entries"`
		Platforms []string                `json:"platforms"`
	}
	if len(doc.AllowedCallers) > 0 {
		callers = &struct {
			Entries   []ratls.DependencyEntry `json:"entries"`
			Platforms []string                `json:"platforms"`
		}{}
		if err := json.Unmarshal(doc.AllowedCallers, callers); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid allowed callers: "+err.Error())
			return
		}
	}
	var domains []string
	if doc.Domains != nil {
		domains = s.policy.DomainsFor(appID)
	}

	applied := make([]string, 0, 4)
	if deps != nil {
		applied = append(applied, "dependencies")
	}
	if callers != nil {
		applied = append(applied, "allowed_callers")
	}
	if len(doc.Owners) > 0 {
		applied = append(applied, "owners")
	}
	if doc.Domains != nil {
		applied = append(applied, "domains")
	}

	// Apply in the background. Every step takes the launcher lock, which a
	// container load holds through image pulls and volume work, and the
	// document is already accepted and pinned: making the caller wait only
	// timed the control plane out (and told the owner it was not delivered)
	// while the policy went on to apply. The certificate stamp (OID 7.3) is
	// last, so a verifier never sees a document advertised before it is
	// enforced.
	seq, digest := doc.Seq, sha256.Sum256(rawDoc)
	owners := doc.Owners
	hasDomains := doc.Domains != nil
	go func() {
		fail := func(what string, err error) {
			s.log.Error("app policy accepted but not fully applied",
				zap.String("container", name), zap.String("step", what), zap.Error(err))
		}
		if deps != nil {
			if _, err := s.launcher.SetDependencies(name, deps); err != nil {
				fail("dependencies", err)
				return
			}
		}
		if callers != nil {
			set := &ratls.DependencySet{Entries: callers.Entries}
			if err := s.launcher.SetIngressAllowedCallers(name, set, callers.Platforms); err != nil {
				fail("allowed_callers", err)
				return
			}
		}
		if len(owners) > 0 {
			s.launcher.SetConfigOwners(name, owners)
		}
		if hasDomains {
			if err := s.launcher.SetDirectDomains(name, domains); err != nil {
				// Domains report through the direct status; keep going so the
				// rest of the policy is advertised.
				fail("domains", err)
			}
		}
		if err := s.launcher.SetAppPolicyStamp(name, seq, digest); err != nil {
			fail("stamp", err)
			return
		}
		s.log.Info("app policy applied", zap.String("container", name), zap.Uint64("seq", seq))
	}()

	s.log.Info("app policy accepted",
		zap.String("container", name), zap.String("app_id", appID),
		zap.Uint64("seq", doc.Seq), zap.Strings("applied", applied))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"app_id":  appID,
		"seq":     doc.Seq,
		"applied": applied,
	})
}

// policyPinned reports whether this container's app has accepted a signed
// policy. Once it has, the control plane may no longer author that app's
// policy: the owner's signature is the only way in.
func (s *Server) policyPinned(containerName string) bool {
	if s.policy == nil {
		return false
	}
	appID := s.launcher.AppIDOf(containerName)
	if appID == "" {
		return false
	}
	return s.policy.Pinned(appID)
}

// newPolicyStore opens the pin store, logging and disabling signed policy when
// it cannot be read rather than refusing to start: an unreadable pin file must
// not take a host's apps down.
func newPolicyStore(path string, verifier apppolicy.TokenVerifier, log *zap.Logger) *apppolicy.Store {
	store, err := apppolicy.NewStore(path, verifier)
	if err != nil {
		log.Error("signed app policy disabled: pin store unusable", zap.String("path", path), zap.Error(err))
		return nil
	}
	return store
}
