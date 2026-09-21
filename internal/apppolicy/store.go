// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package apppolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// TokenVerifier verifies an identity-provider token and returns its claims. The
// runtime's OIDC verifier satisfies it; a test supplies its own.
type TokenVerifier interface {
	VerifyApprovalToken(token string) (map[string]interface{}, error)
}

// pin is what an app remembers about its own policy: who may approve a change,
// and the last sequence accepted.
type pin struct {
	Approver string `json:"approver"`
	Seq      uint64 `json:"seq"`
	// Constellation is where the owner approved this app's data key to live.
	// Kept with the pin so it is known at the next boot, before any policy
	// has been delivered: that is exactly when a key would be resolved.
	Constellation *Constellation `json:"constellation,omitempty"`
}

// Store keeps each app's pin. It lives on the manager's /data volume, which is
// encrypted under a key from the vault, so the host cannot edit it. A host that
// restores an older /data can roll a pin back, which is why the accepted
// document is also advertised in the app's certificate: an old policy is then
// visible to anyone attesting the app rather than silent.
type Store struct {
	path     string
	verifier TokenVerifier
	mu       sync.Mutex
	pins     map[string]pin
}

// NewStore loads the pins at path, creating an empty set when the file does not
// exist. An empty path gives an in-memory store (dev and tests). Without a
// verifier no document can be accepted: an approval nobody checks is not one.
func NewStore(path string, verifier TokenVerifier) (*Store, error) {
	s := &Store{path: path, verifier: verifier, pins: make(map[string]pin)}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("apppolicy: read pins: %w", err)
	}
	if err := json.Unmarshal(raw, &s.pins); err != nil {
		return nil, fmt.Errorf("apppolicy: parse pins: %w", err)
	}
	if s.pins == nil {
		s.pins = make(map[string]pin)
	}
	return s, nil
}

// Pinned reports whether the app has accepted a policy document before. Until
// it has, the runtime still takes policy from the control plane, which is how
// an app that predates signed policy keeps working.
func (s *Store) Pinned(appID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.pins[appID]
	return ok
}

// Approver returns the subject whose approval this app's policy requires, or
// "" when it has accepted none yet.
func (s *Store) Approver(appID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pins[appID].Approver
}

// Accept verifies an approved policy document against what the app already
// knows and, when it holds, records the new pin. It returns the document and
// the exact bytes that were approved, which is what the certificate advertises.
//
// The rules are:
//   - the first document pins the subject who approved it, and its seq;
//   - later documents must be approved by that subject and carry a higher seq;
//   - a document may name the NEXT approver, which is how an app changes hands,
//     but it must still be approved by the current one.
func (s *Store) Accept(raw []byte) (*Document, []byte, error) {
	doc, rawDoc, token, err := Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if s.verifier == nil {
		return nil, nil, fmt.Errorf("apppolicy: no token verifier configured")
	}
	claims, err := s.verifier.VerifyApprovalToken(token)
	if err != nil {
		return nil, nil, fmt.Errorf("apppolicy: approval token: %w", err)
	}
	sub, err := CheckApproval(doc, rawDoc, claims)
	if err != nil {
		return nil, nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, pinned := s.pins[doc.AppID]
	if pinned {
		if sub != current.Approver {
			return nil, nil, fmt.Errorf("apppolicy: %s does not approve this app's policy", sub)
		}
		if doc.Seq <= current.Seq {
			return nil, nil, fmt.Errorf("apppolicy: document seq %d is not newer than %d", doc.Seq, current.Seq)
		}
	}

	next := sub
	if doc.Approver != "" {
		next = doc.Approver
	}
	// A document that names no constellation leaves the approved one alone,
	// so an owner editing their peers does not silently unpin their vault.
	constellation := current.Constellation
	if doc.Constellation.Valid() {
		constellation = doc.Constellation
	}
	s.pins[doc.AppID] = pin{Approver: next, Seq: doc.Seq, Constellation: constellation}
	if err := s.saveLocked(); err != nil {
		delete(s.pins, doc.AppID)
		if pinned {
			s.pins[doc.AppID] = current
		}
		return nil, nil, err
	}
	return doc, rawDoc, nil
}

// Forget drops an app's pin, for when the app itself is removed. A policy pin
// outliving its app would refuse the next app that reused the id.
func (s *Store) Forget(appID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pins[appID]; !ok {
		return nil
	}
	delete(s.pins, appID)
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	raw, err := json.Marshal(s.pins)
	if err != nil {
		return fmt.Errorf("apppolicy: encode pins: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("apppolicy: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".app-policy.*.tmp")
	if err != nil {
		return fmt.Errorf("apppolicy: temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// ConstellationFor returns the constellation the app's owner approved, or nil
// when they approved none. The launcher consults it before resolving a key.
func (s *Store) ConstellationFor(appID string) *Constellation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pins[appID].Constellation
}
