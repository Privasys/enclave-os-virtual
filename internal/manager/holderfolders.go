// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package manager

// Holder folders (internal/holders): the enclave OS is its own resource
// service for the kind "app_storage". A holder's data lives in a folder of
// the app's volume under the holder's key; the app asks the manager to open
// or close it and never sees a key or names a path.
//
// The wallet mints the capability HERE, on the app's hostname under the
// manager-reserved prefix, with the holder's bearer and the wallet-instance
// proof: the nonce-only result route is enough for coordinates that are
// worthless without a binding key, and a folder key is not coordinates (a
// forged first approval would create the holder's folder under an
// attacker's key). The holder's key comes in with the mint, is loaded into
// the kernel, wrapped under a key derived from the app's vault-backed
// volume DEK and kept beside the approval record when the app works
// unattended, and zeroed here. Only the measured enclave OS of this app can
// unwrap, because only it receives the app's DEK from the vault; renewal,
// constellation migration and the owner's promote on an upgrade are the
// DEK's, already built, and nothing exists per holder in the vault.
//
// Revoke is verified: a key removed while files are in use leaves them
// readable, so the manager kills what holds them and reads the kernel's
// status back; only "absent" is a revoke.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/holders"
	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

const (
	// holderCapabilitiesPath is the wallet-facing pair on the app's hostname:
	// POST (mint), GET (list this holder's), DELETE /{id} (revoke, verified).
	holderCapabilitiesPath = "/__privasys/v1/capabilities"

	// holderContainerMount is where the app's volume is mounted inside the
	// container (launcher: /run/containers/<name>:/data).
	holderContainerMount = "/data"

	// revokeGrace is how long the app gets, after the revoke event, to stop
	// the holder's processes before the manager kills them.
	revokeGrace = 3 * time.Second
)

// holderKeyFor is the folder name of a holder for an app: a hash, derived
// here and never sent by the app.
func holderKeyFor(appID, subject string) string {
	sum := sha256.Sum256([]byte(appID + "\x00" + subject))
	return hex.EncodeToString(sum[:16])
}

// ---- wrapping -------------------------------------------------------------

func wrapKey(wrapKey, raw []byte, aad string) (string, error) {
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, raw, []byte(aad))
	return base64.StdEncoding.EncodeToString(out), nil
}

func unwrapKey(wrapKey []byte, wrapped, aad string) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("wrapped key too short")
	}
	return gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], []byte(aad))
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---- open folders, in memory ---------------------------------------------

type holderOpenState struct {
	KeyID    string
	HostUID  int
	OpenedAt time.Time
	// ReadOnly: the folder is open read-only (its grant is [read]).
	ReadOnly bool
	// Container, HolderKey and Resource/Subject/CapabilityID name the open
	// folder, so a new task of the container can re-check it
	// (recheckReadOnlyFolders).
	Container    string
	HolderKey    string
	Resource     string
	Subject      string
	CapabilityID string
	// Mount and Exposed are the volume's paths (launcher.HolderFolders) at
	// open time, so the re-check can close the folder without asking the
	// launcher, whose lock its caller holds.
	Mount   string
	Exposed string
}

// readOnlyOf lists the open read-only folders of container, by grant key.
func (h *holderState) readOnlyOf(container string) map[string]holderOpenState {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]holderOpenState{}
	for k, st := range h.open {
		if st.ReadOnly && st.Container == container {
			out[k] = st
		}
	}
	return out
}

// holderState is what the manager knows about open folders: nothing
// survives a restart, which is the point (every folder is locked then).
type holderState struct {
	mu   sync.Mutex
	open map[string]holderOpenState // grantKey -> state
	// busy serialises the opens, mints and closes of one holder's folder:
	// each checks the state, works on the folder and records the result,
	// and two of them interleaved could record a mode the folder is not in
	// (a read-only mint over a writable open, 2026-11-27 review).
	busy map[string]*sync.Mutex
}

func newHolderState() *holderState {
	return &holderState{open: map[string]holderOpenState{}, busy: map[string]*sync.Mutex{}}
}

// lock takes the folder lock of key and returns its release. Never taken
// from the task pre-start hook, which runs under the launcher's lock.
func (h *holderState) lock(key string) func() {
	h.mu.Lock()
	m := h.busy[key]
	if m == nil {
		m = &sync.Mutex{}
		h.busy[key] = m
	}
	h.mu.Unlock()
	m.Lock()
	return m.Unlock
}

func (h *holderState) get(key string) (holderOpenState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, ok := h.open[key]
	return st, ok
}

// holderStateStale reports whether a recorded open of key is stale: its key
// is no longer loaded (a volume remounted under the state), which the kernel
// says. A stale state is dropped. Unsure (no folder service, no answer) is
// not stale.
func (s *Server) holderStateStale(container, key string, st holderOpenState) bool {
	hf, err := s.launcher.HolderFolders(container)
	if err != nil {
		return false
	}
	ks, err := holders.KeyStatus(hf.Mount, st.KeyID)
	if err != nil || ks == holders.Present {
		return false
	}
	s.holdersOpen.drop(key)
	return true
}

func (h *holderState) set(key string, st holderOpenState) {
	h.mu.Lock()
	h.open[key] = st
	h.mu.Unlock()
}

func (h *holderState) drop(key string) {
	h.mu.Lock()
	delete(h.open, key)
	h.mu.Unlock()
}

// ---- events ----------------------------------------------------------------

// resourceEvent is one line of the app's event stream.
type resourceEvent struct {
	Type         string `json:"-"`
	Resource     string `json:"resource,omitempty"`
	Subject      string `json:"subject,omitempty"`
	CapabilityID string `json:"capability_id,omitempty"`
	At           string `json:"at"`
}

// eventHub fans events out to the containers listening on
// GET /api/v1/resources/events. No replay: a client re-reads status on
// connect. A slow listener is dropped rather than blocking the emitter.
type eventHub struct {
	mu   sync.Mutex
	subs map[string]map[chan resourceEvent]struct{} // container -> listeners
}

func newEventHub() *eventHub { return &eventHub{subs: map[string]map[chan resourceEvent]struct{}{}} }

func (h *eventHub) subscribe(container string) (chan resourceEvent, func()) {
	ch := make(chan resourceEvent, 32)
	h.mu.Lock()
	if h.subs[container] == nil {
		h.subs[container] = map[chan resourceEvent]struct{}{}
	}
	h.subs[container][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs[container], ch)
		h.mu.Unlock()
	}
}

func (h *eventHub) emit(container string, ev resourceEvent) {
	if h == nil {
		return
	}
	if ev.At == "" {
		ev.At = time.Now().UTC().Format(time.RFC3339)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[container] {
		select {
		case ch <- ev:
		default:
		}
	}
}

// handleResourceEvents: GET /api/v1/resources/events (container token),
// text/event-stream. Nothing polls: approvals, revokes, opens and closes
// arrive here.
func (s *Server) handleResourceEvents(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	// The metrics middleware wraps the writer (responseWriter in manager.go)
	// and exposes Unwrap, not Flush: a type assertion on http.Flusher fails
	// on it, so every listener was answered "streaming unsupported" (HTTP
	// 500) and no container ever received an event. The response controller
	// follows Unwrap down to the connection's flusher.
	rc := http.NewResponseController(w)
	ch, cancel := s.events.subscribe(name)
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	if err := rc.Flush(); err != nil {
		s.log.Error("resource events: streaming unsupported", zap.String("container", name), zap.Error(err))
		return
	}
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			if err := rc.Flush(); err != nil {
				return
			}
		case ev := <-ch:
			data, _ := json.Marshal(ev)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

// ---- the wallet-facing pair on the app host --------------------------------

// serveHolderCapabilities answers the wallet under /__privasys/v1/capabilities
// on an app host. Every call carries the holder's platform bearer; a mint
// additionally proves it comes from the wallet app itself.
func (s *Server) serveHolderCapabilities(w http.ResponseWriter, r *http.Request, container string) {
	sub, isWallet, ok := s.holderCaller(w, r)
	if !ok {
		return
	}
	appID := s.launcher.ContainerFreezeState(container).AppID
	if appID == "" {
		s.jsonError(w, http.StatusServiceUnavailable, "container has no platform app id")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, holderCapabilitiesPath)
	switch {
	case rest == "" && r.Method == http.MethodPost:
		if !isWallet {
			s.jsonError(w, http.StatusForbidden, "a capability is minted by the wallet app itself")
			return
		}
		s.mintHolderCapability(w, r, container, appID, sub)
	case rest == "" && r.Method == http.MethodGet:
		s.listHolderCapabilities(w, container, appID, sub)
	case strings.HasPrefix(rest, "/") && r.Method == http.MethodDelete:
		s.revokeHolderCapability(w, container, appID, sub, path.Base(rest))
	default:
		s.jsonError(w, http.StatusNotFound, "not found")
	}
}

// holderCaller authenticates the wallet's call: the holder's OIDC bearer,
// and whether the wallet-instance proof (WIA + request-bound proof) is
// present and valid.
func (s *Server) holderCaller(w http.ResponseWriter, r *http.Request) (sub string, isWallet bool, ok bool) {
	if s.verifier == nil {
		s.jsonError(w, http.StatusServiceUnavailable, "no identity verifier configured")
		return "", false, false
	}
	if bearerToken(r.Header.Get("Authorization")) == "" {
		s.jsonError(w, http.StatusUnauthorized, "expected the holder's Bearer token")
		return "", false, false
	}
	c, err := s.callerOf(r).Platform()
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, "invalid holder token")
		return "", false, false
	}
	_, proven := s.walletCall.IsWalletCall(r)
	stripWalletProof(r)
	return c.Sub, proven || c.Wallet, true
}

// mintHolderCapability: the wallet delivers the holder's key with the
// approval. Body, as the wallet sends to any resource service:
//
//	{nonce, kind, permissions, request, setup: {key_b64, unattended}}
//
// The bearer's subject must be the ask's subject.
func (s *Server) mintHolderCapability(w http.ResponseWriter, r *http.Request, container, appID, sub string) {
	var body struct {
		Nonce string `json:"nonce"`
		Kind  string `json:"kind"`
		Setup struct {
			KeyB64     string `json:"key_b64"`
			Unattended *bool  `json:"unattended"`
		} `json:"setup"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&body); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	p, ok := s.caps.get(body.Nonce)
	if !ok || p.container != container || p.Capability.Kind != launcher.AppStorageKind {
		s.jsonError(w, http.StatusNotFound, "no such capability request")
		return
	}
	if p.subject != sub {
		s.log.Warn("holder mint: bearer subject is not the ask's",
			zap.String("container", container), zap.String("ask", prefix8(p.subject)), zap.String("bearer", prefix8(sub)))
		s.jsonError(w, http.StatusForbidden, "this request was made for another holder")
		return
	}
	// A writable open cannot become read-only in place, here as on the open
	// path: a writable fd the app already holds would survive the read-only
	// bind. The folder must be closed (which ends whatever holds its files)
	// before a read-only grant is minted on it. The folder lock is held from
	// this check to the recorded state, so an open cannot slip in between.
	defer s.holdersOpen.lock(grantKey(appID, p.resource, sub))()
	if st, open := s.holdersOpen.get(grantKey(appID, p.resource, sub)); open && !st.ReadOnly {
		readOnly, aerr := holderReadOnly(p.Capability.Permissions)
		if aerr != nil {
			s.jsonError(w, http.StatusForbidden, aerr.Error())
			return
		}
		if readOnly && !s.holderStateStale(container, grantKey(appID, p.resource, sub), st) {
			s.jsonError(w, http.StatusConflict, "the folder is open writable; close it before it can open read-only")
			return
		}
	}
	raw, err := base64.StdEncoding.DecodeString(body.Setup.KeyB64)
	if err != nil || len(raw) != holders.RawKeySize {
		s.jsonError(w, http.StatusBadRequest, fmt.Sprintf("setup.key_b64 must be %d bytes, standard base64", holders.RawKeySize))
		return
	}
	defer zeroBytes(raw)
	hf, err := s.launcher.HolderFolders(container)
	if err != nil {
		s.log.Warn("holder mint refused", zap.String("container", container), zap.Error(err))
		s.jsonError(w, http.StatusNotImplemented, err.Error())
		return
	}
	decl, _ := s.resourceDecl(container, p.resource)
	unattended := declUnattended(decl)
	if body.Setup.Unattended != nil {
		unattended = unattended && *body.Setup.Unattended
	}
	holderKey := holderKeyFor(appID, sub)
	_, wasOpen := s.holdersOpen.get(grantKey(appID, p.resource, sub))
	// The grant records exactly the ask's permission set (resolveHolder), so
	// the folder is unlocked in that mode now: read-only is bound before the
	// key loads, as on every other open.
	keyID, readOnly, err := s.unlockHolderFolder(container, hf, holderKey, p.Capability.Permissions, raw, true)
	if errors.Is(err, errHolderAccess) {
		s.jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	if err != nil {
		s.log.Error("holder folder create", zap.String("container", container), zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, "the folder could not be created")
		return
	}
	// A mint that fails after the unlock locks the folder again: no folder
	// stays open without a grant the manager tracks.
	// (A folder that was already open before this mint is left as it was.)
	relock := func() {
		if wasOpen {
			return
		}
		_, _, _ = holders.Close(hf.Mount, holderKey, keyID)
		s.releaseHolderBind(hf, holderKey)
	}
	capID := newCapabilityID()
	wrapped := ""
	if unattended {
		wrapped, err = wrapKey(hf.WrapKey, raw, holderKey+"|"+capID)
		if err != nil {
			relock()
			s.jsonError(w, http.StatusInternalServerError, "the key could not be wrapped")
			return
		}
	}
	containerPath := path.Join(holderContainerMount, holders.Dir, holderKey)
	_, g, err := s.caps.resolveHolder(body.Nonce, capID, map[string]string{"path": containerPath}, holderKey, keyID, wrapped, unattended)
	if err != nil {
		relock()
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	// The mint loaded the key: the folder is open, owned by root until the
	// app's first open names a uid.
	s.holdersOpen.set(grantKey(appID, p.resource, sub), holderOpenState{KeyID: keyID, HostUID: -1, OpenedAt: time.Now().UTC(), ReadOnly: readOnly,
		Container: container, HolderKey: holderKey, Resource: p.resource, Subject: sub, CapabilityID: capID,
		Mount: hf.Mount, Exposed: hf.Exposed})
	s.log.Info("holder folder minted", zap.String("container", container), zap.String("resource", p.resource),
		zap.String("holder", holderKey), zap.Bool("unattended", unattended), zap.Bool("read_only", readOnly),
		zap.String("capability_id", capID))
	s.events.emit(container, resourceEvent{Type: "capability.approved", Resource: p.resource, Subject: sub, CapabilityID: capID})
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"capability_id":  capID,
		"kind":           launcher.AppStorageKind,
		"service_result": g.ServiceResult,
		"expires_unix":   0,
	})
}

// declUnattended reports whether the declaration lets the app keep the
// holder's key to work unattended. Only an explicit true does: a load
// refuses an app_storage declaration without the option, and anything else
// reads as false, as the wallet and the control plane read it.
func declUnattended(decl capabilityDecl) bool {
	v, _ := decl.Options["unattended"].(bool)
	return v
}

func newCapabilityID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "hf_" + hex.EncodeToString(b)
}

func prefix8(s string) string {
	if len(s) > 8 {
		return s[:8] + "…"
	}
	return s
}

// listHolderCapabilities: what this holder holds on this app, in the shape
// every resource service answers (know-how, the holder-facing pair).
func (s *Server) listHolderCapabilities(w http.ResponseWriter, container, appID, sub string) {
	var out []map[string]any
	for _, g := range s.caps.grantsFor(appID) {
		if !g.usable() || g.Subject != sub || g.Kind != launcher.AppStorageKind {
			continue
		}
		decl, _ := s.resourceDecl(container, g.Resource)
		out = append(out, map[string]any{
			"capability_id":  g.CapabilityID,
			"kind":           g.Kind,
			"permissions":    g.Permissions,
			"resource_label": decl.Label,
			"subject_app_id": appID,
			"created_unix":   g.At.Unix(),
			"expires_unix":   0,
			"unattended":     g.Unattended,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"capabilities": out})
}

// revokeHolderCapability: DELETE /__privasys/v1/capabilities/{id}. For an
// app_storage capability the folder is closed and the closing verified; for
// any other kind this is the caller-side revoke (the record the holder
// withdrew at the service goes here too, so the app stops saying approved).
func (s *Server) revokeHolderCapability(w http.ResponseWriter, container, appID, sub, capID string) {
	key, g := s.caps.byCapabilityID(appID, capID)
	if g == nil {
		s.jsonError(w, http.StatusNotFound, "not this holder's capability")
		return
	}
	if g.Subject != sub {
		s.jsonError(w, http.StatusNotFound, "not this holder's capability")
		return
	}
	if g.Status == "revoked" {
		s.jsonError(w, http.StatusGone, "already revoked")
		return
	}
	s.events.emit(container, resourceEvent{Type: "capability.revoked", Resource: g.Resource, Subject: g.Subject, CapabilityID: capID})
	if g.Kind == launcher.AppStorageKind {
		// The folder lock covers the close AND the revoke: until the grant
		// is revoked its wrapped key could reopen the folder, so no open may
		// run between the verified close and the revoke.
		defer s.holdersOpen.lock(key)()
		if verified, err := s.closeHolderVerified(container, key, g); err != nil {
			s.log.Error("holder revoke", zap.String("container", container), zap.String("capability_id", capID), zap.Error(err))
			s.jsonError(w, http.StatusInternalServerError, "the folder could not be closed")
			return
		} else if !verified {
			s.jsonError(w, http.StatusConflict, "files still in use: the folder could not be closed and verified")
			return
		}
	}
	s.caps.revoke(appID, key)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status": "closed_and_verified", "capability_id": capID, "at": time.Now().UTC().Format(time.RFC3339),
	})
}

// closeHolderVerified removes the holder's key and proves it is gone: after
// the grace period the processes still holding files are killed and the
// removal repeated. Only an absent key is a closed folder.
func (s *Server) closeHolderVerified(container, key string, g *capabilityGrant) (bool, error) {
	hf, err := s.launcher.HolderFolders(container)
	if err != nil {
		return false, err
	}
	st, ok := s.holdersOpen.get(key)
	keyID := g.KeyID
	if ok {
		keyID = st.KeyID
	}
	if keyID == "" {
		return true, nil // never loaded in this process, nothing to remove
	}
	time.Sleep(revokeGrace)
	for attempt := 0; attempt < 3; attempt++ {
		status, pids, err := holders.Close(hf.Mount, g.HolderKey, keyID)
		if err == nil && status == holders.Absent {
			s.holdersOpen.drop(key)
			s.releaseHolderBind(hf, g.HolderKey)
			return true, nil
		}
		if err != nil && !errors.Is(err, holders.ErrBusy) {
			return false, err
		}
		s.log.Warn("holder key incompletely removed: killing what holds it",
			zap.String("container", container), zap.String("holder", g.HolderKey), zap.Ints("pids", pids), zap.Int("attempt", attempt+1))
		for _, pid := range pids {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false, nil
}

// ---- the app-facing routes -----------------------------------------------

// handleResourceOpen: POST /api/v1/resources/{resource}/open {subject, uid}.
func (s *Server) handleResourceOpen(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	resource := r.PathValue("resource")
	decl, ok := s.resourceDecl(name, resource)
	if !ok || decl.Kind != launcher.AppStorageKind {
		s.jsonError(w, http.StatusNotFound, "no app_storage resource of that name in the app manifest")
		return
	}
	var body struct {
		Subject string `json:"subject"`
		UID     *int   `json:"uid"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&body); err != nil || body.Subject == "" {
		s.jsonError(w, http.StatusBadRequest, "subject is required")
		return
	}
	appID := s.launcher.ContainerFreezeState(name).AppID
	hf, err := s.launcher.HolderFolders(name)
	if err != nil {
		s.jsonError(w, http.StatusNotImplemented, err.Error())
		return
	}
	g := s.caps.granted(appID, resource, body.Subject)
	switch {
	case g.denied():
		s.writeJSON(w, http.StatusForbidden, map[string]any{"status": "declined", "at": g.At})
		return
	case g != nil && g.Status == "revoked":
		s.writeJSON(w, http.StatusForbidden, map[string]any{"status": "revoked", "at": g.At})
		return
	case !g.usable() || g.HolderKey == "":
		s.askHolder(w, name, appID, resource, body.Subject, decl)
		return
	}
	key := grantKey(appID, resource, body.Subject)
	defer s.holdersOpen.lock(key)()
	hostUID := -1
	if body.UID != nil {
		hostUID = s.launcher.HostUID(*body.UID)
	}
	containerPath := path.Join(holderContainerMount, holders.Dir, g.HolderKey)
	if st, open := s.holdersOpen.get(key); open {
		// The keyring is the superblock's: a volume remounted under the
		// state (a redeploy, 2026-09-18) has no key any more, and "open"
		// would hand the app a folder every write answers ENOKEY on. Trust
		// the state only when the kernel agrees; otherwise load the key
		// again below.
		if ks, err := holders.KeyStatus(hf.Mount, st.KeyID); err != nil || ks != holders.Present {
			s.log.Warn("holder folder recorded open but its key is not loaded; reopening",
				zap.String("container", name), zap.String("holder", g.HolderKey), zap.Error(err))
			s.holdersOpen.drop(key)
			open = false
		}
		if open {
			readOnly, aerr := holderReadOnly(g.Permissions)
			if aerr != nil {
				s.jsonError(w, http.StatusForbidden, aerr.Error())
				return
			}
			// A writable open cannot become read-only in place: a writable
			// fd the app already holds would survive a read-only bind. The
			// folder must be closed (which ends whatever holds its files)
			// before it opens read-only.
			if readOnly && !st.ReadOnly {
				s.jsonError(w, http.StatusConflict, "the folder is open writable; close it before it can open read-only")
				return
			}
			if !readOnly && st.ReadOnly {
				if err := s.unbindHolder(holders.FolderPath(hf.Exposed, g.HolderKey)); err != nil {
					s.jsonError(w, http.StatusInternalServerError, "the folder could not be made writable")
					return
				}
				st.ReadOnly = false
				s.holdersOpen.set(key, st)
			}
			if hostUID >= 0 && hostUID != st.HostUID {
				if err := holders.Chown(hf.Mount, g.HolderKey, hostUID); err != nil {
					s.log.Warn("holder chown", zap.Error(err))
				}
				st.HostUID = hostUID
				s.holdersOpen.set(key, st)
			}
			s.answerOpen(w, name, hf.Mount, g, containerPath)
			return
		}
	}
	if g.WrappedKey == "" {
		// Consent stands but the key is not kept here (the app does not work
		// unattended, or the enclave restarted before it could): the holder's
		// wallet must deliver it again.
		s.askHolder(w, name, appID, resource, body.Subject, decl)
		return
	}
	raw, err := unwrapKey(hf.WrapKey, g.WrappedKey, g.HolderKey+"|"+g.CapabilityID)
	if err != nil {
		s.log.Error("holder key unwrap", zap.String("container", name), zap.String("holder", g.HolderKey), zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, "the stored key could not be unwrapped")
		return
	}
	keyID, readOnly, err := s.unlockHolderFolder(name, hf, g.HolderKey, g.Permissions, raw, false)
	zeroBytes(raw)
	if errors.Is(err, errHolderAccess) {
		s.jsonError(w, http.StatusForbidden, err.Error())
		return
	}
	if err != nil {
		s.log.Error("holder open", zap.String("container", name), zap.String("holder", g.HolderKey), zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, "the folder could not be opened")
		return
	}
	if hostUID >= 0 {
		if err := holders.Chown(hf.Mount, g.HolderKey, hostUID); err != nil {
			s.log.Warn("holder chown", zap.Error(err))
		}
	}
	s.holdersOpen.set(key, holderOpenState{KeyID: keyID, HostUID: hostUID, OpenedAt: time.Now().UTC(), ReadOnly: readOnly,
		Container: name, HolderKey: g.HolderKey, Resource: resource, Subject: body.Subject, CapabilityID: g.CapabilityID,
		Mount: hf.Mount, Exposed: hf.Exposed})
	s.answerOpen(w, name, hf.Mount, g, containerPath)
}

func (s *Server) answerOpen(w http.ResponseWriter, container, mount string, g *capabilityGrant, containerPath string) {
	used, _ := holders.Usage(mount, g.HolderKey)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status": "open", "path": containerPath, "capability_id": g.CapabilityID,
		"used_bytes": used, "unattended": g.Unattended,
	})
}

// askHolder starts (or reports) the ask for a holder whose key the manager
// does not hold, and answers needs_holder.
func (s *Server) askHolder(w http.ResponseWriter, container, appID, resource, subject string, decl capabilityDecl) {
	host := s.launcher.ContainerHostname(container)
	p, outstanding := s.caps.pendingFor(container, resource, subject)
	if !outstanding {
		var err error
		if p, err = s.caps.create(container, appID, appID, subject, decl); err != nil {
			if errors.Is(err, errTooManyAsks) {
				w.Header().Set("Retry-After", "60")
				s.jsonError(w, http.StatusTooManyRequests, err.Error())
				return
			}
			s.jsonError(w, http.StatusInternalServerError, "could not create the capability request")
			return
		}
		p.ServiceURL = "https://" + host + holderCapabilitiesPath
		s.startCapabilityPush(container, subject, p.Nonce, host)
	}
	s.writeJSON(w, http.StatusConflict, map[string]any{
		"status": "needs_holder", "nonce": p.Nonce, "app_host": host,
	})
}

// handleResourceClose: POST /api/v1/resources/{resource}/close {subject}.
func (s *Server) handleResourceClose(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	resource := r.PathValue("resource")
	var body struct {
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&body); err != nil || body.Subject == "" {
		s.jsonError(w, http.StatusBadRequest, "subject is required")
		return
	}
	appID := s.launcher.ContainerFreezeState(name).AppID
	g := s.caps.granted(appID, resource, body.Subject)
	if !g.usable() || g.HolderKey == "" {
		s.jsonError(w, http.StatusNotFound, "no folder for that holder")
		return
	}
	key := grantKey(appID, resource, body.Subject)
	defer s.holdersOpen.lock(key)()
	st, open := s.holdersOpen.get(key)
	if !open {
		s.writeJSON(w, http.StatusOK, map[string]any{"status": "closed"})
		return
	}
	hf, err := s.launcher.HolderFolders(name)
	if err != nil {
		s.jsonError(w, http.StatusNotImplemented, err.Error())
		return
	}
	status, pids, err := holders.Close(hf.Mount, g.HolderKey, st.KeyID)
	if err != nil && !errors.Is(err, holders.ErrBusy) {
		s.jsonError(w, http.StatusInternalServerError, "the folder could not be closed")
		return
	}
	if status != holders.Absent {
		s.writeJSON(w, http.StatusAccepted, map[string]any{"status": "busy", "processes": len(pids)})
		return
	}
	s.holdersOpen.drop(key)
	s.releaseHolderBind(hf, g.HolderKey)
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "closed"})
}

// handleResourceSubjects: GET /api/v1/resources/{resource}/subjects. The
// app's approved subjects, so it keeps no record of who uses it.
func (s *Server) handleResourceSubjects(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	resource := r.PathValue("resource")
	if _, ok := s.resourceDecl(name, resource); !ok {
		s.jsonError(w, http.StatusNotFound, "resource not declared in the app manifest")
		return
	}
	appID := s.launcher.ContainerFreezeState(name).AppID
	out := []map[string]any{}
	for _, g := range s.caps.grantsFor(appID) {
		if g.Resource != resource || g.Subject == "" {
			continue
		}
		out = append(out, map[string]any{
			"subject": g.Subject, "status": g.Status, "capability_id": g.CapabilityID, "at": g.At,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"subjects": out})
}
