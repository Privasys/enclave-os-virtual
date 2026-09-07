package manager

// Resource capabilities (P2 of the drive-as-remote-disk plan): the runtime
// brokers a user's consent for a resource an app declared in its manifest.
//
// The app never holds the capability key, never serves the wallet, and never
// learns how the holder was reached. It asks the manager over loopback:
//
//	POST /api/v1/resources/{resource}/request   {subject, retry}
//	GET  /api/v1/resources/{resource}/status?subject=
//	POST /api/v1/resources/sign                 {payload_b64}
//
// and the manager does the rest: it holds a per-app sealed Ed25519 binding
// key, keeps the pending ask, pushes the holder's wallet through the
// control plane with the app's own attested identity, serves the wallet's
// attested fetch of the ask and receives the outcome on the app's hostname:
//
//	GET  /.well-known/privasys/capability-request?nonce=
//	POST /.well-known/privasys/capability-result
//
// The wire shapes are the wallet's (plans/wallet-resource-capabilities.md).
// The push carries only the nonce and the host; everything that matters,
// including the key being authorised, is learned inside the attested channel.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/enclave-os-virtual/internal/tdx"
	"go.uber.org/zap"
)

const (
	capabilityPendingTTL    = 15 * time.Minute
	capabilityWellKnown     = "/.well-known/privasys/capability-"
	capabilityRequestPath   = "/.well-known/privasys/capability-request"
	capabilityResultPath    = "/.well-known/privasys/capability-result"
	capabilityKindFolder    = "storage.folder"
	capabilityPushType      = "capability-request"
	capabilityStatusPending = "pending"
)

// capabilityAsk is the capability as the wallet renders it: a closed kind
// and permission vocabulary, a label (a value the wallet phrases, never a
// sentence) and an opaque request forwarded verbatim to the resource
// service. The request never names an ownership boundary; the resource
// service derives it from the authenticated holder.
type capabilityAsk struct {
	Kind          string          `json:"kind"`
	Permissions   []string        `json:"permissions"`
	ResourceLabel string          `json:"resource_label"`
	Request       json.RawMessage `json:"request"`
}

// capabilityPending is what the wallet fetches over RA-TLS.
type capabilityPending struct {
	Nonce         string        `json:"nonce"`
	BindingPubkey string        `json:"binding_pubkey"`
	ResourceApp   string        `json:"resource_app"`
	Capability    capabilityAsk `json:"capability"`

	container string
	appID     string
	resource  string
	subject   string
	created   time.Time
}

// capabilityGrant is the outcome the wallet delivered, approved OR denied.
// A denial is kept so the app stops asking; only the user reopens it.
type capabilityGrant struct {
	Resource      string            `json:"resource"`
	CapabilityID  string            `json:"capability_id,omitempty"`
	Status        string            `json:"status"`
	ServiceResult map[string]string `json:"service_result,omitempty"`
	At            time.Time         `json:"at"`
}

func (g *capabilityGrant) usable() bool {
	return g != nil && g.Status == "approved" && g.CapabilityID != ""
}

func (g *capabilityGrant) denied() bool { return g != nil && g.Status == "denied" }

// capabilityBroker holds the per-app binding keys, the outstanding asks and
// the outcomes. State lives under dir on the enclave's encrypted volume
// (per app id, so a redeploy of the same app keeps its key and its
// grants); an empty dir keeps everything in memory (dev/test).
type capabilityBroker struct {
	mu      sync.Mutex
	dir     string
	log     *zap.Logger
	keys    map[string]ed25519.PrivateKey // app id hex -> key
	pending map[string]*capabilityPending // nonce -> ask
	grants  map[string]*capabilityGrant   // grantKey -> outcome
}

func newCapabilityBroker(dir string, log *zap.Logger) *capabilityBroker {
	if log == nil {
		log = zap.NewNop()
	}
	return &capabilityBroker{
		dir:     dir,
		log:     log,
		keys:    map[string]ed25519.PrivateKey{},
		pending: map[string]*capabilityPending{},
		grants:  map[string]*capabilityGrant{},
	}
}

func (b *capabilityBroker) appDir(appID string) string {
	return filepath.Join(b.dir, appID)
}

func grantKey(appID, resource, subject string) string {
	sum := sha256.Sum256([]byte(appID + "\x00" + resource + "\x00" + subject))
	return hex.EncodeToString(sum[:16])
}

// keyLocked returns the app's binding key, loading or generating and sealing
// it on first use. Replacing a key would silently invalidate every
// capability approved for it, so a malformed file is an error, not a reset.
func (b *capabilityBroker) keyLocked(appID string) (ed25519.PrivateKey, error) {
	if k, ok := b.keys[appID]; ok {
		return k, nil
	}
	if b.dir == "" {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		b.keys[appID] = k
		return k, nil
	}
	path := filepath.Join(b.appDir(appID), "binding-key.bin")
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("capability: sealed key %s is %d bytes, expected %d; refusing to replace it", path, len(raw), ed25519.PrivateKeySize)
		}
		b.keys[appID] = ed25519.PrivateKey(raw)
		return b.keys[appID], nil
	case errors.Is(err, os.ErrNotExist):
		_, k, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, genErr
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path+".tmp", k, 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			return nil, err
		}
		b.keys[appID] = k
		b.log.Info("capability binding key generated", zap.String("app_id", appID))
		return k, nil
	default:
		return nil, err
	}
}

// bindingPubkey returns the app's binding public key (standard base64, the
// wallet's encoding), generating the key on first use.
func (b *capabilityBroker) bindingPubkey(appID string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, err := b.keyLocked(appID)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), nil
}

// sign signs payload with the app's binding key (the holder-of-key proof an
// app presents to the resource service; served to the app on request).
func (b *capabilityBroker) sign(appID string, payload []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, err := b.keyLocked(appID)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(k, payload), nil
}

// create registers an ask for one subject and returns it. The nonce is the
// only secret in the flow before the wallet's attested fetch.
func (b *capabilityBroker) create(container, appID, resourceApp, subject string, decl capabilityDecl) (*capabilityPending, error) {
	if subject == "" {
		return nil, errors.New("no acting subject")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	req, err := json.Marshal(map[string]string{"folder": decl.Label})
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	k, err := b.keyLocked(appID)
	if err != nil {
		return nil, err
	}
	b.sweepLocked()
	p := &capabilityPending{
		Nonce:         base64.RawURLEncoding.EncodeToString(raw),
		BindingPubkey: base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)),
		ResourceApp:   resourceApp,
		Capability: capabilityAsk{
			Kind:          decl.Kind,
			Permissions:   append([]string(nil), decl.Permissions...),
			ResourceLabel: decl.Label,
			Request:       req,
		},
		container: container,
		appID:     appID,
		resource:  decl.Name,
		subject:   subject,
		created:   time.Now().UTC(),
	}
	b.pending[p.Nonce] = p
	return p, nil
}

// get returns an unexpired ask by nonce.
func (b *capabilityBroker) get(nonce string) (*capabilityPending, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepLocked()
	p, ok := b.pending[nonce]
	return p, ok
}

func (b *capabilityBroker) sweepLocked() {
	cut := time.Now().UTC().Add(-capabilityPendingTTL)
	for n, p := range b.pending {
		if p.created.Before(cut) {
			delete(b.pending, n)
		}
	}
}

// resolve records the outcome and consumes the nonce (single use: a replayed
// outcome must not overwrite a later, narrower one).
func (b *capabilityBroker) resolve(nonce, status, capabilityID string, result map[string]string) (*capabilityPending, *capabilityGrant, error) {
	b.mu.Lock()
	p, ok := b.pending[nonce]
	if !ok {
		b.mu.Unlock()
		return nil, nil, errors.New("unknown or expired capability request")
	}
	delete(b.pending, nonce)
	g := &capabilityGrant{
		Resource:      p.resource,
		CapabilityID:  capabilityID,
		Status:        status,
		ServiceResult: result,
		At:            time.Now().UTC(),
	}
	key := grantKey(p.appID, p.resource, p.subject)
	b.grants[key] = g
	b.mu.Unlock()
	if err := b.persist(p.appID, key, g); err != nil {
		// The outcome holds for this process either way; failing the wallet's
		// delivery would tell the holder their decision was lost when it was not.
		b.log.Warn("capability outcome not persisted (holds for this run)", zap.String("app_id", p.appID), zap.Error(err))
	}
	return p, g, nil
}

// granted returns the recorded outcome for (app, resource, subject), if any.
func (b *capabilityBroker) granted(appID, resource, subject string) *capabilityGrant {
	if subject == "" {
		return nil
	}
	key := grantKey(appID, resource, subject)
	b.mu.Lock()
	defer b.mu.Unlock()
	if g, ok := b.grants[key]; ok {
		return g
	}
	if b.dir == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(b.appDir(appID), "grants", key+".json"))
	if err != nil {
		return nil
	}
	var g capabilityGrant
	if json.Unmarshal(raw, &g) != nil {
		return nil
	}
	b.grants[key] = &g
	return &g
}

func (b *capabilityBroker) persist(appID, key string, g *capabilityGrant) error {
	if b.dir == "" {
		return nil
	}
	path := filepath.Join(b.appDir(appID), "grants", key+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// capabilityDecl is the manifest declaration the broker acts on (mirrors
// launcher.ResourceDecl without importing it into the wire types).
type capabilityDecl struct {
	Kind        string
	Name        string
	Label       string
	Permissions []string
}

// ---- App-facing loopback endpoints -------------------------------------

// resourceDecl finds the calling container's declaration for {resource}.
func (s *Server) resourceDecl(container, resource string) (capabilityDecl, bool) {
	for _, d := range s.launcher.ContainerResourceDecls(container) {
		if d.Name == resource {
			label := d.Label
			if label == "" {
				label = d.Name
			}
			return capabilityDecl{Kind: d.Kind, Name: d.Name, Label: label, Permissions: d.Permissions}, true
		}
	}
	return capabilityDecl{}, false
}

// resourceAppFor names the resource service for a capability kind by
// IDENTITY (the wallet resolves it; a URL in the payload would let an app
// point the holder anywhere).
func (s *Server) resourceAppFor(kind string) string {
	if kind == capabilityKindFolder {
		return s.cfg.StorageResourceApp
	}
	return ""
}

// handleResourceRequest starts (or reports) an ask for the calling
// container: POST /api/v1/resources/{resource}/request {subject, retry}.
func (s *Server) handleResourceRequest(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	resource := r.PathValue("resource")
	decl, ok := s.resourceDecl(name, resource)
	if !ok {
		s.jsonError(w, http.StatusNotFound, "resource not declared in the app manifest")
		return
	}
	var body struct {
		Subject string `json:"subject"`
		Retry   bool   `json:"retry"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&body); err != nil || body.Subject == "" {
		s.jsonError(w, http.StatusBadRequest, "subject is required")
		return
	}
	appID := s.launcher.ContainerFreezeState(name).AppID
	if appID == "" {
		s.jsonError(w, http.StatusServiceUnavailable, "container has no platform app id")
		return
	}
	resourceApp := s.resourceAppFor(decl.Kind)
	if resourceApp == "" {
		s.jsonError(w, http.StatusNotImplemented, "no resource service for kind "+decl.Kind)
		return
	}
	if g := s.caps.granted(appID, resource, body.Subject); g != nil {
		if g.usable() {
			s.writeJSON(w, http.StatusOK, map[string]any{
				"status": "already_granted", "capability_id": g.CapabilityID,
				"service_result": g.ServiceResult, "at": g.At,
			})
			return
		}
		// A refusal stands until the user reopens it: retry is the user
		// changing their mind, never the app trying again.
		if g.denied() && !body.Retry {
			s.writeJSON(w, http.StatusOK, map[string]any{"status": "declined", "at": g.At})
			return
		}
	}
	p, err := s.caps.create(name, appID, resourceApp, body.Subject, decl)
	if err != nil {
		s.log.Warn("capability request failed", zap.String("container", name), zap.Error(err))
		s.jsonError(w, http.StatusInternalServerError, "could not create the capability request")
		return
	}
	host := s.launcher.ContainerHostname(name)
	go s.pushCapabilityRequest(name, body.Subject, p.Nonce, host)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"status": capabilityStatusPending, "nonce": p.Nonce, "app_host": host,
	})
}

// handleResourceStatus: GET /api/v1/resources/{resource}/status?subject=
func (s *Server) handleResourceStatus(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	resource := r.PathValue("resource")
	decl, ok := s.resourceDecl(name, resource)
	if !ok {
		s.jsonError(w, http.StatusNotFound, "resource not declared in the app manifest")
		return
	}
	appID := s.launcher.ContainerFreezeState(name).AppID
	g := s.caps.granted(appID, resource, r.URL.Query().Get("subject"))
	out := map[string]any{
		"persistent":   g.usable(),
		"declined":     g.denied(),
		"kind":         decl.Kind,
		"permissions":  decl.Permissions,
		"label":        decl.Label,
		"resource_app": s.resourceAppFor(decl.Kind),
	}
	if g.usable() {
		out["capability_id"] = g.CapabilityID
		out["service_result"] = g.ServiceResult
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleResourceSign returns the app's holder-of-key proof over a payload:
// POST /api/v1/resources/sign {payload_b64} -> {signature_b64, pubkey_b64}.
// The key never leaves the manager; the app asks for each proof.
func (s *Server) handleResourceSign(w http.ResponseWriter, r *http.Request) {
	name, ok := s.containerFromRequest(w, r)
	if !ok {
		return
	}
	if len(s.launcher.ContainerResourceDecls(name)) == 0 {
		s.jsonError(w, http.StatusNotFound, "app declares no resources")
		return
	}
	var body struct {
		PayloadB64 string `json:"payload_b64"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&body); err != nil {
		s.jsonError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(body.PayloadB64)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "payload_b64 must be standard base64")
		return
	}
	appID := s.launcher.ContainerFreezeState(name).AppID
	sig, err := s.caps.sign(appID, payload)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "signing failed")
		return
	}
	pub, _ := s.caps.bindingPubkey(appID)
	s.writeJSON(w, http.StatusOK, map[string]string{
		"signature_b64": base64.StdEncoding.EncodeToString(sig),
		"pubkey_b64":    pub,
	})
}

// ---- Wallet-facing endpoints on the app's hostname ----------------------

// serveCapabilityWellKnown answers the wallet on an app host. Only asks
// created for THIS container are visible on its hostname.
func (s *Server) serveCapabilityWellKnown(w http.ResponseWriter, r *http.Request, container string) {
	switch {
	case r.URL.Path == capabilityRequestPath && r.Method == http.MethodGet:
		p, ok := s.caps.get(r.URL.Query().Get("nonce"))
		if !ok || p.container != container {
			// Unknown and expired are deliberately indistinguishable.
			s.jsonError(w, http.StatusNotFound, "no such capability request")
			return
		}
		s.writeJSON(w, http.StatusOK, p)
	case r.URL.Path == capabilityResultPath && r.Method == http.MethodPost:
		var body struct {
			Nonce         string            `json:"nonce"`
			Status        string            `json:"status"`
			CapabilityID  string            `json:"capability_id"`
			ServiceResult map[string]string `json:"service_result"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&body); err != nil {
			s.jsonError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if body.Status != "approved" && body.Status != "denied" {
			s.jsonError(w, http.StatusBadRequest, "status must be approved or denied")
			return
		}
		// The nonce is the authorisation: this route carries no holder
		// credential by design. A forged result can only point the app at
		// coordinates bound to a key it does not hold, which fails on first
		// use; so it costs a failed call and a log line, not access.
		if p, ok := s.caps.get(body.Nonce); !ok || p.container != container {
			s.jsonError(w, http.StatusNotFound, "unknown or expired capability request")
			return
		}
		p, g, err := s.caps.resolve(body.Nonce, body.Status, body.CapabilityID, body.ServiceResult)
		if err != nil {
			s.jsonError(w, http.StatusNotFound, err.Error())
			return
		}
		s.log.Info("capability outcome recorded",
			zap.String("container", p.container), zap.String("resource", p.resource),
			zap.String("status", g.Status), zap.String("capability_id", g.CapabilityID))
		s.writeJSON(w, http.StatusOK, map[string]string{"status": g.Status})
	default:
		s.jsonError(w, http.StatusNotFound, "not found")
	}
}

// ---- Push through the control plane -------------------------------------

// pushCapabilityRequest asks the control plane to push the holder's wallet,
// authenticated with the app's own attested identity (the same triple an
// app presents itself: leaf, fresh challenge, quote committing to both).
// Best effort: the ask is also reachable from the app's UI by nonce + host.
func (s *Server) pushCapabilityRequest(container, subject, nonce, host string) {
	if s.cfg.MgmtBaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	leafB64, chB64, evB64, err := s.headerIdentity(container)
	if err != nil {
		s.log.Warn("capability push: identity", zap.String("container", container), zap.Error(err))
		return
	}
	body, _ := json.Marshal(map[string]any{
		"sub":     subject,
		"type":    capabilityPushType,
		"payload": map[string]string{"nonce": nonce, "app_host": host},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(s.cfg.MgmtBaseURL, "/")+"/api/v1/notify", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Privasys-App-Identity", leafB64)
	req.Header.Set("X-Privasys-App-Challenge", chB64)
	req.Header.Set("X-Privasys-App-Evidence", evB64)
	resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
	if err != nil {
		s.log.Warn("capability push failed", zap.String("container", container), zap.Error(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		s.log.Warn("capability push refused", zap.String("container", container),
			zap.Int("status", resp.StatusCode), zap.String("body", strings.TrimSpace(string(b))))
		return
	}
	s.log.Info("capability request pushed", zap.String("container", container), zap.String("host", host))
}

// headerIdentity mints the container's attested app identity for one
// control-plane call: leaf DER, a fresh challenge (8 bytes unix seconds ||
// 24 random) and a quote over ClientReportData(SPKI, challenge,
// HeaderIdentityHctx). Mirrors ra-tls-clients' HeaderEvidence.
func (s *Server) headerIdentity(container string) (leafB64, challengeB64, evidenceB64 string, err error) {
	certPEM, _, err := s.launcher.MintIdentity(container)
	if err != nil {
		return "", "", "", err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", "", "", errors.New("minted identity is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", "", err
	}
	challenge := make([]byte, ratls.ContextLen)
	binary.BigEndian.PutUint64(challenge[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(challenge[8:]); err != nil {
		return "", "", "", err
	}
	rd := ratls.ClientReportData(leaf.RawSubjectPublicKeyInfo, challenge, ratls.HeaderIdentityHctx[:], nil)
	var rd64 [64]byte
	copy(rd64[:], rd)
	quote, err := tdx.GetQuote(rd64)
	if err != nil {
		return "", "", "", err
	}
	return base64.StdEncoding.EncodeToString(block.Bytes),
		base64.StdEncoding.EncodeToString(challenge),
		base64.StdEncoding.EncodeToString(quote), nil
}
