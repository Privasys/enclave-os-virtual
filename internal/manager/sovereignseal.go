package manager

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// handleSovereignSeal serves POST /api/v1/containers/{name}/sovereign-seal:
// the calling container's version-bound sovereign sealing key S_N (the
// sovereign-data framework, Phase 1). The wrapper (requireContainerSelf)
// has already bound {name} to the caller's PRIVASYS_CONTAINER_TOKEN, so
// an app can only ever obtain its OWN key, and the launcher derives it
// solely for the image digest that container is currently running — an
// upgraded image receives a different S_N, which is what makes an app
// upgrade a consent boundary for user-owned data.
//
// The response carries the key hex, the image digest it is bound to (the
// app should record it beside anything it seals, so a later version can
// name which S_N a blob needs), and the derivation version label.
func (s *Server) handleSovereignSeal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	derive := s.sovereignSealFn
	if derive == nil {
		derive = s.launcher.SovereignSealKey
	}
	key, digest, err := derive(name)
	if err != nil {
		s.log.Warn("sovereign-seal refused", zap.String("name", name), zap.Error(err))
		s.jsonError(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"seal_key":     hex.EncodeToString(key),
		"image_digest": hex.EncodeToString(digest),
		"version":      "privasys-sovereign-seal/v1",
	})
}
