package manager

// Direct domains: adopter hostnames whose TLS ends in this enclave with a
// publicly trusted certificate (internal/directtls, launcher/direct.go). The
// owner names them in the signed app policy; the control plane reads this
// status before it lets a gateway splice a name here, and checks the
// adopter's CAA record against the account it reports.

import (
	"encoding/json"
	"net/http"
)

// handleDirectStatus handles GET /api/v1/containers/{name}/direct.
func (s *Server) handleDirectStatus(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "container name is required")
		return
	}
	if !s.launcher.DirectSupported() {
		s.jsonError(w, http.StatusNotFound, "direct domains are not configured on this host")
		return
	}
	st, err := s.launcher.DirectStatus(name)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}
