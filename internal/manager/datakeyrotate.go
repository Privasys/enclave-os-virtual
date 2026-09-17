package manager

// Moving this enclave's /data DEK onto another vault constellation.
//
// A prod confidential VM has no operator shell — that is the point of it — so
// this cannot be a command someone runs on the box. The control plane drives
// it over the manager's authenticated API, exactly as it drives a container
// volume's KEK rotation, and the work itself happens in-TD where the quote and
// the LUKS header are.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/auth"
	"github.com/Privasys/enclave-os-virtual/internal/bootstrap"
)

// dataDeviceCandidates mirrors luks-setup's discovery order: the GCE
// device-name=data disk first, then the legacy partlabel.
var dataDeviceCandidates = []string{
	"/dev/disk/by-id/google-data",
	"/dev/disk/by-partlabel/data",
}

func findDataDevice() (string, error) {
	for _, c := range dataDeviceCandidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("no /data device found (looked for %v)", dataDeviceCandidates)
}

// handleRotateDataKey handles POST /api/v1/data-key/rotate. Manager-role only.
//
// Body is the grant bundle the control plane minted for THIS enclave
// (POST /api/v1/admin/enclaves/{id}/data-key/rotate-grant). The volume stays
// openable throughout and the call is idempotent — a volume already on the
// target constellation reports ok with rotated=false. See
// bootstrap.RotateDataDEK for the ordering and why the material is fresh.
func (s *Server) handleRotateDataKey(w http.ResponseWriter, r *http.Request) {
	result := r.Context().Value(authResultKey).(*auth.AuthResult)
	if !result.HasManagerAccess() {
		s.jsonError(w, http.StatusForbidden, "manager role required to rotate the data key")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, "could not read the request body")
		return
	}
	var bundle bootstrap.RotateBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		s.jsonError(w, http.StatusBadRequest, "body is not a rotate bundle: "+err.Error())
		return
	}
	device, err := findDataDevice()
	if err != nil {
		s.jsonError(w, http.StatusConflict, err.Error())
		return
	}
	before, _ := bootstrap.DataKeyConstellation(r.Context(), device)
	if err := bootstrap.RotateDataDEK(r.Context(), s.log, bootstrap.Config{}, device, &bundle); err != nil {
		s.log.Error("data-key rotation failed", zap.Error(err))
		s.jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	after, _ := bootstrap.DataKeyConstellation(r.Context(), device)
	s.log.Info("data-key rotated", zap.String("from", before), zap.String("to", after))
	s.writeJSON(w, http.StatusOK, map[string]any{
		"device":  device,
		"from":    before,
		"to":      after,
		"rotated": before != after,
	})
}
