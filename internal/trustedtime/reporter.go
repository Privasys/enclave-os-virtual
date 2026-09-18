package trustedtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// incidentBody is what the runtime POSTs to the monitor's incident URL.
type incidentBody struct {
	EnclaveID  string `json:"enclave_id"`
	Reason     string `json:"reason"`
	HostTimeMs int64  `json:"host_time_ms"`
	FloorMs    int64  `json:"floor_ms"`
	NTSTimeMs  int64  `json:"nts_time_ms"`
	Nonce      string `json:"nonce"`
}

// receipt is the monitor's signed acknowledgement of an incident.
type receipt struct {
	IncidentID string `json:"incident_id"`
	Nonce      string `json:"nonce"`
	KeyID      string `json:"key_id"`
	Sig        string `json:"sig"`
}

// ReceiptSignedBytes are the bytes the monitor signs for a receipt. nonce is
// the base64url string exactly as the runtime sent it.
func ReceiptSignedBytes(enclaveID, nonce, incidentID string) []byte {
	return []byte("privasys-clock-receipt/v1\n" + enclaveID + "\n" + nonce + "\n" + incidentID)
}

// HTTPReporter posts incidents over plain HTTPS (system roots). TLS only
// carries the report: what authenticates the answer is the receipt signature
// under the pinned monitor key, bound to a fresh 32-byte nonce.
type HTTPReporter struct {
	Client *http.Client
}

// NewHTTPReporter returns a reporter with a default client. The caller's
// context bounds each report.
func NewHTTPReporter() *HTTPReporter {
	return &HTTPReporter{Client: &http.Client{}}
}

// Report implements Reporter.
func (r *HTTPReporter) Report(ctx context.Context, cfg MonitorConfig, inc Incident) error {
	pub, err := cfg.publicKey()
	if err != nil {
		return err
	}
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(n[:])
	body, _ := json.Marshal(incidentBody{
		EnclaveID:  cfg.EnclaveID,
		Reason:     inc.Reason,
		HostTimeMs: inc.HostTimeMs,
		FloorMs:    inc.FloorMs,
		NTSTimeMs:  inc.NTSTimeMs,
		Nonce:      nonce,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.IncidentURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("monitor answered %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var rc receipt
	if err := json.Unmarshal(rb, &rc); err != nil {
		return fmt.Errorf("malformed receipt: %w", err)
	}
	return verifyReceipt(pub, cfg, nonce, rc)
}

func verifyReceipt(pub ed25519.PublicKey, cfg MonitorConfig, nonce string, rc receipt) error {
	if rc.Nonce != nonce {
		return errors.New("receipt is for another nonce")
	}
	if !strings.EqualFold(rc.KeyID, cfg.MonitorKeyID) {
		return fmt.Errorf("receipt signed with key %q, not the pinned %q", rc.KeyID, cfg.MonitorKeyID)
	}
	if rc.IncidentID == "" {
		return errors.New("receipt carries no incident_id")
	}
	sig, err := b64Decode(rc.Sig)
	if err != nil || !ed25519.Verify(pub, ReceiptSignedBytes(cfg.EnclaveID, nonce, rc.IncidentID), sig) {
		return errors.New("receipt signature does not verify under the pinned monitor key")
	}
	return nil
}
