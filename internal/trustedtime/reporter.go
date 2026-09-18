package trustedtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
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

// RATLSALPN is the ALPN an RA-TLS client advertises. The platform gateway
// splices connections that carry it straight through to the enclave, which
// terminates TLS itself; connections without it are terminated at the
// gateway and re-dialled inward in plaintext.
const RATLSALPN = "privasys-ratls/1"

// HTTPReporter posts incidents to the monitor. What authenticates the answer
// is the receipt signature under the pinned monitor key, bound to a fresh
// 32-byte nonce; TLS only carries the report.
type HTTPReporter struct {
	Client *http.Client
}

// NewHTTPReporter returns a reporter whose client reaches the monitor
// enclave end to end. The caller's context bounds each report.
//
// The client advertises RATLSALPN so the gateway splices the connection to
// the monitor enclave. Without it the gateway terminates TLS and forwards the
// request in plaintext, and the monitor's runtime refuses plaintext /api/* on
// that leg (sealed transport required): no receipt could ever arrive, and a
// host behind the floor would fail closed for good.
//
// The certificate the monitor presents is an RA-TLS certificate chained to
// the platform's own CA, not a web PKI one, so web PKI verification is
// skipped. That costs nothing here: the connection stays encrypted, and the
// receipt signature under the pinned key is the authentication. A party in
// the middle can drop or delay a report (which fails closed), never forge a
// receipt.
func NewHTTPReporter() *HTTPReporter {
	return &HTTPReporter{Client: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{RATLSALPN, "http/1.1"},
			InsecureSkipVerify: true, // see above: the receipt signature authenticates
		},
		// The marker goes first so the gateway splices; http/1.1 follows
		// because the enclave's TLS server does not list the marker, and TLS
		// 1.3 aborts a handshake with no common protocol. No h2: the exchange
		// is HTTP/1.1 over the spliced connection.
		ForceAttemptHTTP2: false,
	}}}
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
