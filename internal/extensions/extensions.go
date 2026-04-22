// Package extensions writes per-hostname OID extension files that
// Caddy's RA-TLS module reads during certificate issuance.
//
// Each file is a JSON object with static extensions and an optional
// upstream URL for dynamic (container-provided) extensions:
//
//	{
//	   "extensions": [
//	     {"oid": "1.3.6.1.4.1.65230.1.1", "value": "<base64>"},
//	     ...
//	   ],
//	   "upstream": "http://127.0.0.1:8080"
//	}
//
// The manager writes these files to the extensions directory (e.g.
// /run/manager/extensions/) before adding the corresponding Caddy route.
// The RA-TLS module reads <extensions_dir>/<hostname>.json on every cert
// issuance, appending the static extensions alongside the hardware
// attestation quote. If upstream is set, it also calls
// GET <upstream>/.well-known/attestation-extensions to pull any custom OIDs
// the container wants to include (the Virtual equivalent of enclave-os-mini's
// custom_oids() trait method).
package extensions

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// jsonExtension matches the format expected by the RA-TLS module's extensions_dir.
type jsonExtension struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
}

// extensionsFile is the top-level JSON structure for extension files.
type extensionsFile struct {
	Extensions []jsonExtension `json:"extensions"`
	Upstream   string          `json:"upstream,omitempty"`
}

// Write serialises the given pkix.Extension slice to
// <dir>/<hostname>.json.  The directory is created if it does not exist.
// If upstream is non-empty it is included so the RA-TLS module can pull
// dynamic OID extensions from the container at cert issuance time.
//
// The file is written atomically (write to temp + rename) to avoid
// a partial read during certificate issuance.
func Write(dir, hostname string, exts []pkix.Extension, upstream string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("extensions: mkdir %q: %w", dir, err)
	}

	entries := make([]jsonExtension, 0, len(exts))
	for _, ext := range exts {
		entries = append(entries, jsonExtension{
			OID:   oidString(ext.Id),
			Value: base64.StdEncoding.EncodeToString(ext.Value),
		})
	}

	file := extensionsFile{
		Extensions: entries,
		Upstream:   upstream,
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("extensions: marshal: %w", err)
	}

	target := filepath.Join(dir, hostname+".json")
	tmp := target + ".tmp"

	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("extensions: write tmp: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("extensions: rename %q → %q: %w", tmp, target, err)
	}
	return nil
}

// Remove deletes the extension file for the given hostname.  It is not
// an error if the file does not exist.
func Remove(dir, hostname string) error {
	target := filepath.Join(dir, hostname+".json")
	err := os.Remove(target)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("extensions: remove %q: %w", target, err)
	}
	return nil
}

// oidString formats an asn1.ObjectIdentifier as dot-notation.
func oidString(oid asn1.ObjectIdentifier) string {
	s := ""
	for i, v := range oid {
		if i > 0 {
			s += "."
		}
		s += fmt.Sprintf("%d", v)
	}
	return s
}
