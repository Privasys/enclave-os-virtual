// Package appmanifest reads an app's MCP manifest from the OCI image label
// org.privasys.manifest, the same label the control plane reads at detect
// time. The label lives in the image config blob, so it is covered by the
// digest-pinned image digest the launcher verifies and attests (Config
// Merkle Tree leaf container.image_digest, OID 3.2): what the runtime
// enforces from it (prices, guarded routes, the attribute provider) is
// always measured.
package appmanifest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Label is the OCI image label carrying the manifest.
const Label = "org.privasys.manifest"

// Tool is one tool of the manifest, with the fields the runtime enforces.
type Tool struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Endpoint  string `json:"endpoint"`
	XPrivasys struct {
		// Price is the tool's fee rule, read by apifees.
		Price json.RawMessage `json:"price"`
		// Auth is the route's access policy, in the grammar of Enclave OS
		// Mini's WIT @auth: public, authenticated, owner or role(a, b).
		Auth string `json:"auth"`
	} `json:"x-privasys"`
}

// Doc is the manifest, as far as the runtime reads it.
type Doc struct {
	Tools     []Tool `json:"tools"`
	Configure struct {
		Endpoint string `json:"endpoint"`
	} `json:"configure"`
	XPrivasys struct {
		// AttributeProvider is the marketplace namespace this app attests
		// for ("privasys" for the identity verifier). A disclosure voucher
		// names the provider whose work it pays for, and only an app that
		// declares that namespace may consume one. It is in the manifest
		// because the label is measured; a provider-to-app mapping from the
		// control plane would make the runtime enforce something nobody
		// could verify.
		AttributeProvider string `json:"attribute_provider"`
	} `json:"x-privasys"`
}

// Decode reads the label in either encoding in the wild: raw JSON, or
// base64-encoded JSON.
func Decode(raw string) (*Doc, error) {
	var doc Doc
	if err := json.Unmarshal([]byte(raw), &doc); err == nil {
		return &doc, nil
	}
	decoded, derr := base64.StdEncoding.DecodeString(raw)
	if derr != nil {
		return nil, errors.New("appmanifest: the label is neither JSON nor base64 JSON")
	}
	if err := json.Unmarshal(decoded, &doc); err != nil {
		return nil, fmt.Errorf("appmanifest: label parse: %w", err)
	}
	return &doc, nil
}

// AttributeProvider is the marketplace namespace an app attests for, or ""
// when it declares none (or the label does not decode). An app that
// declares none is not an attester and must never consume a disclosure
// voucher.
func AttributeProvider(raw string) string {
	doc, err := Decode(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(doc.XPrivasys.AttributeProvider)
}
