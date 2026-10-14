// Package surfaces reads and enforces an app's declared surfaces: which of
// its routes may be served in the CLEAR on the gateway-terminated leg.
//
// Everything an app serves is private unless it says otherwise. The gateway
// terminates public TLS so browsers and third-party machines get a trusted
// certificate, and on that leg the gateway, an unattested VM, reads whatever
// is not sealed. So the runtime refuses plaintext app requests there
// (403 sealed-transport-required) except for two declared surfaces:
//
//   - static: GET/HEAD path prefixes for the app's own browser shell
//     (measured code, no user data), so the page can load before a sealed
//     session exists;
//   - public: explicit method+path routes for data the app deliberately
//     publishes, or inbound events from senders that cannot run our
//     transport (webhooks, OAuth redirects, federation peers).
//
// The declaration lives in the app's manifest (privasys.json, carried by the
// measured org.privasys.manifest image label), with the older
// org.privasys.static-unsealed-prefixes label kept as an alias for the static
// list. Because the label is inside the digest-pinned image config, the
// surfaces are part of the attested identity: a verifier reads off the image
// exactly what the app serves in the clear, and changing them changes the
// digest the owner approves.
//
// A request on a declared surface is served anonymous by construction (the
// manager keeps only an allow-list of headers in both directions, never
// asserts an identity, and refuses prices), so a mistake in app code cannot
// turn a public route into a channel for account data.
package surfaces

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// StaticLabel is the measured image label by which an app opted its public
// browser-UI shell paths out of require-sealed before the manifest carried
// surfaces. Comma-separated path prefixes (an entry of exactly "/" matches
// the root document only). Kept as an alias for surfaces.static.
const StaticLabel = "org.privasys.static-unsealed-prefixes"

// Route is one public route: a method and a path, exact unless the path
// ends in "/" (then a prefix). Headers lists extra request headers the
// route needs beyond the default allow-list, typically a webhook sender's
// signature header.
type Route struct {
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Headers []string `json:"headers,omitempty"`
}

// Prefix reports whether the route matches every path under Path.
func (r Route) Prefix() bool { return strings.HasSuffix(r.Path, "/") }

// Matches reports whether the route covers method+path.
func (r Route) Matches(method, path string) bool {
	if !strings.EqualFold(r.Method, method) {
		return false
	}
	return r.coversPath(path)
}

func (r Route) coversPath(path string) bool {
	if r.Prefix() {
		return strings.HasPrefix(path, r.Path)
	}
	return path == r.Path
}

// Limits bounds the clear leg per client address.
type Limits struct {
	// RPS is the sustained request rate per client; Burst the bucket size.
	RPS   float64 `json:"rps,omitempty"`
	Burst int     `json:"burst,omitempty"`
}

// Default rate limit for a public or static route per client address: a
// trusted certificate on an unauthenticated route is otherwise a free
// denial-of-service surface.
const (
	DefaultRPS   = 10
	DefaultBurst = 50
)

// Surfaces is an app's declaration of what it serves in the clear.
type Surfaces struct {
	// Static prefixes: GET/HEAD only, never /api.
	Static []string `json:"static,omitempty"`
	// Public routes: explicit method and path pairs.
	Public []Route `json:"public,omitempty"`
	// CORS is "*" (public routes open to any origin, no credentials) or
	// "same-origin" (the default: no cross-origin headers at all).
	CORS   string `json:"cors,omitempty"`
	Limits Limits `json:"limits,omitempty"`
}

// Empty reports whether nothing is declared.
func (s *Surfaces) Empty() bool {
	return s == nil || (len(s.Static) == 0 && len(s.Public) == 0)
}

// OpenCORS reports whether public routes answer any origin.
func (s *Surfaces) OpenCORS() bool { return s != nil && s.CORS == "*" }

// RPS and Burst return the declared limits or the defaults.
func (s *Surfaces) RPS() float64 {
	if s == nil || s.Limits.RPS <= 0 {
		return DefaultRPS
	}
	return s.Limits.RPS
}

func (s *Surfaces) Burst() int {
	if s == nil || s.Limits.Burst <= 0 {
		return DefaultBurst
	}
	return s.Limits.Burst
}

// IsStatic reports whether path is under a declared static prefix. The
// data plane is never static: /api* is excluded whatever is declared, and a
// lone "/" matches the root document only.
func (s *Surfaces) IsStatic(path string) bool {
	if s == nil || isAPI(path) {
		return false
	}
	for _, p := range s.Static {
		if p == "" {
			continue
		}
		if p == "/" {
			if path == "/" {
				return true
			}
			continue
		}
		if path == p || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// PublicRoute returns the declared route covering method+path, if any.
func (s *Surfaces) PublicRoute(method, path string) (Route, bool) {
	if s == nil {
		return Route{}, false
	}
	for _, r := range s.Public {
		if r.Matches(method, path) {
			return r, true
		}
	}
	return Route{}, false
}

// PublicMethods lists the declared methods for path (for a CORS preflight),
// sorted, or nothing when no public route covers it.
func (s *Surfaces) PublicMethods(path string) []string {
	if s == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, r := range s.Public {
		if r.coversPath(path) {
			seen[strings.ToUpper(r.Method)] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// PublicHeaders lists the extra request headers declared by routes covering
// path, canonicalised, for the CORS preflight and the request allow-list.
func (s *Surfaces) PublicHeaders(path string) []string {
	if s == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, r := range s.Public {
		if !r.coversPath(path) {
			continue
		}
		for _, h := range r.Headers {
			seen[http.CanonicalHeaderKey(h)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Covers reports whether method+path is served in the clear: a static GET
// or HEAD, or a public route.
func (s *Surfaces) Covers(method, path string) bool {
	if s == nil {
		return false
	}
	if (method == http.MethodGet || method == http.MethodHead) && s.IsStatic(path) {
		return true
	}
	_, ok := s.PublicRoute(method, path)
	return ok
}

// CoversPath reports whether any method of path is served in the clear.
func (s *Surfaces) CoversPath(path string) bool {
	return s != nil && (s.IsStatic(path) || len(s.PublicMethods(path)) > 0)
}

func isAPI(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

var allowedMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodDelete: true, http.MethodPatch: true,
}

// Validate normalises the declaration and refuses what the runtime would
// never serve: a static prefix on the data plane, a public route with an
// unknown method or a relative path, an unknown CORS mode. Every path is
// kept as declared (no trailing-slash games), only methods and header
// names are canonicalised.
func (s *Surfaces) Validate() error {
	if s == nil {
		return nil
	}
	for i, p := range s.Static {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") {
			return fmt.Errorf("surfaces.static[%d]: %q is not an absolute path", i, p)
		}
		if isAPI(p) || strings.HasPrefix(p, "/api") && (p == "/api" || p == "/api/") {
			return fmt.Errorf("surfaces.static[%d]: %q is on the data plane; declare an explicit public route instead", i, p)
		}
		s.Static[i] = p
	}
	for i, r := range s.Public {
		m := strings.ToUpper(strings.TrimSpace(r.Method))
		if !allowedMethods[m] {
			return fmt.Errorf("surfaces.public[%d]: method %q is not one of GET, HEAD, POST, PUT, PATCH, DELETE", i, r.Method)
		}
		p := strings.TrimSpace(r.Path)
		if p == "" || !strings.HasPrefix(p, "/") {
			return fmt.Errorf("surfaces.public[%d]: %q is not an absolute path", i, r.Path)
		}
		if p == "/" {
			return fmt.Errorf("surfaces.public[%d]: a public route cannot be the whole origin; declare the paths", i)
		}
		if strings.HasPrefix(p, "/__privasys/") || strings.HasPrefix(p, "/privasys/session/") {
			return fmt.Errorf("surfaces.public[%d]: %q is a runtime path", i, p)
		}
		hs := make([]string, 0, len(r.Headers))
		for _, h := range r.Headers {
			h = http.CanonicalHeaderKey(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if neverAllowed[h] {
				return fmt.Errorf("surfaces.public[%d]: header %s can never be declared on a public route", i, h)
			}
			hs = append(hs, h)
		}
		s.Public[i] = Route{Method: m, Path: p, Headers: hs}
	}
	switch s.CORS {
	case "", "same-origin", "*":
	default:
		return fmt.Errorf("surfaces.cors: %q is not \"*\" or \"same-origin\"", s.CORS)
	}
	if s.Limits.RPS < 0 || s.Limits.Burst < 0 {
		return fmt.Errorf("surfaces.limits: negative values")
	}
	return nil
}

// neverAllowed are request headers no declaration can add to the clear
// leg's allow-list: credentials and runtime-asserted identity.
var neverAllowed = map[string]bool{
	"Authorization": true, "Cookie": true, "X-App-Auth": true,
	"X-Privasys-Sub": true, "X-Privasys-Spend": true, "X-Privasys-Spend-Proof": true,
	"X-Privasys-Transport": true, "X-Privasys-Edge": true,
}

// AddLegacyStatic unions the static prefixes from the older label into the
// declaration (creating one when the manifest declares none).
func AddLegacyStatic(s *Surfaces, label string) *Surfaces {
	var prefixes []string
	for _, p := range strings.Split(label, ",") {
		if p = strings.TrimSpace(p); p != "" {
			prefixes = append(prefixes, p)
		}
	}
	if len(prefixes) == 0 {
		return s
	}
	if s == nil {
		s = &Surfaces{}
	}
	seen := map[string]bool{}
	for _, p := range s.Static {
		seen[p] = true
	}
	for _, p := range prefixes {
		if !seen[p] {
			s.Static = append(s.Static, p)
			seen[p] = true
		}
	}
	return s
}

// Parse reads the surfaces block of a manifest label (raw JSON or
// base64-encoded JSON, both encodings are in the wild). A manifest without
// the block yields nil, nil. The result is validated.
func Parse(raw string) (*Surfaces, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var doc struct {
		Surfaces *Surfaces `json:"surfaces"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		decoded, derr := base64.StdEncoding.DecodeString(raw)
		if derr != nil {
			return nil, fmt.Errorf("surfaces: manifest label is neither JSON nor base64 JSON: %w", err)
		}
		if err := json.Unmarshal(decoded, &doc); err != nil {
			return nil, fmt.Errorf("surfaces: manifest label parse: %w", err)
		}
	}
	if doc.Surfaces == nil {
		return nil, nil
	}
	if err := doc.Surfaces.Validate(); err != nil {
		return nil, err
	}
	return doc.Surfaces, nil
}

// Conflict is returned when a declaration would put something in the clear
// that must never be: a priced endpoint, or the configure surface.
type Conflict struct{ Reason string }

func (c *Conflict) Error() string { return "surfaces: " + c.Reason }

// CheckPriced refuses a declaration that covers a priced endpoint. A public
// route is anonymous, so nobody could pay; refusing at load is the honest
// version of "unbillable".
func (s *Surfaces) CheckPriced(pricedPaths []string) error {
	if s == nil {
		return nil
	}
	for _, p := range pricedPaths {
		if s.CoversPath(p) {
			return &Conflict{Reason: fmt.Sprintf("priced endpoint %s is declared public; a public route cannot carry a price", p)}
		}
	}
	return nil
}

// CheckConfigAPI refuses a declaration that covers the configure surface,
// which is owner/admin only and needs the bearer a public route strips.
func (s *Surfaces) CheckConfigAPI(method, path string) error {
	if s == nil || path == "" {
		return nil
	}
	if s.Covers(strings.ToUpper(method), path) {
		return &Conflict{Reason: fmt.Sprintf("configure endpoint %s %s is declared public; the configure surface is owner-only", strings.ToUpper(method), path)}
	}
	return nil
}

// Summary is one line for the log and the attestation view.
func (s *Surfaces) Summary() string {
	if s.Empty() {
		return "none"
	}
	parts := make([]string, 0, len(s.Static)+len(s.Public))
	for _, p := range s.Static {
		parts = append(parts, "static "+p)
	}
	for _, r := range s.Public {
		parts = append(parts, r.Method+" "+r.Path)
	}
	return strings.Join(parts, ", ")
}
