package apifees

import (
	"fmt"
	"strings"
)

// Policy is a route's access policy, as a tool's x-privasys.auth declares it.
// It is the grammar of the WIT @auth annotation in Enclave OS Mini, so one
// vocabulary covers both runtimes.
type Policy string

const (
	// PolicyPublic needs nothing from the caller (the default). It does not
	// put a route in the clear: that is surfaces.public.
	PolicyPublic Policy = "public"
	// PolicyAuthenticated needs a caller the runtime can name: a verified
	// platform bearer, or the subject of a sealed session.
	PolicyAuthenticated Policy = "authenticated"
	// PolicyOwner needs the app's owner or admin, exactly like the configure
	// endpoint.
	PolicyOwner Policy = "owner"
	// PolicyRole needs a verified platform bearer carrying one of Roles,
	// compared as written.
	PolicyRole Policy = "role"
)

// RouteAuth is one guarded route: a tool's endpoint and its policy.
type RouteAuth struct {
	Tool   string
	Path   string
	Policy Policy
	Roles  []string
}

// ParseAuthAnnotation reads an x-privasys.auth value: public,
// authenticated, owner or role(a, b, ...), case-insensitively and with
// optional spaces. Anything else, and a role() naming no role, is an error:
// the app is refused rather than run under a policy its developer did not
// write.
func ParseAuthAnnotation(value string) (Policy, []string, error) {
	v := strings.TrimSpace(value)
	switch {
	case strings.EqualFold(v, "public"):
		return PolicyPublic, nil, nil
	case strings.EqualFold(v, "authenticated"):
		return PolicyAuthenticated, nil, nil
	case strings.EqualFold(v, "owner"):
		return PolicyOwner, nil, nil
	}
	if len(v) >= 4 && strings.EqualFold(v[:4], "role") {
		rest := strings.TrimSpace(v[4:])
		if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
			var roles []string
			for _, r := range strings.Split(rest[1:len(rest)-1], ",") {
				if r = strings.TrimSpace(r); r != "" {
					roles = append(roles, r)
				}
			}
			if len(roles) == 0 {
				return "", nil, fmt.Errorf("auth %q names no role", v)
			}
			return PolicyRole, roles, nil
		}
	}
	return "", nil, fmt.Errorf("unrecognised auth %q (expected public, authenticated, owner or role(...))", v)
}

// ParseRouteAuth reads every tool's access policy from the raw
// org.privasys.manifest label. Public tools and tools without an annotation
// are left out: they need nothing. The configure endpoint is left out too,
// because it has its own owner gate whatever it declares. An annotation that
// does not parse, or an annotated tool without an absolute endpoint, is an
// error, so the load is refused rather than run with a route unguarded.
func ParseRouteAuth(raw string) ([]RouteAuth, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	doc, err := decodeManifest(raw)
	if err != nil {
		return nil, err
	}
	var out []RouteAuth
	for _, t := range doc.Tools {
		if strings.TrimSpace(t.XPrivasys.Auth) == "" {
			continue
		}
		policy, roles, err := ParseAuthAnnotation(t.XPrivasys.Auth)
		if err != nil {
			return nil, fmt.Errorf("apifees: tool %q: %w", t.Name, err)
		}
		if policy == PolicyPublic {
			continue
		}
		p := strings.TrimSpace(t.Endpoint)
		if p == "" || !strings.HasPrefix(p, "/") || p == "/" {
			return nil, fmt.Errorf("apifees: tool %q declares auth %q but its endpoint %q is not a route", t.Name, t.XPrivasys.Auth, t.Endpoint)
		}
		if p == doc.Configure.Endpoint {
			continue
		}
		out = append(out, RouteAuth{Tool: t.Name, Path: p, Policy: policy, Roles: roles})
	}
	return out, nil
}
