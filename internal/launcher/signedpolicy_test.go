package launcher

import (
	"encoding/json"
	"testing"

	"go.uber.org/zap"

	"enclave-os-mini/clients/go/ratls"
)

type fakeSigned struct {
	callers, deps json.RawMessage
	owners        []string
	asked         string
}

func (f *fakeSigned) SignedFor(appID string) (json.RawMessage, json.RawMessage, []string) {
	f.asked = appID
	return f.callers, f.deps, f.owners
}

// A load carries the control plane's unsigned copy of callers, dependencies
// and owners; for a pinned app the owner's signed document must win, or every
// redeploy, boot replay and reconciler load would restore stale pins.
func TestLoadUsesTheSignedPolicyOverTheRequest(t *testing.T) {
	l := &Launcher{log: zap.NewNop()}
	src := &fakeSigned{
		callers: json.RawMessage(`{"entries":[{"app_id":"6739a7c1fb554ac49c1a89f2609a972f","measurements":[{"tdx":{"rtmr1":"new"}}]}],"platforms":["c513b146"]}`),
		deps:    json.RawMessage(`{"entries":[{"app_id":"02104572ca2f41e8ae2d24c0294e6f5e"}]}`),
		owners:  []string{"owner-sub"},
	}
	l.SetSignedPolicy(src)
	req := LoadRequest{
		Name:                    "drive-demo",
		AppId:                   "02104572-ca2f-41e8-ae2d-24c0294e6f5e",
		IngressAllowedCallers:   &ratls.DependencySet{Entries: []ratls.DependencyEntry{{AppID: "stale"}}},
		IngressAllowedPlatforms: []string{"old"},
		Owners:                  []string{"someone-else"},
	}
	l.applySignedPolicy(&req)
	if src.asked != "02104572ca2f41e8ae2d24c0294e6f5e" {
		t.Fatalf("asked for app %q", src.asked)
	}
	if req.IngressAllowedCallers == nil || len(req.IngressAllowedCallers.Entries) != 1 || req.IngressAllowedCallers.Entries[0].AppID != "6739a7c1fb554ac49c1a89f2609a972f" {
		t.Fatalf("callers = %+v, want the signed ones", req.IngressAllowedCallers)
	}
	if len(req.IngressAllowedPlatforms) != 1 || req.IngressAllowedPlatforms[0] != "c513b146" {
		t.Fatalf("platforms = %v", req.IngressAllowedPlatforms)
	}
	if req.Dependencies == nil || len(req.Dependencies.Entries) != 1 {
		t.Fatalf("dependencies = %+v", req.Dependencies)
	}
	if len(req.Owners) != 1 || req.Owners[0] != "owner-sub" {
		t.Fatalf("owners = %v", req.Owners)
	}

	// An app the owner never signed keeps the request's values.
	l.SetSignedPolicy(&fakeSigned{})
	req2 := LoadRequest{Name: "x", AppId: "02104572-ca2f-41e8-ae2d-24c0294e6f5e", Owners: []string{"keep"}}
	l.applySignedPolicy(&req2)
	if len(req2.Owners) != 1 || req2.Owners[0] != "keep" {
		t.Fatalf("unsigned app lost its request owners: %v", req2.Owners)
	}
}
