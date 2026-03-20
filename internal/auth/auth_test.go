package auth

import (
	"testing"

	"go.uber.org/zap"
)

func TestNewVerifier_RequiresOIDC(t *testing.T) {
	_, err := NewVerifier(nil, zap.NewNop())
	if err == nil {
		t.Fatal("expected error when OIDC config is nil")
	}
}

func TestNewVerifier_RequiresIssuer(t *testing.T) {
	_, err := NewVerifier(&OIDCConfig{}, zap.NewNop())
	if err == nil {
		t.Fatal("expected error when issuer is empty")
	}
}

func TestNewVerifier_Defaults(t *testing.T) {
	cfg := &OIDCConfig{Issuer: "https://auth.example.com"}
	v, err := NewVerifier(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if v.oidc.RoleClaim != "urn:zitadel:iam:org:project:roles" {
		t.Fatalf("expected default role claim, got %s", v.oidc.RoleClaim)
	}
	if v.oidc.ManagerRole != "privasys-platform:manager" {
		t.Fatalf("expected default manager role, got %s", v.oidc.ManagerRole)
	}
	if v.oidc.MonitoringRole != "privasys-platform:monitoring" {
		t.Fatalf("expected default monitoring role, got %s", v.oidc.MonitoringRole)
	}
}

func TestHasManagerAccess(t *testing.T) {
	tests := []struct {
		name     string
		result   AuthResult
		expected bool
	}{
		{
			name:     "manager role has access",
			result:   AuthResult{Source: "oidc", Role: "manager"},
			expected: true,
		},
		{
			name:     "monitoring role denied",
			result:   AuthResult{Source: "oidc", Role: "monitoring"},
			expected: false,
		},
		{
			name:     "empty role denied",
			result:   AuthResult{Source: "oidc", Role: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.HasManagerAccess()
			if got != tt.expected {
				t.Fatalf("HasManagerAccess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsContainerPermitted(t *testing.T) {
	r := &AuthResult{
		Source: "oidc",
		Role:   "manager",
		Containers: []ContainerPermission{
			{Name: "postgres", Digest: "sha256:abc123"},
			{Name: "myapp", Digest: "sha256:def456"},
		},
	}

	// Permitted image.
	if !r.IsContainerPermitted("registry.example.com/pg:latest@sha256:abc123") {
		t.Fatal("expected postgres to be permitted")
	}
	// Not permitted image.
	if r.IsContainerPermitted("registry.example.com/evil:latest@sha256:evil999") {
		t.Fatal("expected unknown image to be denied")
	}
	// Unload by name.
	if !r.IsUnloadPermitted("postgres") {
		t.Fatal("expected unload postgres to be permitted")
	}
	if r.IsUnloadPermitted("evil") {
		t.Fatal("expected unload evil to be denied")
	}
}

func TestAuthResult_NilContainers_PermitsAll(t *testing.T) {
	r := &AuthResult{Source: "oidc", Role: "manager"}
	if !r.IsContainerPermitted("anything@sha256:any") {
		t.Fatal("nil containers should permit all")
	}
	if !r.IsUnloadPermitted("anything") {
		t.Fatal("nil containers should permit all unloads")
	}
}

func TestHasMonitoringAccess(t *testing.T) {
	tests := []struct {
		name     string
		result   AuthResult
		expected bool
	}{
		{
			name:     "manager role has monitoring access",
			result:   AuthResult{Source: "oidc", Role: "manager"},
			expected: true,
		},
		{
			name:     "monitoring role has monitoring access",
			result:   AuthResult{Source: "oidc", Role: "monitoring"},
			expected: true,
		},
		{
			name:     "empty role denied",
			result:   AuthResult{Source: "oidc", Role: ""},
			expected: false,
		},
		{
			name:     "unknown role denied",
			result:   AuthResult{Source: "oidc", Role: "viewer"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.result.HasMonitoringAccess()
			if got != tt.expected {
				t.Fatalf("HasMonitoringAccess() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCheckRole_ZitadelMap(t *testing.T) {
	claims := map[string]interface{}{
		"urn:zitadel:iam:org:project:roles": map[string]interface{}{
			"privasys-platform:manager": map[string]interface{}{
				"orgId": "123",
			},
		},
	}
	if !checkRole(claims, "privasys-platform:manager", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected Zitadel map role to match")
	}
	if checkRole(claims, "privasys-platform:monitoring", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected monitoring role not to match")
	}
}

func TestCheckRole_StandardArray(t *testing.T) {
	claims := map[string]interface{}{
		"roles": []interface{}{"privasys-platform:monitoring", "user"},
	}
	if !checkRole(claims, "privasys-platform:monitoring", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected standard roles array to match")
	}
	if checkRole(claims, "privasys-platform:manager", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected manager role not in standard roles")
	}
}

func TestCheckRole_KeycloakRealmAccess(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"privasys-platform:manager"},
		},
	}
	if !checkRole(claims, "privasys-platform:manager", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected Keycloak realm_access role to match")
	}
}
