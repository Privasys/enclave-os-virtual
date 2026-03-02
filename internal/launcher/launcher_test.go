package launcher

import (
	"testing"
)

func TestLoadRequestRuntimeEnv(t *testing.T) {
	// With vault token.
	req := LoadRequest{
		Name:       "test",
		Image:      "example.com/img@sha256:abcd",
		Port:       8080,
		VaultToken: "secret-token-123",
	}
	env := req.runtimeEnv()
	if env["VAULT_TOKEN"] != "secret-token-123" {
		t.Fatalf("expected VAULT_TOKEN=secret-token-123, got %q", env["VAULT_TOKEN"])
	}

	// Without vault token.
	req2 := LoadRequest{
		Name:  "test2",
		Image: "example.com/img@sha256:abcd",
		Port:  8080,
	}
	env2 := req2.runtimeEnv()
	if len(env2) != 0 {
		t.Fatalf("expected empty runtime env, got %v", env2)
	}
}

func TestVaultTokenNotInSpec(t *testing.T) {
	req := LoadRequest{
		Name:       "test",
		Image:      "example.com/img@sha256:abcd",
		Port:       8080,
		VaultToken: "secret-token",
		Env:        map[string]string{"FOO": "bar"},
	}

	spec := req.toContainerSpec()

	// The spec's Env should NOT contain VAULT_TOKEN.
	if _, ok := spec.Env["VAULT_TOKEN"]; ok {
		t.Fatal("VAULT_TOKEN should not be in the attested spec")
	}

	// Regular env should be present.
	if spec.Env["FOO"] != "bar" {
		t.Fatal("regular env should be preserved")
	}
}

func TestValidateLoadRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     LoadRequest
		wantErr bool
	}{
		{
			name:    "valid",
			req:     LoadRequest{Name: "a", Image: "img@sha256:abc", Port: 443},
			wantErr: false,
		},
		{
			name:    "valid with vault token",
			req:     LoadRequest{Name: "a", Image: "img@sha256:abc", Port: 443, VaultToken: "tok"},
			wantErr: false,
		},
		{
			name:    "missing name",
			req:     LoadRequest{Image: "img", Port: 443},
			wantErr: true,
		},
		{
			name:    "missing image",
			req:     LoadRequest{Name: "a", Port: 443},
			wantErr: true,
		},
		{
			name:    "bad port",
			req:     LoadRequest{Name: "a", Image: "img", Port: 0},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
