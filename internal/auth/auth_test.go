package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// generateTestCert creates a self-signed ECDSA P-256 certificate and
// returns the PEM bytes and the private key.
func generateTestCert(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Enclave OS (Virtual) Operations",
			Organization: []string{"Privasys Ltd"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, key
}

// signJWT creates a compact JWS with ES256.
func signJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]string{"alg": "ES256", "typ": "JWT"}
	hJSON, _ := json.Marshal(header)
	cJSON, _ := json.Marshal(claims)

	h := base64.RawURLEncoding.EncodeToString(hJSON)
	c := base64.RawURLEncoding.EncodeToString(cJSON)

	signingInput := h + "." + c
	hash := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// r and s padded to 32 bytes each.
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeTempCert(t *testing.T, certPEM []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "operations.crt")
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

func TestVerifyBootstrapJWT_Valid(t *testing.T) {
	certPEM, key := generateTestCert(t)
	path := writeTempCert(t, certPEM)

	v, err := NewVerifier(path, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signJWT(t, key, map[string]interface{}{
		"iss": "privasys-operations",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	if err := v.VerifyBootstrapJWT(token); err != nil {
		t.Fatalf("VerifyBootstrapJWT: %v", err)
	}
}

func TestVerifyBootstrapJWT_Expired(t *testing.T) {
	certPEM, key := generateTestCert(t)
	path := writeTempCert(t, certPEM)

	v, err := NewVerifier(path, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signJWT(t, key, map[string]interface{}{
		"iss": "privasys-operations",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	})

	if err := v.VerifyBootstrapJWT(token); err == nil {
		t.Fatal("expected error for expired JWT")
	}
}

func TestVerifyBootstrapJWT_WrongIssuer(t *testing.T) {
	certPEM, key := generateTestCert(t)
	path := writeTempCert(t, certPEM)

	v, err := NewVerifier(path, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signJWT(t, key, map[string]interface{}{
		"iss": "evil-corp",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	if err := v.VerifyBootstrapJWT(token); err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestVerifyBootstrapJWT_WrongKey(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	path := writeTempCert(t, certPEM)

	v, err := NewVerifier(path, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Sign with a different key.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := signJWT(t, wrongKey, map[string]interface{}{
		"iss": "privasys-operations",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	if err := v.VerifyBootstrapJWT(token); err == nil {
		t.Fatal("expected error for wrong signing key")
	}
}

func TestCertFingerprint(t *testing.T) {
	certPEM, _ := generateTestCert(t)
	path := writeTempCert(t, certPEM)

	v, err := NewVerifier(path, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	fp := v.CertFingerprint()
	if fp == "" {
		t.Fatal("fingerprint is empty")
	}
	if len(fp) != 64 {
		t.Fatalf("expected 64 hex chars, got %d: %s", len(fp), fp)
	}
}

func TestAuthenticate_OperationsJWT_ManagerRole(t *testing.T) {
	certPEM, key := generateTestCert(t)
	path := writeTempCert(t, certPEM)

	v, err := NewVerifier(path, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signJWT(t, key, map[string]interface{}{
		"iss": "privasys-operations",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	result, err := v.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result.Source != "operations-jwt" {
		t.Fatalf("expected source operations-jwt, got %s", result.Source)
	}
	if result.Role != "manager" {
		t.Fatalf("expected role manager, got %s", result.Role)
	}
	if !result.HasManagerAccess() {
		t.Fatal("operations JWT should have manager access")
	}
}

func TestAuthenticate_WithContainersClaim(t *testing.T) {
	certPEM, key := generateTestCert(t)
	path := writeTempCert(t, certPEM)

	v, err := NewVerifier(path, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signJWT(t, key, map[string]interface{}{
		"iss": "privasys-operations",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"containers": []map[string]string{
			{"name": "postgres", "digest": "sha256:abc123"},
			{"name": "myapp", "digest": "sha256:def456"},
		},
	})

	result, err := v.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(result.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(result.Containers))
	}

	// Permitted image.
	if !result.IsContainerPermitted("registry.example.com/pg:latest@sha256:abc123") {
		t.Fatal("expected postgres to be permitted")
	}
	// Not permitted image.
	if result.IsContainerPermitted("registry.example.com/evil:latest@sha256:evil999") {
		t.Fatal("expected unknown image to be denied")
	}
	// Unload by name.
	if !result.IsUnloadPermitted("postgres") {
		t.Fatal("expected unload postgres to be permitted")
	}
	if result.IsUnloadPermitted("evil") {
		t.Fatal("expected unload evil to be denied")
	}
}

func TestAuthResult_NilContainers_PermitsAll(t *testing.T) {
	r := &AuthResult{Source: "operations-jwt", Role: "manager"}
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
			name:     "operations JWT has monitoring access",
			result:   AuthResult{Source: "operations-jwt", Role: "manager"},
			expected: true,
		},
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
			"enclave-os-virtual:manager": map[string]interface{}{
				"orgId": "123",
			},
		},
	}
	if !checkRole(claims, "enclave-os-virtual:manager", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected Zitadel map role to match")
	}
	if checkRole(claims, "enclave-os-virtual:monitoring", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected monitoring role not to match")
	}
}

func TestCheckRole_StandardArray(t *testing.T) {
	claims := map[string]interface{}{
		"roles": []interface{}{"enclave-os-virtual:monitoring", "user"},
	}
	if !checkRole(claims, "enclave-os-virtual:monitoring", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected standard roles array to match")
	}
	if checkRole(claims, "enclave-os-virtual:manager", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected manager role not in standard roles")
	}
}

func TestCheckRole_KeycloakRealmAccess(t *testing.T) {
	claims := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"enclave-os-virtual:manager"},
		},
	}
	if !checkRole(claims, "enclave-os-virtual:manager", "urn:zitadel:iam:org:project:roles") {
		t.Fatal("expected Keycloak realm_access role to match")
	}
}
