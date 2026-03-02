package manifest

import (
	"strings"
	"testing"
)

func sampleManifest() *Manifest {
	return &Manifest{
		Version: "1",
		Platform: Platform{
			Hostname:           "enclave.example.com",
			CACertPath:         "/etc/enclave-os/ca.pem",
			CAKeyPath:          "/etc/enclave-os/ca-key.pem",
			AttestationBackend: "tdx",
		},
		Containers: []Container{
			{
				Name:     "myapp",
				Image:    "ghcr.io/example/myapp@sha256:abcdef1234567890",
				Hostname: "app.example.com",
				Port:     8080,
				Env: map[string]string{
					"DATABASE_HOST": "localhost",
					"DATABASE_PORT": "5432",
				},
			},
			{
				Name:     "postgres",
				Image:    "docker.io/library/postgres@sha256:deadbeef12345678",
				Port:     5432,
				Internal: true,
				Volumes:  []string{"/data/postgres:/var/lib/postgresql/data"},
			},
		},
	}
}

func TestParse(t *testing.T) {
	yaml := `
version: "1"
platform:
  hostname: enclave.example.com
  ca_cert: /etc/enclave-os/ca.pem
  ca_key: /etc/enclave-os/ca-key.pem
  attestation_backend: tdx
containers:
  - name: web
    image: "registry.example.com/web@sha256:aabbccdd"
    hostname: www.example.com
    port: 8080
    env:
      APP_MODE: production
`
	m, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if m.Version != "1" {
		t.Fatalf("version = %q, want 1", m.Version)
	}
	if len(m.Containers) != 1 {
		t.Fatalf("len(containers) = %d, want 1", len(m.Containers))
	}
	if m.Containers[0].Name != "web" {
		t.Fatalf("name = %q, want web", m.Containers[0].Name)
	}
}

func TestValidate_BadVersion(t *testing.T) {
	m := sampleManifest()
	m.Version = "2"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestValidate_DuplicateName(t *testing.T) {
	m := sampleManifest()
	m.Containers[1].Name = "myapp"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestValidate_DuplicateHostname(t *testing.T) {
	m := sampleManifest()
	m.Containers[1].Hostname = "app.example.com"
	m.Containers[1].Internal = false
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for duplicate hostname")
	}
}

func TestValidate_BadPort(t *testing.T) {
	m := sampleManifest()
	m.Containers[0].Port = 0
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("expected port error, got %v", err)
	}
}

func TestValidate_MissingImage(t *testing.T) {
	m := sampleManifest()
	m.Containers[0].Image = ""
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for missing image")
	}
}

func TestPlatformMerkleTree(t *testing.T) {
	m := sampleManifest()
	caCert := []byte("mock-ca-cert")
	digests := map[string][]byte{
		"myapp":    {0x01, 0x02, 0x03},
		"postgres": {0x04, 0x05, 0x06},
	}
	tree := m.PlatformMerkleTree(caCert, digests)
	root := tree.Root()

	// Root must be non-zero.
	var zero [32]byte
	if root == zero {
		t.Fatal("platform merkle root is zero")
	}

	// Same inputs produce same root.
	tree2 := m.PlatformMerkleTree(caCert, digests)
	if tree.Root() != tree2.Root() {
		t.Fatal("platform merkle tree is not deterministic")
	}
}

func TestContainerMerkleTree(t *testing.T) {
	c := sampleManifest().Containers[0]
	digest := []byte{0xAA, 0xBB, 0xCC}

	tree := c.ContainerMerkleTree(digest)
	root := tree.Root()

	var zero [32]byte
	if root == zero {
		t.Fatal("container merkle root is zero")
	}

	// Different env → different root.
	c2 := c
	c2.Env = map[string]string{"DIFFERENT": "value"}
	tree2 := c2.ContainerMerkleTree(digest)
	if tree.Root() == tree2.Root() {
		t.Fatal("different env should produce different merkle root")
	}
}

func TestCombinedImagesHash(t *testing.T) {
	m := sampleManifest()
	digests := map[string][]byte{
		"myapp":    {0x01, 0x02},
		"postgres": {0x03, 0x04},
	}
	h := CombinedImagesHash(m.Containers, digests)

	var zero [32]byte
	if h == zero {
		t.Fatal("combined images hash is zero")
	}

	// Deterministic.
	h2 := CombinedImagesHash(m.Containers, digests)
	if h != h2 {
		t.Fatal("combined images hash is not deterministic")
	}
}
