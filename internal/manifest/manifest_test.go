package manifest

import (
	"testing"
)

func sampleContainers() []Container {
	return []Container{
		{
			Name:     "myapp",
			Image:    "ghcr.io/example/myapp@sha256:abcdef1234567890",
			Hostname: "myapp.prod1.example.com",
			Port:     8000,
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
	}
}

func TestContainerMerkleTree(t *testing.T) {
	c := sampleContainers()[0]
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
	containers := sampleContainers()
	digests := map[string][]byte{
		"myapp":    {0x01, 0x02},
		"postgres": {0x03, 0x04},
	}
	h := CombinedImagesHash(containers, digests)

	var zero [32]byte
	if h == zero {
		t.Fatal("combined images hash is zero")
	}

	// Deterministic.
	h2 := CombinedImagesHash(containers, digests)
	if h != h2 {
		t.Fatal("combined images hash is not deterministic")
	}
}
