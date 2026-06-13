// Package manager — persistent app registry.
//
// The registry records every successful container Load so that the
// manager can replay them on restart. Without this, a manager process
// restart (kernel panic, package update, OOM) would leave the host
// without any running apps until the management-service reconciler
// notices and redeploys — which can be minutes and requires the
// management-service to be reachable.
//
// Storage layout: a single JSON file at Config.RegistryPath (default
// /data/manager-apps.json) containing a JSON array of LoadRequest
// objects. Writes are atomic (tmp+rename), 0600, root-owned.
//
// Security: LoadRequest no longer carries volume-key material —
// vault-backed volumes persist only the (non-secret) KeyHandle and are
// re-resolved from the constellation on replay. Env values flagged
// secret may still appear, so keep the registry path on the per-VM
// LUKS-encrypted /data volume rather than the unencrypted rootfs.

package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/Privasys/enclave-os-virtual/internal/launcher"
)

// registry is the on-disk persistent app list. Methods are
// goroutine-safe. A nil registry is a no-op (used when RegistryPath is
// empty in dev/test).
type registry struct {
	path string
	mu   sync.Mutex
}

func newRegistry(path string) *registry {
	if path == "" {
		return nil
	}
	return &registry{path: path}
}

// Save records (or updates) a LoadRequest under its Name. If a request
// with the same Name already exists it is replaced — this keeps the
// registry idempotent against re-loads with new image digests.
func (r *registry) Save(req launcher.LoadRequest) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entries, err := r.loadLocked()
	if err != nil {
		return err
	}
	replaced := false
	for i, e := range entries {
		if e.Name == req.Name {
			entries[i] = req
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, req)
	}
	return r.writeLocked(entries)
}

// Remove deletes the entry whose Name matches name. Missing entries are
// silently ignored.
func (r *registry) Remove(name string) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entries, err := r.loadLocked()
	if err != nil {
		return err
	}
	out := entries[:0]
	for _, e := range entries {
		if e.Name != name {
			out = append(out, e)
		}
	}
	return r.writeLocked(out)
}

// List returns a copy of all persisted LoadRequests. Returns nil and no
// error if the registry file does not yet exist (first boot).
func (r *registry) List() ([]launcher.LoadRequest, error) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loadLocked()
}

func (r *registry) loadLocked() ([]launcher.LoadRequest, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("registry read %s: %w", r.path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var entries []launcher.LoadRequest
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("registry parse %s: %w", r.path, err)
	}
	return entries, nil
}

func (r *registry) writeLocked(entries []launcher.LoadRequest) error {
	if entries == nil {
		entries = []launcher.LoadRequest{}
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("registry marshal: %w", err)
	}
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("registry mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".manager-apps.*.tmp")
	if err != nil {
		return fmt.Errorf("registry tmp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("registry write tmp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("registry chmod: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("registry fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("registry close tmp: %w", err)
	}
	if err := os.Rename(tmpName, r.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("registry rename: %w", err)
	}
	return nil
}
