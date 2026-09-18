package trustedtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// state is what survives a restart. It lives on the encrypted /data volume, so
// the host cannot read or forge it; it can only roll the whole volume back,
// which restores an older, lower floor that the boot NTS fetch corrects.
type state struct {
	FloorMs int64          `json:"floor_ms"`
	Flagged bool           `json:"flagged"`
	Reason  string         `json:"reason,omitempty"`
	Config  *MonitorConfig `json:"config,omitempty"`
}

// loadState reads the state file. A missing file (first boot) or an empty
// path yields the zero state.
func loadState(path string) (state, error) {
	var st state
	if path == "" {
		return st, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("trustedtime: read state: %w", err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("trustedtime: parse state %s: %w", path, err)
	}
	return st, nil
}

// saveState writes the state atomically (temp file, fsync, rename).
func saveState(path string, st state) error {
	if path == "" {
		return nil
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".clock-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
