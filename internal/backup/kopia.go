// Package backup runs content backups of container volumes with kopia.
//
// The manager opens a read-only snapshot of an app's volume (internal/volume)
// and this package ships it to an S3-compatible bucket: content-addressed,
// deduplicated, compressed, and encrypted client-side under a repository
// password that only the enclave holds (released by the vaults). Every
// snapshot restores on its own; deleting old ones never breaks newer ones.
//
// Each operation runs in a throwaway state directory under /run (tmpfs) that is
// removed afterwards, so neither the repository config (which names the bucket
// credentials) nor the cache outlives the call. The repository password and the
// bucket credentials reach kopia through its environment, never its arguments.
//
// Snapshots are recorded as <app>@privasys:/run/backups/<app>, independent of
// the host, so an app's backups continue under the same identity wherever it
// runs (and kopia's maintenance owner follows it).
package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Hostname is the host every app's snapshots are recorded under.
const Hostname = "privasys"

// Target is the bucket an app's repository lives in. Supplied by the platform
// per request; the credentials are write credentials for that bucket.
type Target struct {
	// Endpoint is the S3 endpoint host, without scheme (e.g.
	// "s3.gra.io.cloud.ovh.net").
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	Region   string `json:"region,omitempty"`
	// Prefix scopes the app's repository inside the bucket (e.g.
	// "apps/<app-id>/").
	Prefix          string `json:"prefix"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	// RetentionMode and RetentionDays set an S3 Object Lock retention on every
	// object the repository writes (COMPLIANCE or GOVERNANCE). Only applied
	// when the repository is created; empty means no lock.
	RetentionMode string `json:"retention_mode,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty"`
}

func (t Target) validate() error {
	var missing []string
	for k, v := range map[string]string{
		"endpoint": t.Endpoint, "bucket": t.Bucket, "prefix": t.Prefix,
		"access_key_id": t.AccessKeyID, "secret_access_key": t.SecretAccessKey,
	} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("backup: target is missing %s", strings.Join(missing, ", "))
	}
	if strings.Contains(t.Endpoint, "://") {
		return errors.New("backup: target endpoint is a host name, without scheme")
	}
	switch t.RetentionMode {
	case "", "COMPLIANCE", "GOVERNANCE":
	default:
		return fmt.Errorf("backup: unknown retention mode %q", t.RetentionMode)
	}
	if t.RetentionMode != "" && t.RetentionDays <= 0 {
		return errors.New("backup: retention_days is required with a retention mode")
	}
	return nil
}

// Retention is how many snapshots the repository keeps, per kopia's
// keep-* buckets. A set retention is applied in full: a zero bucket keeps
// none, never kopia's default (which would keep 24 monthly and 3 annual
// snapshots nobody asked for). An empty retention leaves the repository's
// policy as it is.
type Retention struct {
	Latest  int `json:"latest,omitempty"`
	Hourly  int `json:"hourly,omitempty"`
	Daily   int `json:"daily,omitempty"`
	Weekly  int `json:"weekly,omitempty"`
	Monthly int `json:"monthly,omitempty"`
	Annual  int `json:"annual,omitempty"`
}

func (r Retention) args() []string {
	if r == (Retention{}) {
		return nil
	}
	var a []string
	for _, kv := range []struct {
		flag string
		n    int
	}{
		{"--keep-latest", r.Latest}, {"--keep-hourly", r.Hourly}, {"--keep-daily", r.Daily},
		{"--keep-weekly", r.Weekly}, {"--keep-monthly", r.Monthly}, {"--keep-annual", r.Annual},
	} {
		a = append(a, kv.flag+"="+strconv.Itoa(kv.n))
	}
	return a
}

// Snapshot describes one backup in an app's repository.
type Snapshot struct {
	ID        string    `json:"id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	// SizeBytes and Files describe the backed-up tree (not the bytes stored,
	// which deduplication makes much smaller).
	SizeBytes int64 `json:"size_bytes"`
	Files     int64 `json:"files"`
	// Failed counts entries kopia could not read.
	Failed int `json:"failed,omitempty"`
	// Retention lists why kopia keeps this snapshot (e.g. "daily-3").
	Retention   []string `json:"retention,omitempty"`
	Description string   `json:"description,omitempty"`
}

// kopiaManifest is the subset of kopia's snapshot JSON we read.
type kopiaManifest struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	RootEntry   struct {
		Summ struct {
			Size      int64 `json:"size"`
			Files     int64 `json:"files"`
			NumFailed int   `json:"numFailed"`
		} `json:"summ"`
	} `json:"rootEntry"`
	RetentionReason []string `json:"retentionReason"`
}

func (k kopiaManifest) snapshot() Snapshot {
	return Snapshot{
		ID: k.ID, StartTime: k.StartTime, EndTime: k.EndTime,
		SizeBytes: k.RootEntry.Summ.Size, Files: k.RootEntry.Summ.Files,
		Failed: k.RootEntry.Summ.NumFailed, Retention: k.RetentionReason,
		Description: k.Description,
	}
}

// Runner drives the kopia binary.
type Runner struct {
	log *zap.Logger
	// Binary is the kopia executable (baked into the image).
	Binary string
	// StateBase holds the per-operation state directories (tmpfs).
	StateBase string
}

// NewRunner returns a Runner with the image's defaults.
func NewRunner(log *zap.Logger) *Runner {
	return &Runner{log: log.Named("backup"), Binary: "/usr/bin/kopia", StateBase: "/run/kopia"}
}

// session is one connected repository in a throwaway state directory.
type session struct {
	r     *Runner
	app   string
	dir   string
	env   []string
	creds Target
}

// open connects to (or, when create is set and it does not exist yet, creates)
// the app's repository.
func (r *Runner) open(ctx context.Context, app, password string, t Target, create bool) (*session, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if app == "" || strings.ContainsAny(app, "/@: ") {
		return nil, fmt.Errorf("backup: invalid app name %q", app)
	}
	if password == "" {
		return nil, errors.New("backup: empty repository password")
	}
	if err := os.MkdirAll(r.StateBase, 0o700); err != nil {
		return nil, fmt.Errorf("backup: state dir: %w", err)
	}
	dir, err := os.MkdirTemp(r.StateBase, app+"-")
	if err != nil {
		return nil, fmt.Errorf("backup: state dir: %w", err)
	}
	s := &session{r: r, app: app, dir: dir, creds: t, env: []string{
		"HOME=" + dir,
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"KOPIA_PASSWORD=" + password,
		"KOPIA_CONFIG_PATH=" + filepath.Join(dir, "repository.config"),
		"KOPIA_CACHE_DIRECTORY=" + filepath.Join(dir, "cache"),
		"KOPIA_LOG_DIR=" + filepath.Join(dir, "logs"),
		"KOPIA_CHECK_FOR_UPDATES=false",
		"KOPIA_PERSIST_CREDENTIALS_ON_CONNECT=false",
		"KOPIA_USE_KEYRING=false",
		"AWS_ACCESS_KEY_ID=" + t.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + t.SecretAccessKey,
	}}

	storage := []string{"s3", "--bucket=" + t.Bucket, "--endpoint=" + t.Endpoint, "--prefix=" + t.Prefix}
	if t.Region != "" {
		storage = append(storage, "--region="+t.Region)
	}
	identity := []string{"--override-hostname=" + Hostname, "--override-username=" + app,
		// Bound the cache: it lives in RAM (tmpfs) for the length of the call.
		"--content-cache-size-mb=256", "--metadata-cache-size-mb=128"}

	connect := append(append([]string{"repository", "connect"}, storage...), identity...)
	_, err = s.run(ctx, connect...)
	if err != nil && create && strings.Contains(err.Error(), "not initialized") {
		mk := append(append([]string{"repository", "create"}, storage...), identity...)
		if t.RetentionMode != "" {
			mk = append(mk, "--retention-mode="+t.RetentionMode,
				fmt.Sprintf("--retention-period=%dh", t.RetentionDays*24))
		}
		if _, err = s.run(ctx, mk...); err == nil {
			r.log.Info("backup repository created",
				zap.String("app", app), zap.String("bucket", t.Bucket), zap.String("prefix", t.Prefix),
				zap.String("retention_mode", t.RetentionMode), zap.Int("retention_days", t.RetentionDays))
			err = s.initMaintenance(ctx)
		}
	}
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// initMaintenance sets the new repository's maintenance: this app's identity
// owns it, full maintenance runs daily, and when the repository writes Object
// Lock retention, full maintenance extends the lock on every object still in
// use (kopia requires the retention to exceed the full interval by 24h).
func (s *session) initMaintenance(ctx context.Context) error {
	args := []string{"maintenance", "set", "--owner=me", "--full-interval=24h"}
	if s.creds.RetentionMode != "" && s.creds.RetentionDays >= 3 {
		args = append(args, "--extend-object-locks=true")
	}
	_, err := s.run(ctx, args...)
	return err
}

func (s *session) close() {
	_, _ = s.run(context.Background(), "repository", "disconnect")
	if err := os.RemoveAll(s.dir); err != nil {
		s.r.log.Warn("backup: state dir cleanup failed", zap.String("dir", s.dir), zap.Error(err))
	}
}

// run executes kopia in the session; the error carries the tail of its output.
func (s *session) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.r.Binary, args...)
	cmd.Env = s.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("kopia %s: %w: %s", strings.Join(args[:min(2, len(args))], " "), err, tail(stderr.String(), 600))
	}
	return stdout.Bytes(), nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

// Backup snapshots source into the app's repository (creating the repository
// on first use), applies the retention policy, and runs any maintenance that is
// due (garbage collection, Object Lock extension).
func (r *Runner) Backup(ctx context.Context, app, password string, t Target, keep Retention, source, description string) (*Result, error) {
	s, err := r.open(ctx, app, password, t, true)
	if err != nil {
		return nil, err
	}
	defer s.close()

	policy := append([]string{"policy", "set", "--global", "--compression=zstd"}, keep.args()...)
	if _, err := s.run(ctx, policy...); err != nil {
		return nil, err
	}
	args := []string{"snapshot", "create", source, "--json", "--no-progress"}
	if description != "" {
		args = append(args, "--description="+description)
	}
	out, err := s.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	var m kopiaManifest
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, fmt.Errorf("backup: unreadable snapshot result: %w", err)
	}
	snap := m.snapshot()
	r.log.Info("backup snapshot created", zap.String("app", app), zap.String("id", snap.ID),
		zap.Int64("size_bytes", snap.SizeBytes), zap.Int64("files", snap.Files), zap.Int("failed", snap.Failed))

	// Maintenance is best-effort: the snapshot is already safe, and a failed
	// run is retried on the next backup.
	if _, err := s.run(ctx, "maintenance", "run"); err != nil {
		r.log.Warn("backup maintenance failed (retried next backup)", zap.String("app", app), zap.Error(err))
	}
	res := &Result{Snapshot: snap, StoredBytes: -1}
	// The repository's state after maintenance, for the platform's catalogue
	// and storage metering. Best-effort too: nil / -1 mean "not read this time".
	if snaps, err := s.snapshots(ctx); err == nil {
		res.Snapshots = snaps
	} else {
		r.log.Warn("backup: snapshot list after the backup failed", zap.String("app", app), zap.Error(err))
	}
	if n, err := s.storedBytes(ctx); err == nil {
		res.StoredBytes = n
	} else {
		r.log.Warn("backup: stored size after the backup failed", zap.String("app", app), zap.Error(err))
	}
	return res, nil
}

// Result is what one backup produced, and the repository's state after it.
type Result struct {
	Snapshot Snapshot `json:"snapshot"`
	// Snapshots is every snapshot the repository keeps after maintenance
	// (retention may have dropped old ones); nil when it could not be read.
	Snapshots []Snapshot `json:"snapshots,omitempty"`
	// StoredBytes is the size of the repository's objects in the bucket
	// (deduplicated, compressed, encrypted); -1 when it could not be read.
	// Object versions kept only by an Object Lock are not included.
	StoredBytes int64 `json:"stored_bytes"`
}

// snapshots lists the repository's snapshots.
func (s *session) snapshots(ctx context.Context) ([]Snapshot, error) {
	out, err := s.run(ctx, "snapshot", "list", "--all", "--json")
	if err != nil {
		return nil, err
	}
	var ms []kopiaManifest
	if err := json.Unmarshal(out, &ms); err != nil {
		return nil, fmt.Errorf("backup: unreadable snapshot list: %w", err)
	}
	snaps := make([]Snapshot, 0, len(ms))
	for _, m := range ms {
		snaps = append(snaps, m.snapshot())
	}
	return snaps, nil
}

// storedBytes reads the total size of the repository's blobs.
func (s *session) storedBytes(ctx context.Context) (int64, error) {
	out, err := s.run(ctx, "blob", "stats", "--raw")
	if err != nil {
		return 0, err
	}
	return parseBlobTotal(string(out))
}

// parseBlobTotal reads "Total: <bytes>" from `kopia blob stats --raw`.
func parseBlobTotal(out string) (int64, error) {
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Total:"); ok {
			return strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	return 0, errors.New("backup: no total in blob stats")
}

// ChangePassword moves the app's repository from oldPassword to newPassword
// (an app key rotation: both derive from the old and new keys). kopia re-wraps
// the repository's key, so every snapshot, old and new, opens with the new
// password. Idempotent: a repository that already opens with newPassword, or
// that does not exist, is left alone.
func (r *Runner) ChangePassword(ctx context.Context, app, oldPassword, newPassword string, t Target) error {
	if s, err := r.open(ctx, app, newPassword, t, false); err == nil {
		s.close()
		return nil
	} else if strings.Contains(err.Error(), "not initialized") {
		return nil
	}
	s, err := r.open(ctx, app, oldPassword, t, false)
	if err != nil {
		return err
	}
	defer s.close()
	// The new password reaches kopia through its environment, like the old.
	s.env = append(s.env, "KOPIA_NEW_PASSWORD="+newPassword)
	if _, err := s.run(ctx, "repository", "change-password"); err != nil {
		return err
	}
	r.log.Info("backup repository password changed (app key rotation)", zap.String("app", app))
	return nil
}

// Restore writes snapshot snapshotID (or the most recent one, for "latest") of
// the app's repository into dest, which must be the app's freshly created,
// empty volume. Owners, permissions and timestamps are restored as recorded.
// Returns the snapshot it restored.
func (r *Runner) Restore(ctx context.Context, app, password string, t Target, snapshotID, dest string) (*Snapshot, error) {
	s, err := r.open(ctx, app, password, t, false)
	if err != nil {
		return nil, err
	}
	defer s.close()
	out, err := s.run(ctx, "snapshot", "list", "--all", "--json")
	if err != nil {
		return nil, err
	}
	var ms []kopiaManifest
	if err := json.Unmarshal(out, &ms); err != nil {
		return nil, fmt.Errorf("backup: unreadable snapshot list: %w", err)
	}
	pick := pickSnapshot(ms, snapshotID)
	if pick == nil {
		return nil, fmt.Errorf("backup: snapshot %q not found in the app's repository", snapshotID)
	}
	if _, err := s.run(ctx, "snapshot", "restore", pick.ID, dest, "--no-progress"); err != nil {
		return nil, err
	}
	snap := pick.snapshot()
	r.log.Info("backup restored", zap.String("app", app), zap.String("id", snap.ID),
		zap.Time("taken_at", snap.StartTime), zap.Int64("size_bytes", snap.SizeBytes))
	return &snap, nil
}

// pickSnapshot finds snapshotID among ms, or the most recent for "latest".
func pickSnapshot(ms []kopiaManifest, snapshotID string) *kopiaManifest {
	var pick *kopiaManifest
	for i := range ms {
		m := &ms[i]
		if snapshotID == "latest" {
			if pick == nil || m.StartTime.After(pick.StartTime) {
				pick = m
			}
		} else if m.ID == snapshotID {
			return m
		}
	}
	return pick
}

// List returns the app's snapshots, oldest first. A repository that does not
// exist yet has no snapshots.
func (r *Runner) List(ctx context.Context, app, password string, t Target) ([]Snapshot, error) {
	s, err := r.open(ctx, app, password, t, false)
	if err != nil {
		if strings.Contains(err.Error(), "not initialized") {
			return []Snapshot{}, nil
		}
		return nil, err
	}
	defer s.close()
	snaps, err := s.snapshots(ctx)
	if err != nil {
		return nil, err
	}
	return snaps, nil
}
