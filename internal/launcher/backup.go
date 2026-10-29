package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/backup"
	"github.com/Privasys/enclave-os-virtual/internal/vaultkey"
)

// backupTimeout bounds one backup job end to end (snapshot, upload,
// maintenance). The snapshot's copy-on-write area also bounds how long a
// backup can safely read a busy volume.
const backupTimeout = 6 * time.Hour

// BackupRequest asks for a content backup of a running, vault-backed
// container's volume, or for its list of backups. The vault addressing fields
// mirror RotateRequest's: deployment plumbing the platform re-supplies,
// untrusted (each vault is verified by attestation at dial time), never secret.
// The target's bucket credentials are secret and live only in this request and
// the job that uses them.
type BackupRequest struct {
	Name  string `json:"name"`
	AppId string `json:"app_id,omitempty"`

	// KeyHandle is the volume's current vault key handle: the owner's key, which
	// opens the volume and from which the repository password is derived
	// (backup.RepositoryPassword). One key per app for both.
	KeyHandle string `json:"key_handle"`

	VaultEndpoints         []string `json:"vault_endpoints,omitempty"`
	VaultMrenclave         string   `json:"vault_mrenclave,omitempty"`
	VaultAttestationServer string   `json:"vault_attestation_server,omitempty"`

	Target    backup.Target    `json:"target"`
	Retention backup.Retention `json:"retention,omitempty"`
	// Description is recorded on the snapshot (e.g. "scheduled", "manual").
	Description string `json:"description,omitempty"`
}

// RestoreSpec names the backup a load fills the app's volume from. The
// repository is the app's own: its password derives from the app's key, so
// only this app's approved measurements (or the owner, holding the key) can
// read it.
type RestoreSpec struct {
	// SnapshotID is the snapshot to restore, or "latest".
	SnapshotID string        `json:"snapshot_id"`
	Target     backup.Target `json:"target"`
}

// restoreVolume fills the freshly created, mounted volume from the backup the
// request names. Runs inside Load, before the container starts, so the app
// never sees a half-restored volume. volumeKey is the key Load just opened the
// volume with.
func (l *Launcher) restoreVolume(ctx context.Context, req LoadRequest, volumeKey, mountPath string) error {
	rs := req.Restore
	if rs.SnapshotID == "" {
		return fmt.Errorf("launcher: restore: snapshot_id is required")
	}
	password, err := backup.RepositoryPassword(volumeKey)
	if err != nil {
		return fmt.Errorf("launcher: restore: %w", err)
	}
	// Not serialised with backups (backupRun): Load holds the launcher lock,
	// so waiting here for another app's long backup would stall every load on
	// the host. A restore and a backup never touch the same volume (a restore
	// needs it absent, a backup needs the app loaded).
	snap, err := l.backupRunner.Restore(ctx, req.Name, password, rs.Target, rs.SnapshotID, mountPath)
	if err != nil {
		return fmt.Errorf("launcher: restore: %w", err)
	}
	l.log.Info("volume restored from backup", zap.String("container", req.Name),
		zap.String("snapshot", snap.ID), zap.Time("taken_at", snap.StartTime),
		zap.Int64("size_bytes", snap.SizeBytes), zap.Int64("files", snap.Files))
	return nil
}

// BackupJob is the state of a container's latest backup job.
type BackupJob struct {
	ID         string           `json:"id"`
	Container  string           `json:"container"`
	State      string           `json:"state"` // running | succeeded | failed
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
	Error      string           `json:"error,omitempty"`
	Snapshot   *backup.Snapshot `json:"snapshot,omitempty"`
}

// backupContext is what a backup needs from the loaded container, captured
// under the launcher lock so the job itself runs without it.
type backupContext struct {
	digest []byte
	appID  []byte
	cfg    vaultkey.Config
}

func (l *Launcher) backupContextFor(req BackupRequest) (*backupContext, error) {
	if l.volMgr == nil {
		return nil, fmt.Errorf("launcher: backup: volumes are not available on this host")
	}
	if req.Name == "" || req.KeyHandle == "" {
		return nil, fmt.Errorf("launcher: backup: name and key_handle are required")
	}
	l.mu.RLock()
	persistent := l.persistentVolume[req.Name]
	digest := append([]byte(nil), l.imageDigests[req.Name]...)
	l.mu.RUnlock()
	// The keys are released to this app's attested identity, so the app must
	// be loaded: its image digest is part of what the vaults check.
	if !persistent {
		return nil, fmt.Errorf("launcher: backup: %q is not a loaded vault-backed app", req.Name)
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("launcher: backup: no image digest recorded for %q", req.Name)
	}
	if err := l.checkApprovedConstellation(req.AppId, req.VaultMrenclave, req.VaultEndpoints); err != nil {
		return nil, fmt.Errorf("launcher: backup: vault constellation: %w", err)
	}
	return &backupContext{
		digest: digest,
		appID:  parseAppID(req.AppId),
		cfg: vaultkey.Config{
			Endpoints:            req.VaultEndpoints,
			MrenclaveHex:         req.VaultMrenclave,
			AttestationServerURL: req.VaultAttestationServer,
			MgmtURL:              l.cfg.ToolSpecMgmtURL,
			EnclaveID:            l.cfg.ToolSpecEnclaveID,
			EnclaveToken:         l.cfg.ToolSpecEnclaveToken,
		},
	}, nil
}

// StartBackup starts a backup job for a container's volume and returns it. One
// job per container at a time; jobs on different containers queue behind each
// other (one snapshot and one upload per host at a time).
func (l *Launcher) StartBackup(req BackupRequest) (*BackupJob, error) {
	bc, err := l.backupContextFor(req)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	job := &BackupJob{ID: hex.EncodeToString(id), Container: req.Name, State: "running", StartedAt: time.Now().UTC()}

	l.backupMu.Lock()
	if prev := l.backupJobs[req.Name]; prev != nil && prev.State == "running" {
		l.backupMu.Unlock()
		return nil, fmt.Errorf("launcher: backup: a backup of %q is already running (job %s)", req.Name, prev.ID)
	}
	l.backupJobs[req.Name] = job
	started := job.copy()
	l.backupMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), backupTimeout)
		defer cancel()
		snap, err := l.runBackup(ctx, req, bc)

		l.backupMu.Lock()
		defer l.backupMu.Unlock()
		now := time.Now().UTC()
		job.FinishedAt = &now
		if err != nil {
			job.State, job.Error = "failed", err.Error()
			l.log.Error("backup failed", zap.String("container", req.Name), zap.String("job", job.ID), zap.Error(err))
			return
		}
		job.State, job.Snapshot = "succeeded", snap
	}()
	return started, nil
}

func (l *Launcher) runBackup(ctx context.Context, req BackupRequest, bc *backupContext) (*backup.Snapshot, error) {
	l.backupRun.Lock()
	defer l.backupRun.Unlock()

	dek, password, err := l.backupKeys(ctx, req, bc)
	if err != nil {
		return nil, err
	}
	snap, err := l.volMgr.OpenSnapshot(req.Name, dek)
	if err != nil {
		return nil, fmt.Errorf("launcher: backup: %w", err)
	}
	defer func() {
		if cerr := snap.Close(); cerr != nil {
			l.log.Error("backup snapshot cleanup failed (removed on the next backup)",
				zap.String("container", req.Name), zap.Error(cerr))
		}
	}()
	return l.backupRunner.Backup(ctx, req.Name, password, req.Target, req.Retention, snap.MountPath, req.Description)
}

// backupKeys fetches the app's key from the vaults again (the manager drops it
// after opening the volume), under the same policy as at load, and derives the
// repository password from it. Never creates a key: the owner did.
func (l *Launcher) backupKeys(ctx context.Context, req BackupRequest, bc *backupContext) (dek, password string, err error) {
	dek, _, _, err = vaultkey.ResolveOrProvision(ctx, l.log, bc.cfg, req.KeyHandle, "", bc.digest, bc.appID)
	if err != nil {
		return "", "", fmt.Errorf("launcher: backup: app key: %w", err)
	}
	password, err = backup.RepositoryPassword(dek)
	if err != nil {
		return "", "", fmt.Errorf("launcher: backup: %w", err)
	}
	return dek, password, nil
}

// ListBackups returns the snapshots in a container's backup repository.
func (l *Launcher) ListBackups(ctx context.Context, req BackupRequest) ([]backup.Snapshot, error) {
	bc, err := l.backupContextFor(req)
	if err != nil {
		return nil, err
	}
	_, password, err := l.backupKeys(ctx, req, bc)
	if err != nil {
		return nil, err
	}
	return l.backupRunner.List(ctx, req.Name, password, req.Target)
}

// BackupStatus returns the container's latest backup job, if any.
func (l *Launcher) BackupStatus(name string) *BackupJob {
	l.backupMu.Lock()
	defer l.backupMu.Unlock()
	if j := l.backupJobs[name]; j != nil {
		return j.copy()
	}
	return nil
}

// backupRunning reports whether a backup of the container is in progress.
func (l *Launcher) backupRunning(name string) bool {
	l.backupMu.Lock()
	defer l.backupMu.Unlock()
	j := l.backupJobs[name]
	return j != nil && j.State == "running"
}

func (j *BackupJob) copy() *BackupJob {
	c := *j
	return &c
}
