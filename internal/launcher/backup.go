package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
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

	// KeyHandle is the volume's current vault key handle (its LUKS passphrase).
	KeyHandle string `json:"key_handle"`
	// RepoKeyHandle names the vault secret that is the backup repository's
	// password. It is created on the first backup, under RepoKeyCreationGrant,
	// with the same policy as the volume key: only this app's approved
	// measurements can ever read the repository.
	RepoKeyHandle        string `json:"repo_key_handle"`
	RepoKeyCreationGrant string `json:"repo_key_creation_grant,omitempty"`

	VaultEndpoints         []string `json:"vault_endpoints,omitempty"`
	VaultMrenclave         string   `json:"vault_mrenclave,omitempty"`
	VaultAttestationServer string   `json:"vault_attestation_server,omitempty"`

	Target    backup.Target    `json:"target"`
	Retention backup.Retention `json:"retention,omitempty"`
	// Description is recorded on the snapshot (e.g. "scheduled", "manual").
	Description string `json:"description,omitempty"`
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
	if req.Name == "" || req.KeyHandle == "" || req.RepoKeyHandle == "" {
		return nil, fmt.Errorf("launcher: backup: name, key_handle and repo_key_handle are required")
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

	password, err := l.repoPassword(ctx, req, bc, true)
	if err != nil {
		return nil, err
	}
	// The volume key is fetched again for every backup (the manager drops it
	// after opening the volume), under the same vault policy as at load.
	dek, _, _, err := vaultkey.ResolveOrProvision(ctx, l.log, bc.cfg, req.KeyHandle, "", bc.digest, bc.appID)
	if err != nil {
		return nil, fmt.Errorf("launcher: backup: volume key: %w", err)
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

// repoPassword resolves the backup repository's password from the vaults,
// creating it on first use when allowed (a grant is then required).
func (l *Launcher) repoPassword(ctx context.Context, req BackupRequest, bc *backupContext, create bool) (string, error) {
	grant := ""
	if create {
		grant = req.RepoKeyCreationGrant
	}
	pw, _, _, err := vaultkey.ResolveOrProvision(ctx, l.log, bc.cfg, req.RepoKeyHandle, grant, bc.digest, bc.appID)
	if err != nil {
		return "", fmt.Errorf("launcher: backup: repository key: %w", err)
	}
	return pw, nil
}

// ListBackups returns the snapshots in a container's backup repository.
func (l *Launcher) ListBackups(ctx context.Context, req BackupRequest) ([]backup.Snapshot, error) {
	bc, err := l.backupContextFor(req)
	if err != nil {
		return nil, err
	}
	password, err := l.repoPassword(ctx, req, bc, false)
	if err != nil {
		// No repository key yet means no backup was ever taken.
		if strings.Contains(err.Error(), "no key-creation grant") {
			return []backup.Snapshot{}, nil
		}
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
