// Package container manages OCI container lifecycle via containerd.
//
// It provides a high-level API to pull images, verify digests, create
// and start containers, forward logs, and run health checks. All
// interactions go through the containerd gRPC API — there is no Docker
// daemon involved.
package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"crypto/tls"

	tasks "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	containerdcdi "github.com/containerd/containerd/v2/pkg/cdi"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/manifest"
)

const (
	// DefaultSocket is the default containerd socket path.
	DefaultSocket = "/run/containerd/containerd.sock"

	// Namespace is the containerd namespace for all Enclave OS containers.
	Namespace = "enclave-os"

	// healthCheckDefaultInterval is the default interval between health checks.
	healthCheckDefaultInterval = 5 * time.Second

	// healthCheckDefaultTimeout is the default timeout for a single health check.
	healthCheckDefaultTimeout = 3 * time.Second

	// healthCheckDefaultRetries is the default number of retries before unhealthy.
	healthCheckDefaultRetries = 3

	// RoothashRegistryHostDir is where disk-mounter records the dm-verity
	// root hash of each verified model disk (/run because /var/lib sits on
	// the read-only erofs root). RoothashRegistryContainerDir is the
	// canonical path workloads read it from (e.g. confidential-ai's
	// ROOTHASH_DIR default): Create bind-mounts host→container read-only
	// whenever the host dir exists, so the AI workload can publish the
	// root hash as attestation OID 3.5 without hashing the weights itself.
	RoothashRegistryHostDir      = "/run/enclave-os/model-roothashes"
	RoothashRegistryContainerDir = "/var/lib/enclave-os/model-roothashes"
)

// Status represents the status of a managed container.
type Status string

const (
	StatusPending   Status = "pending"
	StatusPulling   Status = "pulling"
	StatusRunning   Status = "running"
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusStopped   Status = "stopped"
	StatusFailed    Status = "failed"
	StatusFrozen    Status = "frozen"
)

// PullProgress tracks the progress of an image pull.
type PullProgress struct {
	TotalBytes      int64 `json:"total_bytes"`
	DownloadedBytes int64 `json:"downloaded_bytes"`
}

// ManagedContainer tracks a running container and its metadata.
type ManagedContainer struct {
	Name        string
	Spec        manifest.Container
	Status      Status
	ImageDigest []byte // resolved SHA-256 digest of the pulled image
	Container   client.Container
	Task        client.Task

	pullProgress PullProgress
	failure      string // why Status is failed, for status reports
	mu           sync.RWMutex

	// healthCancel stops this container's health-check goroutine. Set by
	// StartHealthChecks, fired by Stop — without it the goroutine (started
	// on a background context) outlives the container and keeps probing a
	// dead/old port forever after unload or a port-changing reload.
	healthCancel context.CancelFunc
}

// SetStatus updates the container status safely.
func (mc *ManagedContainer) SetStatus(s Status) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.Status = s
}

// SetFailure marks the container failed and records why. The message is
// surfaced in status reports so the control plane can show the operator a
// reason instead of a bare "failed" (prod enclaves have no journal access).
func (mc *ManagedContainer) SetFailure(msg string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.Status = StatusFailed
	mc.failure = msg
}

// GetFailure returns the recorded failure reason ("" when none).
func (mc *ManagedContainer) GetFailure() string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.failure
}

// GetStatus returns the container status safely.
func (mc *ManagedContainer) GetStatus() Status {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.Status
}

// SetPullProgress updates pull progress safely.
func (mc *ManagedContainer) SetPullProgress(downloaded, total int64) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.pullProgress = PullProgress{TotalBytes: total, DownloadedBytes: downloaded}
}

// GetPullProgress returns pull progress safely.
func (mc *ManagedContainer) GetPullProgress() PullProgress {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.pullProgress
}

// Manager manages the lifecycle of OCI containers through containerd.
type Manager struct {
	client     *client.Client
	log        *zap.Logger
	containers map[string]*ManagedContainer
	mu         sync.RWMutex
}

// NewManager connects to containerd and returns a new Manager.
func NewManager(log *zap.Logger, socket string) (*Manager, error) {
	if socket == "" {
		socket = DefaultSocket
	}
	c, err := client.New(socket)
	if err != nil {
		return nil, fmt.Errorf("container: failed to connect to containerd at %s: %w", socket, err)
	}
	return &Manager{
		client:     c,
		log:        log.Named("container"),
		containers: make(map[string]*ManagedContainer),
	}, nil
}

// Close shuts down the containerd connection.
func (m *Manager) Close() error {
	return m.client.Close()
}

// ctx returns a context with the enclave-os containerd namespace set.
func (m *Manager) ctx(parent context.Context) context.Context {
	return namespaces.WithNamespace(parent, Namespace)
}

// RemoveImage deletes an image reference and synchronously garbage-collects its
// content + snapshots, reclaiming disk. Callers must ensure no container still
// references the image. A not-found image is treated as success (idempotent).
func (m *Manager) RemoveImage(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	ctx = m.ctx(ctx)
	if err := m.client.ImageService().Delete(ctx, ref, images.SynchronousDelete()); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return fmt.Errorf("delete image %s: %w", ref, err)
	}
	return nil
}

// PruneImages garbage-collects containerd images that are NOT in `keep`,
// reclaiming disk on the (small, persistent) /data/containerd store. Enclave
// images accumulate across every app version deployed, there is no host to
// `ctr image prune` on, and a full store hangs the NEXT pull at "pulling"
// forever — so the manager prunes before it pulls. `keep` is the set of
// image refs still referenced by a registered/running container plus the
// image about to be pulled; disk:// refs are ignored (no containerd image).
//
// SynchronousDelete triggers containerd's full content mark-and-sweep, so
// this also reclaims ORPHANED blobs left by earlier killed/partial pulls
// (not just the named image's layers) — as long as no lease still holds
// them; leaked pull-leases carry a gc.expire label and self-expire. So this
// one call is both the image GC and the content GC.
//
// Best-effort: a delete failure is logged, never fatal. Returns how many were
// removed.
func (m *Manager) PruneImages(ctx context.Context, keep map[string]bool) (int, error) {
	ctx = m.ctx(ctx)
	imgs, err := m.client.ImageService().List(ctx)
	if err != nil {
		return 0, fmt.Errorf("list images: %w", err)
	}
	removed := 0
	for _, img := range imgs {
		if keep[img.Name] {
			continue
		}
		if err := m.client.ImageService().Delete(ctx, img.Name, images.SynchronousDelete()); err != nil {
			if strings.Contains(err.Error(), "not found") {
				continue
			}
			// A still-referenced image (a running container) refuses delete —
			// log and move on; never let GC break the deploy path.
			m.log.Warn("prune: could not remove image",
				zap.String("image", img.Name), zap.Error(err))
			continue
		}
		m.log.Info("prune: removed unused image", zap.String("image", img.Name))
		removed++
	}
	return removed, nil
}

// Pull downloads an OCI image and verifies its digest matches the manifest.
// Returns the resolved image descriptor and the raw digest bytes.
// Registers a pulling container in the manager so pull progress is visible
// via List()/StatusReport().
// RegistryAuth carries optional pull credentials for a private registry. The
// manager fetches these from the app owner's vault (never from the control
// plane) immediately before pulling, so a private image's bytes AND its pull
// token stay inside the TEE — the host and the platform see neither. Nil (or
// empty fields) means an anonymous pull, the public-image path.
type RegistryAuth struct {
	Username string
	Password string
}

func (m *Manager) Pull(ctx context.Context, spec manifest.Container, auth *RegistryAuth) (client.Image, []byte, error) {
	ctx = m.ctx(ctx)
	m.log.Info("pulling image", zap.String("name", spec.Name), zap.String("image", spec.Image))

	// Register a "pulling" container so it shows up in status queries.
	mc := &ManagedContainer{
		Name:   spec.Name,
		Spec:   spec,
		Status: StatusPulling,
	}
	m.mu.Lock()
	m.containers[spec.Name] = mc
	m.mu.Unlock()

	// disk:// scheme: image is already on a locally mounted persistent
	// disk, no network pull needed. See internal/container/disk.go.
	if IsDiskRef(spec.Image) {
		dir, err := diskRefDir(spec.Image)
		if err != nil {
			mc.SetStatus(StatusFailed)
			m.mu.Lock()
			delete(m.containers, spec.Name)
			m.mu.Unlock()
			return nil, nil, err
		}
		img, dgst, err := m.importFromDisk(ctx, spec.Image, dir)
		if err != nil {
			mc.SetStatus(StatusFailed)
			m.mu.Lock()
			delete(m.containers, spec.Name)
			m.mu.Unlock()
			return nil, nil, err
		}
		// Import is effectively a no-progress operation; mark complete.
		mc.SetPullProgress(1, 1)
		return img, dgst, nil
	}

	// Track pull progress per-descriptor using the image handler wrapper.
	var (
		progressMu  sync.Mutex
		totalSize   int64
		fetchedSize int64
		seen        = make(map[godigest.Digest]bool) // true = fetched
	)

	// Use an HTTP/1.1-only resolver. ghcr.io's HTTP/2 endpoint intermittently
	// returns PROTOCOL_ERROR / RST_STREAM mid-stream for large multi-layer
	// image pulls (observed reliably with a 6.3GB image), which containerd
	// cannot recover from. Forcing HTTP/1.1 sidesteps the issue entirely.
	httpTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     &tls.Config{NextProtos: []string{"http/1.1"}},
	}
	httpClient := &http.Client{Transport: httpTransport}
	resOpts := docker.ResolverOptions{Client: httpClient}
	if auth != nil && (auth.Username != "" || auth.Password != "") {
		// Private registry: attach a bearer/basic authorizer. Route through the
		// same HTTP/1.1-only client (WithClient) so the auth path keeps the
		// large-pull workaround above. Credentials came from the vault and are
		// never logged.
		authorizer := docker.NewDockerAuthorizer(
			docker.WithAuthClient(httpClient),
			docker.WithAuthCreds(func(string) (string, string, error) {
				return auth.Username, auth.Password, nil
			}),
		)
		resOpts.Hosts = docker.ConfigureDefaultRegistries(
			docker.WithClient(httpClient),
			docker.WithAuthorizer(authorizer),
		)
		m.log.Info("private registry pull (vault-sourced credentials)", zap.String("name", spec.Name))
	}
	resolver := docker.NewResolver(resOpts)

	pullOnce := func() (client.Image, error) {
		// Reset progress trackers per attempt so that retries don't
		// double-count bytes from a previous failed attempt.
		progressMu.Lock()
		totalSize = 0
		fetchedSize = 0
		seen = make(map[godigest.Digest]bool)
		progressMu.Unlock()

		return m.client.Pull(ctx, spec.Image,
			client.WithPullUnpack,
			client.WithResolver(resolver),
			client.WithImageHandlerWrapper(func(inner images.Handler) images.Handler {
				return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
					children, err := inner.Handle(ctx, desc)
					if err != nil {
						return children, err
					}

					progressMu.Lock()
					if _, known := seen[desc.Digest]; !known {
						totalSize += desc.Size
					}
					if !seen[desc.Digest] {
						fetchedSize += desc.Size
						seen[desc.Digest] = true
					}
					for _, c := range children {
						if _, known := seen[c.Digest]; !known {
							totalSize += c.Size
							seen[c.Digest] = false
						}
					}
					progressMu.Unlock()

					mc.SetPullProgress(fetchedSize, totalSize)
					return children, nil
				})
			}),
		)
	}

	// Retry transient pull errors. ghcr.io occasionally returns
	// HTTP/2 PROTOCOL_ERROR or RST_STREAM mid-stream for large images;
	// containerd surfaces these as one-shot failures. Retry up to 4
	// times with exponential backoff before giving up.
	var (
		img        client.Image
		err        error
		maxRetries = 4
	)
	for attempt := 0; attempt < maxRetries; attempt++ {
		img, err = pullOnce()
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			break // context cancelled, no point retrying
		}
		// Only retry on errors that look transient.
		es := err.Error()
		retryable := strings.Contains(es, "PROTOCOL_ERROR") ||
			strings.Contains(es, "stream error") ||
			strings.Contains(es, "RST_STREAM") ||
			strings.Contains(es, "connection reset") ||
			strings.Contains(es, "EOF") ||
			strings.Contains(es, "unexpected EOF") ||
			strings.Contains(es, "i/o timeout") ||
			strings.Contains(es, "TLS handshake timeout")
		if !retryable {
			break
		}
		backoff := time.Duration(1<<attempt) * time.Second // 1s, 2s, 4s, 8s
		m.log.Warn("transient pull error, retrying",
			zap.String("name", spec.Name),
			zap.Int("attempt", attempt+1),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-time.After(backoff):
		}
	}
	if err != nil {
		// Remove the pulling stub on failure.
		mc.SetStatus(StatusFailed)
		m.mu.Lock()
		delete(m.containers, spec.Name)
		m.mu.Unlock()
		return nil, nil, fmt.Errorf("container: failed to pull %s: %w", spec.Image, err)
	}

	// Mark pull as complete.
	mc.SetPullProgress(totalSize, totalSize)

	// Verify digest if the image ref contains @sha256:
	resolvedDigest := img.Target().Digest.String()
	m.log.Info("image pulled",
		zap.String("name", spec.Name),
		zap.String("digest", resolvedDigest),
	)

	digestBytes, err := digestToBytes(resolvedDigest)
	if err != nil {
		m.mu.Lock()
		delete(m.containers, spec.Name)
		m.mu.Unlock()
		return nil, nil, fmt.Errorf("container: failed to parse digest for %s: %w", spec.Name, err)
	}

	return img, digestBytes, nil
}

// Create creates and starts a container from the given spec.
func (m *Manager) Create(ctx context.Context, spec manifest.Container, img client.Image) (*ManagedContainer, error) {
	ctx = m.ctx(ctx)
	m.log.Info("creating container", zap.String("name", spec.Name))

	// Build OCI spec options.
	opts := []oci.SpecOpts{
		oci.WithImageConfig(img),
		// Host networking — all containers share the host network namespace.
		// In a TEE the VM itself is the security boundary, so this is safe.
		oci.WithHostNamespace(specs.NetworkNamespace),
		// Bind-mount the host's resolv.conf so DNS works inside the container.
		// Using WithMounts directly rather than WithHostResolvconf, because the
		// nvidia-container-runtime rewrites the spec and may drop higher-level
		// OCI options.
		oci.WithMounts([]specs.Mount{{
			Destination: "/etc/resolv.conf",
			Source:      "/etc/resolv.conf",
			Type:        "bind",
			Options:     []string{"rbind", "ro"},
		}}),
	}

	// Hostname override.
	if spec.Hostname != "" {
		opts = append(opts, oci.WithHostname(spec.Hostname))
	}

	// Environment variables.
	if len(spec.Env) > 0 {
		envSlice := make([]string, 0, len(spec.Env))
		for k, v := range spec.Env {
			envSlice = append(envSlice, k+"="+v)
		}
		opts = append(opts, oci.WithEnv(envSlice))
	}

	// Command override.
	if len(spec.Command) > 0 {
		opts = append(opts, oci.WithProcessArgs(spec.Command...))
	}

	// Read the image spec once; it drives both image-declared devices and
	// the image-declared volume below.
	imgSpec, err := img.Spec(ctx)
	if err != nil {
		return nil, fmt.Errorf("container: failed to read image spec for %s: %w", spec.Name, err)
	}

	// Host device passthrough (e.g. /dev/nvidia0). Devices come from the
	// deploy request (spec.Devices) and/or the image's own
	// "ai.privasys.devices" label (comma-separated host paths), so a GPU
	// image declares the hardware it needs the same way it declares its
	// volume mount ("ai.privasys.volume"). This lets a plain deploy of a GPU
	// image get passthrough with no per-deploy input.
	devices := append([]string(nil), spec.Devices...)
	if v, ok := imgSpec.Config.Labels["ai.privasys.devices"]; ok {
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				devices = append(devices, d)
			}
		}
	}
	for _, devPath := range devices {
		opts = append(opts, oci.WithDevices(devPath, "", "rwm"))
	}

	// When GPU devices are requested, ensure NVIDIA_VISIBLE_DEVICES=all
	// so that the nvidia-container-runtime injects driver libraries.
	if len(devices) > 0 {
		opts = append(opts, oci.WithEnv([]string{"NVIDIA_VISIBLE_DEVICES=all"}))
		// Inject NVIDIA driver libraries via CDI. The CDI spec is
		// generated at boot by `nvidia-ctk cdi generate` into
		// /var/run/cdi/nvidia.yaml. CDI is the modern replacement for
		// the legacy nvidia-container-runtime hook and works cleanly
		// with raw containerd (no CRI required).
		opts = append(opts, containerdcdi.WithCDIDevices("nvidia.com/gpu=all"))
	}

	// Image-declared volumes via the "ai.privasys.volume" label.
	// This lets each container image declare its own disk mount
	// (e.g. LABEL ai.privasys.volume="/mnt/model-gemma4-31b:/models:ro").
	if v, ok := imgSpec.Config.Labels["ai.privasys.volume"]; ok {
		parts := strings.SplitN(v, ":", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("container: invalid ai.privasys.volume label %q (expected host:container[:ro|rw])", v)
		}
		mountOpts := "ro"
		if len(parts) == 3 {
			mountOpts = parts[2]
		}
		opts = append(opts, oci.WithMounts([]specs.Mount{{
			Destination: parts[1],
			Source:      parts[0],
			Type:        "bind",
			Options:     []string{"rbind", mountOpts},
		}}))
		m.log.Info("image-declared volume mount",
			zap.String("name", spec.Name),
			zap.String("source", parts[0]),
			zap.String("destination", parts[1]),
			zap.String("options", mountOpts),
		)
	}

	// Model roothash registry: expose disk-mounter's verified dm-verity
	// root hashes read-only at the canonical container path (see the
	// RoothashRegistry* consts). Skipped when the host has no registry
	// (no verity model disks mounted, or a non-GPU image).
	if st, err := os.Stat(RoothashRegistryHostDir); err == nil && st.IsDir() {
		opts = append(opts, oci.WithMounts([]specs.Mount{{
			Destination: RoothashRegistryContainerDir,
			Source:      RoothashRegistryHostDir,
			Type:        "bind",
			Options:     []string{"rbind", "ro"},
		}}))
	}

	// Volume bind mounts (format: "host:container[:ro|rw]").
	if len(spec.Volumes) > 0 {
		mounts := make([]specs.Mount, 0, len(spec.Volumes))
		for _, v := range spec.Volumes {
			parts := strings.SplitN(v, ":", 3)
			if len(parts) < 2 {
				return nil, fmt.Errorf("container: invalid volume format %q (expected host:container[:ro|rw])", v)
			}
			mountOpts := "rw"
			if len(parts) == 3 {
				mountOpts = parts[2]
			}
			mounts = append(mounts, specs.Mount{
				Destination: parts[1],
				Source:      parts[0],
				Type:        "bind",
				Options:     []string{"rbind", mountOpts},
			})
		}
		opts = append(opts, oci.WithMounts(mounts))
	}

	// Clean up any stale container or snapshot from a prior failed
	// attempt (or a boot-disk swap that outlived containerd state) with
	// the same name. Without this, a half-created container/snapshot
	// leaks and prevents future loads. forceRemoveOrphan is the harder
	// fallback used when NewContainer still reports "already exists".
	if existing, err := m.client.LoadContainer(ctx, spec.Name); err == nil {
		// Delete any lingering task FIRST: containerd refuses to delete a
		// container that still has a task (even a STOPPED one), so a bare
		// Delete here silently fails and leaves the orphan — which then
		// breaks the next load with "container already exists". This bit
		// the upgrade flow when a transient load failure left a stopped
		// task behind.
		if t, terr := existing.Task(ctx, nil); terr == nil {
			_ = t.Kill(ctx, 9)
			_, _ = t.Delete(ctx)
		}
		_ = existing.Delete(ctx, client.WithSnapshotCleanup)
	}
	if snSvc := m.client.SnapshotService(""); snSvc != nil {
		_ = snSvc.Remove(ctx, spec.Name+"-snapshot")
	}

	// Create the container.
	containerOpts := []client.NewContainerOpts{
		client.WithImage(img),
		client.WithNewSnapshot(spec.Name+"-snapshot", img),
		client.WithNewSpec(opts...),
	}
	container, err := m.client.NewContainer(ctx, spec.Name, containerOpts...)
	if err != nil && errdefs.IsAlreadyExists(err) {
		// The best-effort cleanup above did not clear the orphan — most
		// often because its snapshot references image layers that are
		// gone (a boot-disk swap replaces the image but keeps containerd's
		// persistent state, so the old container record survives into the
		// new boot). WithSnapshotCleanup then fails and leaves the record.
		// Force-remove via the container store (no snapshot dependency)
		// and retry once. On a headless prod enclave this self-heal is the
		// only recovery — there is no shell to run `ctr delete`.
		m.log.Warn("container already exists after cleanup; force-removing orphan and retrying",
			zap.String("name", spec.Name))
		m.forceRemoveOrphan(ctx, spec.Name)
		container, err = m.client.NewContainer(ctx, spec.Name, containerOpts...)
	}
	if err != nil {
		return nil, fmt.Errorf("container: failed to create %s: %w", spec.Name, err)
	}

	// Create and start the task (== the running process).
	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil && errdefs.IsAlreadyExists(err) {
		// A dead-shim task record from the pre-swap boot survived (see
		// forceRemoveOrphan). Delete it via the task service and retry.
		m.log.Warn("task already exists after container create; force-removing orphan task and retrying",
			zap.String("name", spec.Name))
		if _, derr := m.client.TaskService().Delete(ctx, &tasks.DeleteTaskRequest{ContainerID: spec.Name}); derr != nil && !errdefs.IsNotFound(derr) {
			m.log.Warn("force-remove orphan task failed", zap.String("name", spec.Name), zap.Error(derr))
		}
		task, err = container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	}
	if err != nil {
		_ = container.Delete(ctx)
		return nil, fmt.Errorf("container: failed to create task for %s: %w", spec.Name, err)
	}

	if err := task.Start(ctx); err != nil {
		_, _ = task.Delete(ctx)
		_ = container.Delete(ctx)
		return nil, fmt.Errorf("container: failed to start task for %s: %w", spec.Name, err)
	}

	mc := &ManagedContainer{
		Name:      spec.Name,
		Spec:      spec,
		Status:    StatusRunning,
		Container: container,
		Task:      task,
	}

	m.mu.Lock()
	// Reuse the existing entry (from Pull) if present, updating its fields.
	if existing, ok := m.containers[spec.Name]; ok {
		existing.mu.Lock()
		existing.Spec = spec
		existing.Status = StatusRunning
		existing.Container = container
		existing.Task = task
		existing.mu.Unlock()
		mc = existing
	} else {
		m.containers[spec.Name] = mc
	}
	m.mu.Unlock()

	m.log.Info("container started", zap.String("name", spec.Name))
	return mc, nil
}

// forceRemoveOrphan hard-deletes every containerd record for `name` that
// the ordinary cleanup could not remove. A boot-disk swap keeps
// containerd's persistent state while killing the running shims, so the
// pre-swap build leaves behind BOTH a container record (whose snapshot now
// references gone image layers, so WithSnapshotCleanup fails) AND a task
// record (whose shim is dead, so the normal task Delete fails). Both then
// break the next Load — "container already exists" then "task already
// exists" — and the app runs on the enclave-wide fallback cert with no
// attestation quote. This nukes all three record types via the low-level
// services (task → container → snapshot), each best-effort; the retried
// NewContainer/NewTask is the real success signal. On a headless prod
// enclave (no sshd) this self-heal is the only recovery path.
func (m *Manager) forceRemoveOrphan(ctx context.Context, name string) {
	// 1. Task record — via the task service so a dead-shim task is removed
	//    even though container.Task()/Delete() can't reach the shim.
	if _, err := m.client.TaskService().Delete(ctx, &tasks.DeleteTaskRequest{ContainerID: name}); err != nil && !errdefs.IsNotFound(err) {
		m.log.Warn("force-remove: task-service delete failed", zap.String("name", name), zap.Error(err))
	}
	// 2. Container metadata record — bypasses the snapshot-cleanup path
	//    that failed above.
	if err := m.client.ContainerService().Delete(ctx, name); err != nil && !errdefs.IsNotFound(err) {
		m.log.Warn("force-remove: container-store delete failed", zap.String("name", name), zap.Error(err))
	}
	// 3. Snapshot (the records are gone regardless).
	if snSvc := m.client.SnapshotService(""); snSvc != nil {
		_ = snSvc.Remove(ctx, name+"-snapshot")
	}
}

// Stop stops and removes a container.
func (m *Manager) Stop(ctx context.Context, name string) error {
	ctx = m.ctx(ctx)

	m.mu.RLock()
	mc, ok := m.containers[name]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("container: %s not found", name)
	}

	m.log.Info("stopping container", zap.String("name", name))

	// Stop the health-check goroutine so it doesn't outlive the container
	// and keep probing a dead/old port (the leak fixed here).
	mc.mu.Lock()
	if mc.healthCancel != nil {
		mc.healthCancel()
		mc.healthCancel = nil
	}
	mc.mu.Unlock()

	if mc.Task != nil {
		if err := mc.Task.Kill(ctx, 15); err != nil { // SIGTERM
			m.log.Warn("failed to send SIGTERM", zap.String("name", name), zap.Error(err))
		}
		// Wait for exit (with timeout).
		exitCh, err := mc.Task.Wait(ctx)
		if err == nil {
			select {
			case <-exitCh:
			case <-time.After(10 * time.Second):
				m.log.Warn("SIGTERM timeout, sending SIGKILL", zap.String("name", name))
				_ = mc.Task.Kill(ctx, 9)
			}
		}
		_, _ = mc.Task.Delete(ctx)
	}

	if mc.Container != nil {
		_ = mc.Container.Delete(ctx, client.WithSnapshotCleanup)
	}

	mc.SetStatus(StatusStopped)

	m.mu.Lock()
	delete(m.containers, name)
	m.mu.Unlock()

	m.log.Info("container stopped", zap.String("name", name))
	return nil
}

// Pause freezes the container's task via the cgroup freezer. The process stops
// consuming CPU but keeps its memory and state, so Resume restores it instantly.
// Non-destructive (the container + volume stay loaded) — used for the
// host-driven billing freeze (credits exhausted). No-op if already frozen.
func (m *Manager) Pause(ctx context.Context, name string) error {
	ctx = m.ctx(ctx)
	m.mu.RLock()
	mc, ok := m.containers[name]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("container: %s not found", name)
	}
	if mc.Task == nil {
		return fmt.Errorf("container: %s has no task", name)
	}
	if err := mc.Task.Pause(ctx); err != nil {
		return fmt.Errorf("pause %s: %w", name, err)
	}
	mc.SetStatus(StatusFrozen)
	m.log.Info("container frozen (paused)", zap.String("name", name))
	return nil
}

// Resume lifts a Pause, returning the container to the running state. No-op if
// the container is not currently frozen.
func (m *Manager) Resume(ctx context.Context, name string) error {
	ctx = m.ctx(ctx)
	m.mu.RLock()
	mc, ok := m.containers[name]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("container: %s not found", name)
	}
	if mc.Task == nil {
		return fmt.Errorf("container: %s has no task", name)
	}
	if err := mc.Task.Resume(ctx); err != nil {
		return fmt.Errorf("resume %s: %w", name, err)
	}
	mc.SetStatus(StatusRunning)
	m.log.Info("container resumed (unfrozen)", zap.String("name", name))
	return nil
}

// StopAll stops all managed containers.
func (m *Manager) StopAll(ctx context.Context) {
	m.mu.RLock()
	names := make([]string, 0, len(m.containers))
	for name := range m.containers {
		names = append(names, name)
	}
	m.mu.RUnlock()

	for _, name := range names {
		if err := m.Stop(ctx, name); err != nil {
			m.log.Error("failed to stop container", zap.String("name", name), zap.Error(err))
		}
	}
}

// Get returns the ManagedContainer by name.
func (m *Manager) Get(name string) (*ManagedContainer, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	mc, ok := m.containers[name]
	return mc, ok
}

// List returns all managed containers.
func (m *Manager) List() []*ManagedContainer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*ManagedContainer, 0, len(m.containers))
	for _, mc := range m.containers {
		result = append(result, mc)
	}
	return result
}

// RunHealthCheck runs a single health check iteration for a container.
func (m *Manager) RunHealthCheck(ctx context.Context, mc *ManagedContainer) error {
	hc := mc.Spec.HealthCheck
	if hc == nil {
		return nil
	}

	timeout := time.Duration(hc.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = healthCheckDefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if hc.HTTP != "" {
		return httpHealthCheck(ctx, hc.HTTP)
	}
	if hc.TCP != "" {
		return tcpHealthCheck(ctx, hc.TCP)
	}
	return nil
}

// StartHealthChecks starts a background goroutine that periodically runs
// health checks for the given container.
//
// onReadinessTimeout, if non-nil, is invoked when a freshly started container
// never passes a single health check within HealthCheck.ReadinessTimeoutSeconds
// (the launcher wires this to a full Unload). It frees the container's host
// port so a misbehaving app — e.g. one that ignores the injected $PORT — cannot
// linger and collide with co-located apps.
func (m *Manager) StartHealthChecks(ctx context.Context, mc *ManagedContainer, onReadinessTimeout func()) {
	hc := mc.Spec.HealthCheck
	if hc == nil {
		return
	}

	interval := time.Duration(hc.IntervalSeconds) * time.Second
	if interval == 0 {
		interval = healthCheckDefaultInterval
	}
	retries := hc.Retries
	if retries == 0 {
		retries = healthCheckDefaultRetries
	}
	readiness := time.Duration(hc.ReadinessTimeoutSeconds) * time.Second

	// Tie the goroutine to the container lifecycle: a derived cancellable
	// context, stored so Stop can end it. Cancel any prior goroutine first
	// (a reload restarts checks against the new spec/port).
	hctx, cancel := context.WithCancel(ctx)
	mc.mu.Lock()
	if mc.healthCancel != nil {
		mc.healthCancel()
	}
	mc.healthCancel = cancel
	mc.mu.Unlock()

	go func() {
		failures := 0
		everHealthy := false
		started := time.Now()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-hctx.Done():
				return
			case <-ticker.C:
				if err := m.RunHealthCheck(hctx, mc); err != nil {
					failures++
					m.log.Warn("health check failed",
						zap.String("name", mc.Name),
						zap.Int("failures", failures),
						zap.Error(err),
					)
					if failures >= retries {
						mc.SetStatus(StatusUnhealthy)
					}
					// Readiness deadline: a container that has not passed a
					// single health check within the window never bound its
					// allocated port. Tear it down so it can't sit on a wrong
					// port and collide with co-located apps. Only applies before
					// the first success — once healthy, transient failures are
					// handled by the unhealthy path above.
					if !everHealthy && readiness > 0 && time.Since(started) > readiness {
						m.log.Error("container failed readiness deadline; tearing down",
							zap.String("name", mc.Name),
							zap.Duration("readiness_timeout", readiness),
							zap.Int("failures", failures),
						)
						mc.SetStatus(StatusFailed)
						if onReadinessTimeout != nil {
							go onReadinessTimeout()
						}
						return
					}
				} else {
					if failures > 0 {
						m.log.Info("health check recovered",
							zap.String("name", mc.Name),
						)
					}
					failures = 0
					everHealthy = true
					mc.SetStatus(StatusHealthy)
				}
			}
		}
	}()
}

// ContainerdVersionHash returns the SHA-256 hash of the containerd server
// version string. This is embedded in OID 1.3.6.1.4.1.65230.2.4.
func (m *Manager) ContainerdVersionHash(ctx context.Context) ([]byte, error) {
	ctx = m.ctx(ctx)
	version, err := m.client.Version(ctx)
	if err != nil {
		return nil, fmt.Errorf("container: failed to get containerd version: %w", err)
	}
	h := sha256.Sum256([]byte(version.Version))
	return h[:], nil
}

// ImageDescriptor returns the OCI descriptor for a pulled image.
func (m *Manager) ImageDescriptor(ctx context.Context, ref string) (*ocispec.Descriptor, error) {
	ctx = m.ctx(ctx)
	img, err := m.client.GetImage(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("container: image %s not found: %w", ref, err)
	}
	desc := img.Target()
	return &desc, nil
}

// httpHealthCheck performs an HTTP GET health check.
func httpHealthCheck(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("health check returned %d", resp.StatusCode)
	}
	return nil
}

// tcpHealthCheck performs a TCP connection health check.
func tcpHealthCheck(ctx context.Context, addr string) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// digestToBytes parses a "sha256:hex" string into raw bytes.
func digestToBytes(digest string) ([]byte, error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid digest format: %s", digest)
	}
	return hex.DecodeString(parts[1])
}
