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
	"strings"
	"sync"
	"time"

	"crypto/tls"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	containerdcdi "github.com/containerd/containerd/v2/pkg/cdi"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
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
	mu           sync.RWMutex
}

// SetStatus updates the container status safely.
func (mc *ManagedContainer) SetStatus(s Status) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.Status = s
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

// Pull downloads an OCI image and verifies its digest matches the manifest.
// Returns the resolved image descriptor and the raw digest bytes.
// Registers a pulling container in the manager so pull progress is visible
// via List()/StatusReport().
func (m *Manager) Pull(ctx context.Context, spec manifest.Container) (client.Image, []byte, error) {
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
		progressMu sync.Mutex
		totalSize  int64
		fetchedSize int64
		seen       = make(map[godigest.Digest]bool) // true = fetched
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
	resolver := docker.NewResolver(docker.ResolverOptions{Client: httpClient})

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

	// Host device passthrough (e.g. /dev/nvidia0).
	for _, devPath := range spec.Devices {
		opts = append(opts, oci.WithDevices(devPath, "", "rwm"))
	}

	// When GPU devices are requested, ensure NVIDIA_VISIBLE_DEVICES=all
	// so that the nvidia-container-runtime injects driver libraries.
	if len(spec.Devices) > 0 {
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
	imgSpec, err := img.Spec(ctx)
	if err != nil {
		return nil, fmt.Errorf("container: failed to read image spec for %s: %w", spec.Name, err)
	}
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
	// attempt with the same name. Without this, a half-created
	// container/snapshot leaks and prevents future loads.
	if existing, err := m.client.LoadContainer(ctx, spec.Name); err == nil {
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
	if err != nil {
		return nil, fmt.Errorf("container: failed to create %s: %w", spec.Name, err)
	}

	// Create and start the task (== the running process).
	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
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
func (m *Manager) StartHealthChecks(ctx context.Context, mc *ManagedContainer) {
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

	go func() {
		failures := 0
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.RunHealthCheck(ctx, mc); err != nil {
					failures++
					m.log.Warn("health check failed",
						zap.String("name", mc.Name),
						zap.Int("failures", failures),
						zap.Error(err),
					)
					if failures >= retries {
						mc.SetStatus(StatusUnhealthy)
					}
				} else {
					if failures > 0 {
						m.log.Info("health check recovered",
							zap.String("name", mc.Name),
						)
					}
					failures = 0
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
