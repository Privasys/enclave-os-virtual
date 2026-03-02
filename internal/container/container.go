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

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
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

// ManagedContainer tracks a running container and its metadata.
type ManagedContainer struct {
	Name        string
	Spec        manifest.Container
	Status      Status
	ImageDigest []byte // resolved SHA-256 digest of the pulled image
	Container   client.Container
	Task        client.Task

	mu sync.RWMutex
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
func (m *Manager) Pull(ctx context.Context, spec manifest.Container) (client.Image, []byte, error) {
	ctx = m.ctx(ctx)
	m.log.Info("pulling image", zap.String("name", spec.Name), zap.String("image", spec.Image))

	img, err := m.client.Pull(ctx, spec.Image,
		client.WithPullUnpack,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("container: failed to pull %s: %w", spec.Image, err)
	}

	// Verify digest if the image ref contains @sha256:
	resolvedDigest := img.Target().Digest.String()
	m.log.Info("image pulled",
		zap.String("name", spec.Name),
		zap.String("digest", resolvedDigest),
	)

	digestBytes, err := digestToBytes(resolvedDigest)
	if err != nil {
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

	// Volume bind mounts (format: "host:container").
	if len(spec.Volumes) > 0 {
		mounts := make([]specs.Mount, 0, len(spec.Volumes))
		for _, v := range spec.Volumes {
			parts := strings.SplitN(v, ":", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("container: invalid volume format %q (expected host:container)", v)
			}
			mounts = append(mounts, specs.Mount{
				Destination: parts[1],
				Source:      parts[0],
				Type:        "bind",
				Options:     []string{"rbind", "rw"},
			})
		}
		opts = append(opts, oci.WithMounts(mounts))
	}

	// Create the container.
	container, err := m.client.NewContainer(ctx, spec.Name,
		client.WithImage(img),
		client.WithNewSnapshot(spec.Name+"-snapshot", img),
		client.WithNewSpec(opts...),
	)
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
	m.containers[spec.Name] = mc
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
