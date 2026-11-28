package directtls

import (
	"context"
	"errors"
	"sync"

	"github.com/caddyserver/certmagic"
)

// errAppStopped refuses a write by an app whose names were stopped.
var errAppStopped = errors.New("directtls: this app's certificate management was stopped")

// appStorage is one app's view of the shared storage. Once stop returns, the
// app writes nothing more: stopping cancels the app's issuance, but certmagic
// cannot be waited on, and a certificate it was still obtaining could land
// after the name was released and purged, where the name's next owner reads
// it. stop waits for a write already under way; every later write, delete or
// lock is refused.
type appStorage struct {
	*certmagic.FileStorage
	mu      sync.RWMutex
	stopped bool
}

func newAppStorage(fs *certmagic.FileStorage) *appStorage {
	return &appStorage{FileStorage: fs}
}

// stop refuses every later write and returns once none is under way.
func (a *appStorage) stop() {
	a.mu.Lock()
	a.stopped = true
	a.mu.Unlock()
}

func (a *appStorage) write(fn func() error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.stopped {
		return errAppStopped
	}
	return fn()
}

func (a *appStorage) Store(ctx context.Context, key string, value []byte) error {
	return a.write(func() error { return a.FileStorage.Store(ctx, key, value) })
}

func (a *appStorage) Delete(ctx context.Context, key string) error {
	return a.write(func() error { return a.FileStorage.Delete(ctx, key) })
}

// Lock and Unlock write lock files named after the certificate, which the
// name's next owner uses too: a stopped app neither takes nor removes one (a
// lock it left goes stale on its own).
func (a *appStorage) Lock(ctx context.Context, name string) error {
	return a.write(func() error { return a.FileStorage.Lock(ctx, name) })
}

func (a *appStorage) Unlock(ctx context.Context, name string) error {
	return a.write(func() error { return a.FileStorage.Unlock(ctx, name) })
}
