package main

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/trustedtime"
)

// startTrustedClock installs the trusted clock this process reads through
// trustedtime.Now (the vault client stamps and checks its quotes with it)
// and waits until it answers, at most until ctx is done or wait elapses.
//
// The bootstrap runs before /data is mounted, so the clock keeps its state
// in memory: its floor starts at the build minimum and its first answer
// comes from an NTS quorum, never from the host clock alone. The manager
// installs its own persistent clock once /data is open.
func startTrustedClock(ctx context.Context, log *zap.Logger, wait time.Duration) error {
	clock, err := trustedtime.New(trustedtime.Options{Log: log})
	if err != nil {
		return fmt.Errorf("trusted clock: %w", err)
	}
	trustedtime.Install(clock)
	go func() { _ = clock.Run(ctx) }()

	deadline := time.Now().Add(wait)
	for {
		_, err := clock.Now()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no trusted time after %s: %w", wait, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no trusted time: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
