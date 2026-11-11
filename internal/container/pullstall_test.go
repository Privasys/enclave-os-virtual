package container

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPullStallCancelsWhenNothingArrives(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	go watchPullStall(ctx, cancel, 5*time.Millisecond, 40*time.Millisecond, func() int64 { return 7 })

	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a pull receiving nothing must be cancelled")
	}
	var stalled errPullStalled
	if !errors.As(context.Cause(ctx), &stalled) {
		t.Fatalf("cause = %v, want errPullStalled", context.Cause(ctx))
	}
}

func TestPullStallKeepsAPullThatReceivesBytes(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var got atomic.Int64
	go watchPullStall(ctx, cancel, 5*time.Millisecond, 40*time.Millisecond, func() int64 { return got.Add(1) })

	time.Sleep(200 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatalf("a pull still receiving bytes was cancelled: %v", context.Cause(ctx))
	}
}
