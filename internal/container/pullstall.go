package container

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PullStallTimeout is how long an image pull may go without receiving a byte
// before it is abandoned. A pull has no overall time limit, since a large image
// on a slow link legitimately takes long, but a stalled one must end: the load
// it belongs to blocks every later load of that app, and an endless "pulling"
// tells the owner nothing. Bytes are counted as they arrive (containerd's
// ingest offsets), so a slow layer keeps the pull alive.
var PullStallTimeout = 10 * time.Minute

// pullStallCheck is how often a pull's progress is sampled.
var pullStallCheck = 15 * time.Second

// errPullStalled is the cause a stalled pull is cancelled with.
type errPullStalled struct{ limit time.Duration }

func (e errPullStalled) Error() string {
	return fmt.Sprintf("the image download received nothing for %s", e.limit)
}

// watchPullStall cancels the pull when progress() has not moved for limit. It
// returns when ctx ends. progress may only grow or restart; any change counts
// as movement, since a retried attempt starts its count again.
func watchPullStall(ctx context.Context, cancel context.CancelCauseFunc, every, limit time.Duration, progress func() int64) {
	t := time.NewTicker(every)
	defer t.Stop()
	last := progress()
	movedAt := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if p := progress(); p != last {
				last, movedAt = p, now
				continue
			}
			if now.Sub(movedAt) >= limit {
				cancel(errPullStalled{limit: limit})
				return
			}
		}
	}
}

// ingestedBytes sums the bytes received so far by the content ingests that
// belong to this pull. containerd names a pull's ingests after the blob
// digests ("layer-sha256:<hex>"), so they are matched on those.
func (m *Manager) ingestedBytes(ctx context.Context, digests []string) int64 {
	if len(digests) == 0 {
		return 0
	}
	statuses, err := m.client.ContentStore().ListStatuses(ctx)
	if err != nil {
		return 0
	}
	var n int64
	for _, st := range statuses {
		for _, d := range digests {
			if strings.HasSuffix(st.Ref, d) {
				n += st.Offset
				break
			}
		}
	}
	return n
}
