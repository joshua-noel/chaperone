package ops

import (
	"context"
	"strings"
	"sync"
)

// repoLocks is the per-repo mutex of ADR-002: one merge (or branch update) per
// repository at a time, mirroring "one merge at a time" in merge-procedure.md.
// A waiter gives up when its context ends, so a stuck merge cannot pile up
// callers forever. It does not cover a human merging in the GitHub UI.
type repoLocks struct {
	mu sync.Mutex
	m  map[string]chan struct{}
}

func (l *repoLocks) slot(key string) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = make(map[string]chan struct{})
	}
	c := l.m[key]
	if c == nil {
		c = make(chan struct{}, 1)
		l.m[key] = c
	}
	return c
}

// lock takes the lock for repo (case-insensitive, as GitHub names are) and
// returns the function that releases it.
func (l *repoLocks) lock(ctx context.Context, repo string) (func(), error) {
	c := l.slot(strings.ToLower(repo))
	select {
	case c <- struct{}{}:
		return func() { <-c }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
