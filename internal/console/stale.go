package console

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
)

// A pending merge card can go stale while it waits: another merge moves the base branch, CI turns red, the policy
// changes. Approving it then spends a Windows Hello on an op that is refused when it is released (review item 1). The
// console asks the op service for a read-only look at each pending pr.merge card when it draws the list and flags a
// card that would be refused now. The flag is page chrome outside the card text (`.approval-text`): it is not signed,
// it does not block Approve (the same checks run again at release), and it only ever warns.
//
// A look costs GitHub calls (a short-lived read token and a few API reads), and a page load must not wait on them
// without limit, so: one look per card is shared by every page load that needs it while it runs; a look that fails or
// runs out of time is remembered as "could not check" for as long as a good one; a page waits at most staleTimeout
// and then draws what it has (a late look only fills the cache); and only staleMaxFlight looks run at once.

const (
	staleTTL       = 30 * time.Second // a look, good or failed, is reused this long, so reloading the page does not ask GitHub every time
	staleTimeout   = 4 * time.Second  // a page waits at most this long for the looks; a slow one shows "could not check"
	staleMaxFlight = 8                // looks that may run at once
)

// Why a card could not be checked, in words for the page. None quotes an error: the error is logged, not drawn.
const (
	unknownSlow   = "it did not answer in time"
	unknownBusy   = "too many checks were already running"
	unknownFailed = "the check failed"
)

// staleLook is what one look found. unknown, when set, says why no verdict could be had.
type staleLook struct {
	at      time.Time
	stale   bool
	why     string
	newCard bool
	unknown string
}

// staleCall is a look in flight. done closes when look is set; the waiters read look only after done.
type staleCall struct {
	done chan struct{}
	look staleLook
}

type staleCache struct {
	mu     sync.Mutex
	m      map[string]staleLook
	flying map[string]*staleCall
	// timeout and maxFlight are staleTimeout and staleMaxFlight unless a test sets them.
	timeout   time.Duration
	maxFlight int
}

// staleNote is what the page says about a card: the reason it would be refused now (Why), or why no look could be
// made (Unknown, one of the unknown* sentences). NewCard is set when only a new card can help (see StaleCheck). A card
// that would run has no note.
type staleNote struct {
	Why     string
	Unknown string
	NewCard bool
}

func (l staleLook) note() (staleNote, bool) {
	switch {
	case l.stale:
		return staleNote{Why: l.why, NewCard: l.newCard}, true
	case l.unknown != "":
		return staleNote{Unknown: l.unknown}, true
	}
	return staleNote{}, false
}

// staleFlags returns a note for each pending pr.merge card that would be refused now, or that it could not judge in
// time (GitHub unreachable, too slow, too many looks running). A card that would run has no entry. With no Recheck
// configured (the feature is off) nothing is returned.
func (c *Console) staleFlags(ctx context.Context, pending []*approvals.Approval) map[string]staleNote {
	out := map[string]staleNote{}
	if c.apprOpts.Recheck == nil {
		return out
	}
	now := c.now()
	waits := map[string]*staleCall{}
	c.stale.mu.Lock()
	if c.stale.m == nil {
		c.stale.m = map[string]staleLook{}
		c.stale.flying = map[string]*staleCall{}
	}
	timeout, maxFlight := c.stale.timeout, c.stale.maxFlight
	if timeout <= 0 {
		timeout = staleTimeout
	}
	if maxFlight <= 0 {
		maxFlight = staleMaxFlight
	}
	for id, l := range c.stale.m { // forget old looks
		if now.Sub(l.at) > 10*time.Minute {
			delete(c.stale.m, id)
		}
	}
	for _, a := range pending {
		if a.Op != "pr.merge" || a.State != approvals.StatePending {
			continue
		}
		if l, ok := c.stale.m[a.ID]; ok && now.Sub(l.at) < staleTTL {
			if n, ok := l.note(); ok {
				out[a.ID] = n
			}
			continue
		}
		if call, ok := c.stale.flying[a.ID]; ok { // share the look already running
			waits[a.ID] = call
			continue
		}
		if len(c.stale.flying) >= maxFlight { // too many running: no look now, a later load tries again
			out[a.ID] = staleNote{Unknown: unknownBusy}
			continue
		}
		call := &staleCall{done: make(chan struct{})}
		c.stale.flying[a.ID] = call
		waits[a.ID] = call
		go c.runStaleLook(ctx, a, call, timeout)
	}
	c.stale.mu.Unlock()
	if len(waits) == 0 {
		return out
	}

	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for id, call := range waits {
		select {
		case <-call.done:
		case <-wctx.Done():
			// Stop waiting. A deadline (not a client that went away) is remembered as "could not check" so the next
			// loads do not wait again; the look that is still running overwrites it when it ends.
			if errors.Is(wctx.Err(), context.DeadlineExceeded) {
				c.stale.mu.Lock()
				if c.stale.flying[id] == call {
					c.stale.m[id] = staleLook{at: c.now(), unknown: unknownSlow}
				}
				c.stale.mu.Unlock()
			}
			select {
			case <-call.done:
			default:
				out[id] = staleNote{Unknown: unknownSlow}
				continue
			}
		}
		if n, ok := call.look.note(); ok {
			out[id] = n
		}
	}
	return out
}

// runStaleLook runs one look for a, on a context of its own (a page that stopped waiting must not cancel a look other
// pages share), and records the result in the cache, a failure as well as a success.
func (c *Console) runStaleLook(ctx context.Context, a *approvals.Approval, call *staleCall, timeout time.Duration) {
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	chk, err := c.apprOpts.Recheck(lctx, a.RequestID)
	look := staleLook{stale: chk.Stale, why: chk.Why, newCard: chk.NewCard}
	if err != nil {
		c.log.Warn("stale check of a pending card failed", "approval", a.ID, "err", err)
		look = staleLook{unknown: unknownFailed}
		if lctx.Err() != nil {
			look.unknown = unknownSlow
		}
	}
	look.at = c.now()
	call.look = look
	c.stale.mu.Lock()
	c.stale.m[a.ID] = look
	delete(c.stale.flying, a.ID)
	c.stale.mu.Unlock()
	close(call.done)
}
