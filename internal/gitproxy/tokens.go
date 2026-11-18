package gitproxy

// The token cache (ADR-002 amendment 9). chapd mints one installation token
// per run, repository and permission set, on the first request that needs it,
// and reuses it for the rest of the run. Before, forward minted a token for
// every HTTP request and revoked it right after: about four GitHub calls per
// clone, and a first use of a fresh token for every request, which is the use
// GitHub answers 404 (amendment 8).
//
// A token lives in chapd's memory only. It is revoked when the run ends
// ([Handler.EndRun], called from the run registry's AfterEnd hook) and when
// chapd shuts down ([Handler.Close]). A run that ended gets no new token, even
// from a request that was admitted before the end.

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/ops"
)

const (
	// defaultTokenMargin is how long before expires_at a token stops being
	// reused. A request lasts up to requestTimeout (20 minutes), but GitHub
	// checks the token when the request starts, so the margin only has to
	// cover a slow start.
	defaultTokenMargin = 5 * time.Minute

	// endedTTL is how long chapd remembers that a run ended, so that a request
	// admitted just before the end cannot mint a token for it. A request is
	// admitted and reaches the cache within moments; the hour is far above that.
	endedTTL = time.Hour
)

// tokenKey names one cached token: amendment 9 "run ID + repo + permission set".
type tokenKey struct {
	run, repo, perms string
}

// tokenEntry is one token, or the mint that is making it. ready is closed when
// tok or err is set, so two first requests with the same key share one mint.
type tokenEntry struct {
	ready chan struct{}
	tok   *gh.Token
	err   error
}

// permsKey is a stable name for a permission set.
func permsKey(perms map[string]string) string {
	parts := make([]string, 0, len(perms))
	for k, v := range perms {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) tokenMargin() time.Duration {
	if h.TokenMargin > 0 {
		return h.TokenMargin
	}
	return defaultTokenMargin
}

// fresh reports whether tok may serve a request that starts now.
func (h *Handler) fresh(tok *gh.Token) bool {
	return tok.ExpiresAt().Sub(h.now()) > h.tokenMargin()
}

// acquire returns the token for this caller's run, the repository and the
// permission set, minting it when there is none that is fresh. done is for the
// caller to run when its request is over; refused is true when GitHub answered
// 401, which means the token is dead (revoked by someone else, say): a cached
// token is then dropped, so the next request mints a new one and the run does
// not fail until the old one would have expired. Every error acquire returns
// is ready for the client ([ops.VerifyError] for an ended run,
// [ops.UnavailableError] otherwise).
//
// A caller that is not a run has no run to end, so its token is not cached:
// it is single-use and done revokes it. The gate refuses such callers, so
// this is a fallback only.
func (h *Handler) acquire(ctx context.Context, c *ops.Caller, repo gh.Repo, perms map[string]string) (tok *gh.Token, done func(refused bool), err error) {
	if c.Kind != ops.KindRun || c.RunID == "" {
		tok, err := h.mint(ctx, repo, perms)
		if err != nil {
			return nil, nil, err
		}
		return tok, func(bool) { h.revoke(tok) }, nil
	}
	k := tokenKey{run: c.RunID, repo: repo.String(), perms: permsKey(perms)}
	tok, err = h.cached(ctx, k, repo, perms)
	if err != nil {
		return nil, nil, err
	}
	return tok, func(refused bool) {
		if refused {
			h.drop(k, tok)
		}
	}, nil
}

// drop removes tok from the cache and revokes it, if it is still the one cached
// for k. When it is not (the run ended, or a newer token replaced it), whoever
// took it out owns its revocation.
func (h *Handler) drop(k tokenKey, tok *gh.Token) {
	h.mu.Lock()
	e := h.toks[k]
	cached := e != nil && e.tok == tok
	if cached {
		delete(h.toks, k)
	}
	h.mu.Unlock()
	if cached {
		h.revoke(tok) // GitHub may answer 401: the token is dead already
	}
}

// mint asks the minter for a token; the error is ready for the client.
func (h *Handler) mint(ctx context.Context, repo gh.Repo, perms map[string]string) (*gh.Token, error) {
	tok, err := h.Tokens.Mint(ctx, repo, perms)
	if err != nil {
		h.log().Error("gitproxy: could not mint a token", "repo", repo.String(), "err", err)
		return nil, &ops.UnavailableError{Why: "chapd could not get a GitHub token; nothing was sent", Retryable: true, Err: err}
	}
	return tok, nil
}

func errRunEnded() error {
	return &ops.VerifyError{Code: ops.CodeTokenRevoked, Detail: "the run has ended"}
}

func errClosed() error {
	return &ops.UnavailableError{Why: "chapd is shutting down; nothing was sent", Retryable: true}
}

// cached is the single-flight lookup: the first caller of a key mints, the
// others wait for that mint. A token near its end is replaced.
func (h *Handler) cached(ctx context.Context, k tokenKey, repo gh.Repo, perms map[string]string) (*gh.Token, error) {
	for {
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			return nil, errClosed()
		}
		if _, gone := h.ended[k.run]; gone {
			h.mu.Unlock()
			return nil, errRunEnded()
		}
		e := h.toks[k]
		if e == nil {
			e = &tokenEntry{ready: make(chan struct{})}
			if h.toks == nil {
				h.toks = make(map[tokenKey]*tokenEntry)
			}
			h.toks[k] = e
			h.mu.Unlock()
			return h.lead(ctx, k, e, repo, perms)
		}
		select {
		case <-e.ready:
			if e.err == nil && h.fresh(e.tok) {
				h.mu.Unlock()
				return e.tok, nil
			}
			// Near its end (a failed mint removes its own entry). A request
			// that already holds the old token may still be using it, so it is
			// not revoked yet: EndRun and Close do that.
			if e.tok != nil {
				h.retire(k.run, e.tok)
			}
			if h.toks[k] == e {
				delete(h.toks, k)
			}
			h.mu.Unlock()
			continue
		default:
		}
		h.mu.Unlock()
		select {
		case <-e.ready: // look again: the mint may have failed
		case <-ctx.Done():
			return nil, &ops.UnavailableError{Why: "the request ended while chapd waited for a GitHub token; nothing was sent", Err: ctx.Err()}
		}
	}
}

// lead mints the token of e, which cached put in the map.
func (h *Handler) lead(ctx context.Context, k tokenKey, e *tokenEntry, repo gh.Repo, perms map[string]string) (*gh.Token, error) {
	tok, err := h.mint(ctx, repo, perms)
	var stale *gh.Token // minted, but the run ended or chapd closed meanwhile

	h.mu.Lock()
	_, ended := h.ended[k.run]
	switch {
	case err != nil:
		e.err = err
	case h.closed || ended:
		stale = tok
		e.err = errRunEnded()
		if h.closed {
			e.err = errClosed()
		}
		err = e.err
	default:
		e.tok = tok
	}
	if e.err != nil && h.toks[k] == e {
		delete(h.toks, k)
	}
	h.mu.Unlock()
	close(e.ready)

	if stale != nil {
		h.revoke(stale)
	}
	if err != nil {
		return nil, err
	}
	h.log().Debug("gitproxy: minted a token for the run", "run", k.run, "repo", k.repo, "expires", tok.ExpiresAt())
	return tok, nil
}

// retire keeps a token that was replaced until the run ends, and drops the
// ones that have expired by themselves. Call with h.mu held.
func (h *Handler) retire(run string, tok *gh.Token) {
	now := h.now()
	keep := h.retired[run][:0]
	for _, t := range h.retired[run] {
		if t.ExpiresAt().After(now) {
			keep = append(keep, t)
		} else {
			t.Wipe()
		}
	}
	if h.retired == nil {
		h.retired = make(map[string][]*gh.Token)
	}
	h.retired[run] = append(keep, tok)
}

// EndRun marks every token chapd holds for the run dead and refuses to mint
// another for it, then returns: from that moment a request of the run is
// TOKEN_REVOKED, whatever GitHub does. The run registry calls it after the
// run's end committed (ADR-005, step "End"); ending a run twice is harmless.
//
// The tokens are revoked on GitHub in the background, on a context that
// outlives the caller (at most revokeTimeout each), so a GitHub outage does
// not slow the end of a run or `runner stop --all`. [Handler.WaitRevokes]
// and [Handler.Close] wait for them.
func (h *Handler) EndRun(runID string) {
	h.mu.Lock()
	now := h.now()
	if h.ended == nil {
		h.ended = make(map[string]time.Time)
	}
	for id, at := range h.ended {
		if now.Sub(at) > endedTTL {
			delete(h.ended, id)
		}
	}
	h.ended[runID] = now
	toks := h.takeLocked(func(k tokenKey) bool { return k.run == runID })
	toks = append(toks, h.retired[runID]...)
	delete(h.retired, runID)
	// After Close nothing is left to take, so toks is empty then; the check
	// keeps Add from racing Close's Wait whatever happens later.
	async := len(toks) > 0 && !h.closed
	if async {
		h.revokes.Add(1)
	}
	h.mu.Unlock()

	switch {
	case async:
		go func() {
			defer h.revokes.Done()
			h.revokeAll(toks)
		}()
	case len(toks) > 0:
		h.revokeAll(toks)
	}
}

// Close revokes every token chapd holds, for every run, and refuses to mint more.
// It is best effort: a token that could not be revoked expires on its own within
// the hour. chapd calls it when it shuts down.
func (h *Handler) Close() {
	h.mu.Lock()
	h.closed = true
	toks := h.takeLocked(func(tokenKey) bool { return true })
	for run, ts := range h.retired {
		toks = append(toks, ts...)
		delete(h.retired, run)
	}
	h.mu.Unlock()

	h.revokeAll(toks)
	h.revokes.Wait() // revokes EndRun started: chapd must not exit before them
}

// WaitRevokes returns when every revoke that [Handler.EndRun] started has
// finished. chapd does not need it (Close waits); tests use it to look at
// GitHub after a run ended.
func (h *Handler) WaitRevokes() {
	h.revokes.Wait()
}

// takeLocked removes the entries that match from the map and returns their
// tokens. A mint that is still running has no token yet; it sees the end when
// it finishes (lead). Call with h.mu held.
func (h *Handler) takeLocked(match func(tokenKey) bool) []*gh.Token {
	var toks []*gh.Token
	for k, e := range h.toks {
		if !match(k) {
			continue
		}
		delete(h.toks, k)
		select {
		case <-e.ready:
			if e.tok != nil {
				toks = append(toks, e.tok)
			}
		default:
		}
	}
	return toks
}

// revokeAll revokes the tokens at the same time, so one slow answer from GitHub
// does not add up.
func (h *Handler) revokeAll(toks []*gh.Token) {
	var wg sync.WaitGroup
	for _, t := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.revoke(t)
		}()
	}
	wg.Wait()
}
