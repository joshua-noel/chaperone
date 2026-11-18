package gitproxy_test

// Tests of the token cache (ADR-002 amendment 9): one installation token per
// run, repository and permission set, kept until the run ends. They use the
// fake GitHub of retryRig; the clock is the fake's (Server.Now, Advance), and
// nothing sleeps. The race detector needs cgo, which the factory builds
// without, so the concurrency tests assert what holds in every interleaving
// (one mint) and use a blocked mint only to make the overlap likely.

import (
	"context"
	"errors"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/gitproxy"
	"github.com/joshua-noel/chaperone/internal/ops"
)

func runCaller(id string) *ops.Caller {
	return &ops.Caller{Kind: ops.KindRun, RunID: id}
}

func okRig(t *testing.T) *retryRig {
	t.Helper()
	return newRetryRig(t, func(int) int { return 0 })
}

// discover serves a discovery GET of acme/<repo> for service ("git-upload-pack"
// is a fetch, "git-receive-pack" a push).
func (f *retryRig) discover(c *ops.Caller, repo, service string) error {
	req := httptest.NewRequest("GET", "/git/acme/"+repo+".git/info/refs?service="+service, nil)
	return f.h.ServeGit(httptest.NewRecorder(), req, c)
}

func (f *retryRig) mustDiscover(c *ops.Caller, repo, service string) {
	f.t.Helper()
	if err := f.discover(c, repo, service); err != nil {
		f.t.Fatalf("%s %s for %s: %v", service, repo, c.RunID, err)
	}
}

// tokensSeen are the distinct installation tokens the upstream got, in the
// order of their first use.
func (f *retryRig) tokensSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.reqs {
		if !slices.Contains(out, r.password) {
			out = append(out, r.password)
		}
	}
	return out
}

const (
	fetchSvc = "git-upload-pack"
	pushSvc  = "git-receive-pack"
)

func TestTokenIsReusedForTheSameRunRepoAndPerms(t *testing.T) {
	f := okRig(t)
	c := runCaller("r-1")
	for range 3 {
		f.mustDiscover(c, "shop", fetchSvc)
	}
	if _, err := f.post([]byte("0000"), 4); err != nil { // an upload-pack POST: a fetch as well
		t.Fatal(err)
	}
	if n := f.minted(); n != 1 {
		t.Errorf("%d tokens minted for four fetch requests of one run, want 1", n)
	}
	if got := f.tokensSeen(); len(got) != 1 || len(f.reqs) != 4 {
		t.Errorf("upstream saw %d distinct tokens in %d requests, want 1 in 4", len(got), len(f.reqs))
	}
	if n := f.gh.LiveTokens(); n != 1 {
		t.Errorf("%d tokens live, want the run's one", n)
	}
	for _, p := range f.tokensSeen() {
		if strings.Contains(f.log.String(), p) {
			t.Fatal("the log holds the token")
		}
	}
}

func TestOtherPermsRepoOrRunMintSeparately(t *testing.T) {
	f := okRig(t)
	a, b := runCaller("r-1"), runCaller("r-2")
	f.mustDiscover(a, "shop", fetchSvc)  // contents:read
	f.mustDiscover(a, "shop", pushSvc)   // push permissions
	f.mustDiscover(a, "other", fetchSvc) // another repository
	f.mustDiscover(b, "shop", fetchSvc)  // another run
	if n := f.minted(); n != 4 {
		t.Fatalf("%d tokens minted for four different (run, repo, perms), want 4", n)
	}
	if got := f.tokensSeen(); len(got) != 4 {
		t.Fatalf("upstream saw %d distinct tokens, want 4", len(got))
	}
	// And each one is reused by its own kind of request.
	f.mustDiscover(a, "shop", fetchSvc)
	f.mustDiscover(a, "shop", pushSvc)
	f.mustDiscover(a, "other", fetchSvc)
	f.mustDiscover(b, "shop", fetchSvc)
	if n := f.minted(); n != 4 {
		t.Errorf("%d tokens minted after the repeats, want still 4", n)
	}
}

func TestTokenNearItsEndIsReplaced(t *testing.T) {
	f := okRig(t)
	c := runCaller("r-1")
	f.mustDiscover(c, "shop", fetchSvc)

	// The fake's tokens last an hour; the margin is 5 minutes.
	f.gh.Advance(54 * time.Minute) // 6 minutes left: still used
	f.mustDiscover(c, "shop", fetchSvc)
	if n := f.minted(); n != 1 {
		t.Fatalf("%d tokens minted with 6 minutes left, want the first one reused", n)
	}
	f.gh.Advance(2 * time.Minute) // 4 minutes left: replaced
	f.mustDiscover(c, "shop", fetchSvc)
	if n := f.minted(); n != 2 {
		t.Fatalf("%d tokens minted with 4 minutes left, want a second", n)
	}
	if got := f.tokensSeen(); len(got) != 2 {
		t.Fatalf("upstream saw %d distinct tokens, want 2", len(got))
	}
	f.mustDiscover(c, "shop", fetchSvc)
	if n := f.minted(); n != 2 {
		t.Errorf("%d tokens minted, want the new one reused", n)
	}

	// The replaced token has not expired yet and a request may still use it, so
	// it lives on until the run ends, then goes with the other.
	if n := f.gh.LiveTokens(); n != 2 {
		t.Errorf("%d tokens live before the run ended, want 2", n)
	}
	f.h.EndRun("r-1")
	f.h.WaitRevokes()
	if n := f.gh.LiveTokens(); n != 0 {
		t.Errorf("%d tokens live after the run ended, want 0", n)
	}
}

func TestTokenMarginIsSettable(t *testing.T) {
	f := okRig(t)
	f.h.TokenMargin = 30 * time.Minute
	c := runCaller("r-1")
	f.mustDiscover(c, "shop", fetchSvc)
	f.gh.Advance(29 * time.Minute) // 31 minutes left
	f.mustDiscover(c, "shop", fetchSvc)
	if n := f.minted(); n != 1 {
		t.Fatalf("%d minted, want 1", n)
	}
	f.gh.Advance(2 * time.Minute) // 29 minutes left
	f.mustDiscover(c, "shop", fetchSvc)
	if n := f.minted(); n != 2 {
		t.Fatalf("%d minted, want 2", n)
	}
}

func TestRunEndRevokesItsTokensAndRefusesLaterRequests(t *testing.T) {
	f := okRig(t)
	a, b := runCaller("r-1"), runCaller("r-2")
	f.mustDiscover(a, "shop", fetchSvc)
	f.mustDiscover(a, "shop", pushSvc)
	f.mustDiscover(a, "other", fetchSvc)
	f.mustDiscover(b, "shop", fetchSvc)
	toks := f.tokensSeen()
	if len(toks) != 4 || f.gh.LiveTokens() != 4 {
		t.Fatalf("%d distinct tokens, %d live, want 4 and 4", len(toks), f.gh.LiveTokens())
	}

	f.h.EndRun("r-1")
	f.h.WaitRevokes()
	for i, tok := range toks[:3] {
		if !f.gh.TokenRevoked(tok) {
			t.Errorf("token %d of the ended run was not revoked", i+1)
		}
	}
	if f.gh.TokenRevoked(toks[3]) || f.gh.LiveTokens() != 1 {
		t.Errorf("the other run's token was touched (%d live, want 1)", f.gh.LiveTokens())
	}

	// A request of the ended run is refused, as the token verifier does, and
	// neither mints nor reaches GitHub.
	minted, sent := f.minted(), len(f.reqs)
	for _, svc := range []string{fetchSvc, pushSvc} {
		var ve *ops.VerifyError
		if err := f.discover(a, "shop", svc); !errors.As(err, &ve) || ve.Code != ops.CodeTokenRevoked {
			t.Errorf("%s after the end: %v, want TOKEN_REVOKED", svc, err)
		}
	}
	if f.minted() != minted || len(f.reqs) != sent {
		t.Errorf("a request after the end minted %d and sent %d", f.minted()-minted, len(f.reqs)-sent)
	}
	// The other run goes on with the token it has.
	f.mustDiscover(b, "shop", fetchSvc)
	if f.minted() != minted {
		t.Error("the other run minted again")
	}
	// Ending a run twice, or a run that never had a token, is harmless.
	f.h.EndRun("r-1")
	f.h.EndRun("r-never")
	f.h.WaitRevokes()
	if f.gh.LiveTokens() != 1 {
		t.Errorf("%d tokens live, want the other run's one", f.gh.LiveTokens())
	}
}

// A request that was admitted before the run ended can reach the cache after
// it, and must not leave a token behind for a run that is over.
func TestRunEndedWhileATokenIsBeingMinted(t *testing.T) {
	f := okRig(t)
	f.gh.Before("POST", "/access_tokens", func() { f.h.EndRun("r-1") })
	var ve *ops.VerifyError
	if err := f.discover(runCaller("r-1"), "shop", fetchSvc); !errors.As(err, &ve) || ve.Code != ops.CodeTokenRevoked {
		t.Fatalf("error %v, want TOKEN_REVOKED", err)
	}
	if n := f.gh.LiveTokens(); n != 0 {
		t.Errorf("%d tokens live: the token minted for an ended run was kept", n)
	}
	if len(f.reqs) != 0 {
		t.Errorf("%d requests reached GitHub", len(f.reqs))
	}
}

func TestConcurrentFirstUseMintsOnce(t *testing.T) {
	f := okRig(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.gh.Before("POST", "/access_tokens", func() {
		close(entered)
		<-release // the first mint is under way while the others arrive
	})
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- f.discover(runCaller("r-1"), "shop", fetchSvc)
		}()
	}
	<-entered
	for range 500 {
		runtime.Gosched() // let the others reach the cache and wait
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if got := f.minted(); got != 1 {
		t.Errorf("%d tokens minted by %d simultaneous first requests, want 1", got, n)
	}
	if got := f.tokensSeen(); len(got) != 1 || len(f.reqs) != n {
		t.Errorf("upstream saw %d distinct tokens in %d requests, want 1 in %d", len(got), len(f.reqs), n)
	}
}

// A request that waits for another's mint leaves when its own client does,
// and the mint it waited for still lands.
func TestWaiterLeavesWhenItsRequestEnds(t *testing.T) {
	f := okRig(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.gh.Before("POST", "/access_tokens", func() {
		close(entered)
		<-release
	})
	lead := make(chan error, 1)
	go func() { lead <- f.discover(runCaller("r-1"), "shop", fetchSvc) }()
	<-entered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", "/git/acme/shop.git/info/refs?service="+fetchSvc, nil).WithContext(ctx)
	var ue *ops.UnavailableError
	if err := f.h.ServeGit(httptest.NewRecorder(), req, runCaller("r-1")); !errors.As(err, &ue) {
		t.Fatalf("a waiter whose request ended got %v, want *ops.UnavailableError", err)
	}
	close(release)
	if err := <-lead; err != nil {
		t.Fatal(err)
	}
	if n := f.minted(); n != 1 {
		t.Errorf("%d tokens minted, want 1", n)
	}
}

func TestFailedMintIsNotRemembered(t *testing.T) {
	f := okRig(t)
	f.gh.Inject("POST", "/access_tokens", ghtest.Fault{Status: 422, Message: "nope", Times: 1})
	var ue *ops.UnavailableError
	if err := f.discover(runCaller("r-1"), "shop", fetchSvc); !errors.As(err, &ue) {
		t.Fatalf("error %v, want *ops.UnavailableError", err)
	}
	f.mustDiscover(runCaller("r-1"), "shop", fetchSvc)
	if n := f.gh.LiveTokens(); n != 1 {
		t.Errorf("%d tokens live after the retry, want 1", n)
	}
}

// GitHub answers 401 for a token that is dead (someone revoked it). Keeping it
// would fail every request of the run until it expired.
func TestTokenGitHubRefusesIsReplaced(t *testing.T) {
	f := newRetryRig(t, func(n int) int {
		if n == 2 {
			return 401
		}
		return 0
	})
	c := runCaller("r-1")
	f.mustDiscover(c, "shop", fetchSvc)
	var ue *ops.UnavailableError
	if err := f.discover(c, "shop", fetchSvc); !errors.As(err, &ue) {
		t.Fatalf("second request: %v, want *ops.UnavailableError", err)
	}
	f.mustDiscover(c, "shop", fetchSvc)
	if n := f.minted(); n != 2 {
		t.Errorf("%d tokens minted, want a new one after the 401", n)
	}
	toks := f.tokensSeen()
	if len(toks) != 2 || !f.gh.TokenRevoked(toks[0]) || f.gh.TokenRevoked(toks[1]) {
		t.Errorf("tokens seen %d; the refused one must be revoked and the new one live", len(toks))
	}
	// A 403 is not about the token (permissions, rate limit): it is kept.
	g := newRetryRig(t, func(n int) int {
		if n == 2 {
			return 403
		}
		return 0
	})
	g.mustDiscover(c, "shop", fetchSvc)
	_ = g.discover(c, "shop", fetchSvc)
	g.mustDiscover(c, "shop", fetchSvc)
	if n := g.minted(); n != 1 {
		t.Errorf("%d tokens minted around a 403, want 1", n)
	}
}

func TestCloseRevokesEveryToken(t *testing.T) {
	f := okRig(t)
	f.mustDiscover(runCaller("r-1"), "shop", fetchSvc)
	f.mustDiscover(runCaller("r-1"), "shop", pushSvc)
	f.mustDiscover(runCaller("r-2"), "shop", fetchSvc)
	f.gh.Advance(56 * time.Minute)
	f.mustDiscover(runCaller("r-2"), "shop", fetchSvc) // replaces r-2's token; the old one is retired
	if n := f.gh.LiveTokens(); n != 4 {
		t.Fatalf("%d tokens live, want 4", n)
	}

	f.h.Close()
	if n := f.gh.LiveTokens(); n != 0 {
		t.Errorf("%d tokens live after Close, want 0", n)
	}
	minted := f.minted()
	var ue *ops.UnavailableError
	if err := f.discover(runCaller("r-3"), "shop", fetchSvc); !errors.As(err, &ue) {
		t.Errorf("after Close: %v, want *ops.UnavailableError", err)
	}
	if f.minted() != minted {
		t.Error("a token was minted after Close")
	}
	f.h.Close() // twice is harmless
}

// Without a run there is nothing to end a token with, so it serves one request.
func TestCallerWithoutARunGetsASingleUseToken(t *testing.T) {
	f := okRig(t)
	for range 2 {
		if err := f.discover(&ops.Caller{}, "shop", fetchSvc); err != nil {
			t.Fatal(err)
		}
		if n := f.gh.LiveTokens(); n != 0 {
			t.Fatalf("%d tokens live after the request, want 0", n)
		}
	}
	if n := f.minted(); n != 2 {
		t.Errorf("%d tokens minted for two requests, want 2", n)
	}
}

// stuckRevoker is GitHub unreachable: a revoke does not answer until release
// is closed (or its context ends, which is revokeTimeout, 15 s).
type stuckRevoker struct {
	inner   gitproxy.Revoker
	entered chan struct{}
	release chan struct{}
}

func (s *stuckRevoker) RevokeToken(ctx context.Context, tok *gh.Token) error {
	s.entered <- struct{}{}
	select {
	case <-s.release:
		return s.inner.RevokeToken(ctx, tok)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stuckRig has two tokens of r-1 minted and every later revoke stuck.
func stuckRig(t *testing.T) (*retryRig, *stuckRevoker, []string) {
	t.Helper()
	f := okRig(t)
	f.mustDiscover(runCaller("r-1"), "shop", fetchSvc)
	f.mustDiscover(runCaller("r-1"), "shop", pushSvc)
	toks := f.tokensSeen()
	if len(toks) != 2 {
		t.Fatalf("%d distinct tokens, want 2", len(toks))
	}
	s := &stuckRevoker{inner: f.h.Revoker, entered: make(chan struct{}, 8), release: make(chan struct{})}
	f.h.Revoker = s
	return f, s, toks
}

// EndRun does not wait for GitHub (chaperone #61): the run's tokens are dead for
// chapd the moment it returns, and the revoke goes on in the background.
func TestEndRunReturnsWhileGitHubIsStuck(t *testing.T) {
	f, s, toks := stuckRig(t)
	returned := make(chan struct{})
	go func() { f.h.EndRun("r-1"); close(returned) }()
	select {
	case <-returned:
	case <-time.After(5 * time.Second): // far below the 15 s of a revoke that never answers
		t.Fatal("EndRun waited for the revoke of a token while GitHub does not answer")
	}

	// Dead before the revoke call returned: GitHub still counts the tokens
	// live (their revoke is stuck), but a request of the run is refused and
	// neither mints nor reaches GitHub.
	for range toks {
		select {
		case <-s.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("a revoke was never started")
		}
	}
	if n := f.gh.LiveTokens(); n != 2 {
		t.Fatalf("%d tokens live while the revokes are stuck, want 2: the test does not show the order", n)
	}
	minted, sent := f.minted(), len(f.reqs)
	for _, svc := range []string{fetchSvc, pushSvc} {
		var ve *ops.VerifyError
		if err := f.discover(runCaller("r-1"), "shop", svc); !errors.As(err, &ve) || ve.Code != ops.CodeTokenRevoked {
			t.Errorf("%s while the revoke is stuck: %v, want TOKEN_REVOKED", svc, err)
		}
	}
	if f.minted() != minted || len(f.reqs) != sent {
		t.Errorf("a request of the ended run minted %d and sent %d", f.minted()-minted, len(f.reqs)-sent)
	}

	// GitHub answers at last: the tokens are revoked there too.
	close(s.release)
	f.h.WaitRevokes()
	if n := f.gh.LiveTokens(); n != 0 {
		t.Errorf("%d tokens live after the revokes finished, want 0", n)
	}
}

// chapd's shutdown still waits for the revokes EndRun left running, so they are
// not lost when the process exits.
func TestCloseWaitsForRevokesEndRunStarted(t *testing.T) {
	f, s, toks := stuckRig(t)
	f.h.EndRun("r-1")
	for range toks {
		<-s.entered
	}
	closed := make(chan struct{})
	go func() { f.h.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while a revoke was still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(s.release)
	<-closed
	if n := f.gh.LiveTokens(); n != 0 {
		t.Errorf("%d tokens live after Close, want 0", n)
	}
}
