package console

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/spec"
)

func mergeCard(ar *apprRig, n string) *approvals.Approval {
	return ar.request(func(r *spec.Request) {
		r.Op = "pr.merge"
		r.Target = spec.Target{Adapter: "github", Ref: "acme/shop#" + n}
		r.Params = map[string]any{"base": "main", "head_sha": strings.Repeat(n, 40), "method": "squash"}
	})
}

// Review item 1: a waiting merge card that would be refused now is flagged before the operator spends a Hello on it.
// The flag is page chrome outside the card text; it never blocks Approve.
func TestStaleMergeCardIsFlaggedOutsideTheSignedText(t *testing.T) {
	sr := newScrRig(t)
	b, auth := sr.signedIn()
	stale, fresh := mergeCard(sr.apprRig, "1"), mergeCard(sr.apprRig, "2")
	var calls atomic.Int32
	sr.con.apprOpts.Recheck = func(_ context.Context, requestID string) (StaleCheck, error) {
		calls.Add(1)
		if requestID == stale.RequestID {
			return StaleCheck{Stale: true, Why: "its branch is behind the base (head is 1 commit(s) behind main)."}, nil
		}
		return StaleCheck{}, nil
	}

	page := get(t, b, "/approvals")
	if n := strings.Count(page, "may be stale"); n != 1 {
		t.Fatalf("the page flags %d cards, want 1:\n%s", n, page)
	}
	if !strings.Contains(page, "May be stale:") || !strings.Contains(page, "1 commit(s) behind main") {
		t.Fatal("the warning with the reason is missing")
	}
	// Outside the signed text: every card's .approval-text is still exactly the signed card text.
	for _, a := range []*approvals.Approval{stale, fresh} {
		m := cardPre.FindStringSubmatch(page[strings.Index(page, `id="card-`+a.ID+`"`)-len(`<div class="approval-text" `):])
		if m == nil || cardTextOf(m[3]) != a.CardText {
			t.Fatalf("the card text of %s on the page is not the signed text", a.ID)
		}
		if strings.Contains(cardTextOf(m[3]), "stale") {
			t.Fatal("the warning leaked into the signed text")
		}
	}
	// Home shows it too.
	if home := get(t, b, "/"); strings.Count(home, "may be stale") != 1 {
		t.Fatalf("home flags %d cards, want 1", strings.Count(home, "may be stale"))
	}
	// It does not block Approve: the operator may still decide a flagged card.
	bg := sr.begin(b, stale.ID)
	if rec := sr.finish(b, stale.ID, bg, auth.get(bg.options, pcOrigin.URL, opts{signCount: &zero})); rec.Code != 200 {
		t.Fatalf("a flagged card could not be approved: %d %s", rec.Code, rec.Body)
	}
}

func TestStaleLooksAreCachedAndOnlyForMerges(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	mergeCard(sr.apprRig, "1")
	sr.request(nil) // a deploy card: never looked at
	var calls atomic.Int32
	sr.con.apprOpts.Recheck = func(context.Context, string) (StaleCheck, error) {
		calls.Add(1)
		return StaleCheck{Stale: true, Why: "x."}, nil
	}

	get(t, b, "/approvals")
	get(t, b, "/approvals")
	get(t, b, "/")
	if calls.Load() != 1 {
		t.Fatalf("%d looks for one merge card in a few page loads, want 1 (cached)", calls.Load())
	}
	sr.advance(staleTTL + time.Second)
	get(t, b, "/approvals")
	if calls.Load() != 2 {
		t.Fatalf("%d looks after the cache expired, want 2", calls.Load())
	}
}

// A look that fails is not a flag and not silence: the card says it could not be checked, and the failure is
// remembered as long as a good look, so a reload does not ask GitHub again.
func TestStaleLookThatFailsShowsNotCheckedAndIsCached(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	mergeCard(sr.apprRig, "1")
	var calls atomic.Int32
	sr.con.apprOpts.Recheck = func(context.Context, string) (StaleCheck, error) {
		calls.Add(1)
		return StaleCheck{}, errors.New("github unreachable")
	}
	page := get(t, b, "/approvals")
	if strings.Contains(page, "may be stale") || strings.Contains(page, "May be stale") {
		t.Fatal("a look that could not be made must not flag the card")
	}
	if !strings.Contains(page, "Could not check:") || !strings.Contains(page, "not checked") || !strings.Contains(page, "("+unknownFailed+")") {
		t.Fatal("the card does not say it could not be checked")
	}
	get(t, b, "/approvals")
	get(t, b, "/")
	if calls.Load() != 1 {
		t.Fatalf("%d looks after a failure in a few page loads, want 1 (a failure is cached)", calls.Load())
	}
	sr.advance(staleTTL + time.Second)
	get(t, b, "/approvals")
	if calls.Load() != 2 {
		t.Fatalf("%d looks after the cache expired, want 2", calls.Load())
	}
	// and with no Recheck at all (chapd built without it) nothing changes
	sr.con.apprOpts.Recheck = nil
	if rec := b.do("GET", "/approvals", nil, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "stale") || strings.Contains(rec.Body.String(), "Could not check") {
		t.Fatalf("no Recheck: %d", rec.Code)
	}
}

// waitStaleIdle waits until no look is running, so a test ends with no goroutine still filling the cache.
func waitStaleIdle(t *testing.T, c *Console) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		c.stale.mu.Lock()
		n := len(c.stale.flying)
		c.stale.mu.Unlock()
		if n == 0 {
			return
		}
	}
	t.Fatal("a look is still running")
}

func waitCalls(t *testing.T, calls *atomic.Int32, want int32) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if calls.Load() >= want {
			return
		}
	}
	t.Fatalf("%d looks started, want %d", calls.Load(), want)
}

// A look that never answers (GitHub stuck, a token revoke that outlives its context) must not hold the page: the page
// stops waiting at the deadline, says it could not check, and does not wait again on the next load. The look that is
// still running only fills the cache when it ends.
func TestStaleLookThatHangsDoesNotHoldThePage(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	mergeCard(sr.apprRig, "1")
	release := make(chan struct{})
	var calls atomic.Int32
	sr.con.stale.timeout = 100 * time.Millisecond
	sr.con.apprOpts.Recheck = func(context.Context, string) (StaleCheck, error) { // ignores its context, as a stuck revoke does
		calls.Add(1)
		<-release
		return StaleCheck{Stale: true, Why: "its branch is behind the base (late)."}, nil
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		waitStaleIdle(t, sr.con)
	})

	start := time.Now()
	page := get(t, b, "/approvals")
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the page waited %v on a look that never answered", d)
	}
	if !strings.Contains(page, "Could not check:") || !strings.Contains(page, "("+unknownSlow+")") || strings.Contains(page, "May be stale") {
		t.Fatal("a look that did not answer in time must show 'could not check'")
	}
	start = time.Now()
	home := get(t, b, "/")
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the next load waited %v again", d)
	}
	if strings.Contains(home, "may be stale") {
		t.Fatal("home flagged a card whose look has not answered")
	}
	if calls.Load() != 1 {
		t.Fatalf("%d looks, want 1: a failure is cached and a running look is shared", calls.Load())
	}

	// The late look fills the cache; the next load uses it with no new call.
	close(release)
	waitStaleIdle(t, sr.con)
	if page := get(t, b, "/approvals"); !strings.Contains(page, "May be stale:") || !strings.Contains(page, "(late)") {
		t.Fatal("the late look did not reach the cache")
	}
	if calls.Load() != 1 {
		t.Fatalf("%d looks, want 1", calls.Load())
	}
}

// Page loads that arrive while a look runs share it: one call to GitHub, however many readers.
func TestStaleConcurrentLoadsShareOneLook(t *testing.T) {
	sr := newScrRig(t)
	card := mergeCard(sr.apprRig, "1")
	release := make(chan struct{})
	var calls atomic.Int32
	sr.con.apprOpts.Recheck = func(context.Context, string) (StaleCheck, error) {
		calls.Add(1)
		<-release
		return StaleCheck{Stale: true, Why: "x."}, nil
	}
	const readers = 6
	got := make(chan map[string]staleNote, readers)
	for range readers {
		go func() { got <- sr.con.staleFlags(context.Background(), []*approvals.Approval{card}) }()
	}
	waitCalls(t, &calls, 1)
	close(release)
	for i := range readers {
		if n := (<-got)[card.ID]; n.Why != "x." || n.Unknown != "" {
			t.Fatalf("reader %d: %+v", i, n)
		}
	}
	waitStaleIdle(t, sr.con)
	if calls.Load() != 1 {
		t.Fatalf("%d looks for %d concurrent loads, want 1", calls.Load(), readers)
	}
}

// Only staleMaxFlight looks run at once; a card beyond the cap is shown as not checked and gets its look on a later load.
func TestStaleLooksAreCappedInFlight(t *testing.T) {
	sr := newScrRig(t)
	cards := []*approvals.Approval{mergeCard(sr.apprRig, "1"), mergeCard(sr.apprRig, "2")} // a run may have 2 cards waiting
	release := make(chan struct{})
	var calls atomic.Int32
	sr.con.stale.timeout = 100 * time.Millisecond
	sr.con.stale.maxFlight = 1
	sr.con.apprOpts.Recheck = func(context.Context, string) (StaleCheck, error) {
		calls.Add(1)
		<-release
		return StaleCheck{}, nil
	}
	t.Cleanup(func() { close(release); waitStaleIdle(t, sr.con) })

	out := sr.con.staleFlags(context.Background(), cards)
	waitCalls(t, &calls, 1)
	if got := out[cards[0].ID].Unknown; got != unknownSlow {
		t.Fatalf("the card that was looked at: %q, want %q", got, unknownSlow)
	}
	if got := out[cards[1].ID].Unknown; got != unknownBusy {
		t.Fatalf("the card over the cap: %q, want %q", got, unknownBusy)
	}
	if calls.Load() != 1 {
		t.Fatalf("%d looks started with a cap of 1", calls.Load())
	}
}

// The flag is text, not a control: on a restricted page it still shows, Approve and Deny stay off, and the note does
// not say the operator can decide there. The ordinary page keeps it live.
func TestStaleFlagOnARestrictedPageAddsNoLiveControl(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	stale := mergeCard(sr.apprRig, "1")
	sr.con.apprOpts.Recheck = func(_ context.Context, requestID string) (StaleCheck, error) {
		return StaleCheck{Stale: requestID == stale.RequestID, Why: "its branch is behind the base."}, nil
	}

	rec := b.do("GET", "/approvals?from=frame", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "May be stale:") || !strings.Contains(body, "data-restricted") {
		t.Fatalf("restricted page: %d, want the flag and the restricted note", rec.Code)
	}
	if !strings.Contains(body, `data-action="approve" disabled`) || !strings.Contains(body, `data-action="deny" disabled`) {
		t.Error("a stale flag on a restricted page left Approve or Deny live")
	}
	if strings.Contains(body, "You can still decide") || !strings.Contains(body, "Re-open the page to decide.") {
		t.Error("the stale note on a restricted page must send the operator to Re-open, not say he can decide here")
	}

	ord := b.do("GET", "/approvals", nil, nil).Body.String()
	if !strings.Contains(ord, "You can still decide") || strings.Contains(ord, `data-action="approve" disabled`) {
		t.Error("the ordinary page lost the live Approve or the 'still decide' note")
	}
}

// On a restricted page a card whose look could not be made says so in text only, and Approve and Deny stay off. On the
// legacy restricted page (the browser sent no Sec-Fetch-Site) there is no Re-open link, so no note may send the operator
// to one.
func TestStaleNotesOnRestrictedPagesStayTextAndNameNoWayOutThatIsNotThere(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	stale, down := mergeCard(sr.apprRig, "1"), mergeCard(sr.apprRig, "2")
	sr.con.apprOpts.Recheck = func(_ context.Context, requestID string) (StaleCheck, error) {
		if requestID == down.RequestID {
			return StaleCheck{}, errors.New("github unreachable")
		}
		return StaleCheck{Stale: requestID == stale.RequestID, Why: "its branch is behind the base."}, nil
	}

	body := b.do("GET", "/approvals?from=frame", nil, map[string]string{"Sec-Fetch-Site": "same-origin"}).Body.String()
	if !strings.Contains(body, "May be stale:") || !strings.Contains(body, "Could not check:") {
		t.Fatal("the restricted page lost a note")
	}
	if n := strings.Count(body, "Re-open the page to decide."); n != 2 {
		t.Errorf("%d Re-open hints on the restricted page, want 2 (one per note)", n)
	}
	if strings.Contains(body, "You can still decide") || strings.Count(body, `data-action="approve" disabled`) != 2 || strings.Count(body, `data-action="deny" disabled`) != 2 {
		t.Error("a note on a restricted page left Approve or Deny live or said the operator can decide")
	}

	legacy := b.do("GET", "/approvals?from=frame", nil, map[string]string{"Sec-Fetch-Site": ""}).Body.String()
	if !strings.Contains(legacy, "May be stale:") || !strings.Contains(legacy, "Could not check:") || !strings.Contains(legacy, "data-restricted") {
		t.Fatal("the legacy restricted page lost a note")
	}
	if strings.Contains(legacy, "Re-open the page to decide.") || strings.Contains(legacy, "data-reopen") || strings.Contains(legacy, "You can still decide") {
		t.Error("the legacy restricted page sends the operator to a Re-open link it does not have, or says he can decide")
	}
	if n := strings.Count(legacy, "Approve and Deny are off on this page."); n != 2 {
		t.Errorf("%d neutral hints on the legacy page, want 2", n)
	}
}

// A card that only a new card can help (a retitled PR) does not say "you can still decide": release will refuse it.
func TestStaleNewCardNoteDoesNotSayYouCanStillDecide(t *testing.T) {
	sr := newScrRigCfg(t, withGlass)
	b, _ := sr.signedIn()
	mergeCard(sr.apprRig, "1")
	sr.con.apprOpts.Recheck = func(context.Context, string) (StaleCheck, error) {
		return StaleCheck{Stale: true, Why: "the pull request was retitled after this card was made, so release will refuse it; ask again for a new card.", NewCard: true}, nil
	}

	ord := b.do("GET", "/approvals", nil, nil).Body.String()
	if !strings.Contains(ord, "retitled") || !strings.Contains(ord, "Approving it would not help") || strings.Contains(ord, "You can still decide") {
		t.Error("a retitled card must say approving would not help, not that the operator can still decide")
	}
	if strings.Contains(ord, `data-action="approve" disabled`) {
		t.Error("the note must stay text: Approve is not turned off")
	}
	// on a restricted page the restricted wording wins: nothing there can be decided
	rest := b.do("GET", "/approvals?from=frame", nil, map[string]string{"Sec-Fetch-Site": "same-origin"}).Body.String()
	if !strings.Contains(rest, "Re-open the page to decide.") || strings.Contains(rest, "Approving it would not help") {
		t.Error("the restricted page must keep its own hint")
	}
}
