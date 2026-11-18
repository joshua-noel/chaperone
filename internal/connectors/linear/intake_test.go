package linear

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/linear/lineartest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// ---- who and what ------------------------------------------------------------

func TestOnlyTheOrchestratorMayAskAndOnlyForTheProjectsTeam(t *testing.T) {
	r := newRig(t)
	r.seed()
	ctx := context.Background()
	for _, op := range Ops {
		ref := "board"
		if op == OpComment || op == OpMove {
			ref = "SHOP-1"
		}
		q := req(op, ref, map[string]any{"body": "x", "state": "Blocked"})
		if op == OpList || op == OpStates {
			q.Params = map[string]any{}
		}
		q.Caller = &ops.Caller{Kind: ops.KindRun, RunID: "r-7f3a", Project: testProject}
		_, err := r.ad(op).Check(ctx, q)
		wantRefusal(t, err, ops.CodePolicyRefused)

		q = req(op, ref, q.Params)
		q.Target.Adapter = "github"
		_, err = r.ad(op).Check(ctx, q)
		wantRefusal(t, err, ops.CodeParamsInvalid)

		q = req(op, ref, q.Params)
		q.Project = "other-project" // no linear: block
		_, err = r.ad(op).Check(ctx, q)
		if ref := wantRefusal(t, err, ops.CodePolicyRefused); !strings.Contains(ref.Why, "linear:") {
			t.Errorf("%s: %s", op, ref.Why)
		}
	}
	if n := len(r.fake.Requests()); n != 0 {
		t.Errorf("a refused request reached Linear (%d calls)", n)
	}
}

func TestAnotherTeamIsRefusedBeforeLinearIsAsked(t *testing.T) {
	r := newRig(t)
	r.seed()
	ctx := context.Background()
	for _, q := range []*ops.Request{
		req(OpList, "ENG", nil),
		req(OpStates, "ENG", nil),
		req(OpComment, "ENG-1", map[string]any{"body": "hello"}),
		req(OpMove, "ENG-1", map[string]any{"state": "Blocked"}),
	} {
		_, err := r.ad(q.Op).Check(ctx, q)
		wantRefusal(t, err, ops.CodeScopePath)
	}
	for _, bad := range []string{"shop-1", "SHOP-0", "SHOP-", "SHOP-1a", "SHOP-1 ", "-1", "SHOP-1\n", "board"} {
		_, err := r.ad(OpComment).Check(ctx, req(OpComment, bad, map[string]any{"body": "x"}))
		wantRefusal(t, err, ops.CodeParamsInvalid)
	}
	if n := len(r.fake.Requests()); n != 0 {
		t.Errorf("a refused request reached Linear (%d calls)", n)
	}
}

// An issue that moved to another team keeps its old identifier as an alias
// that Linear still resolves. The write goes by what Linear says the issue is.
func TestAnIssueThatMovedToAnotherTeamIsRefused(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.fake.MoveToTeam("SHOP-1", "ENG", "ENG-7")
	_, err, _, _ := r.run(req(OpComment, "SHOP-1", map[string]any{"body": "hello"}))
	ref := wantRefusal(t, err, ops.CodeScopePath)
	if !strings.Contains(ref.Why, "ENG") {
		t.Errorf("why: %s", ref.Why)
	}
	if r.fake.Count("IntakeComment") != 0 {
		t.Error("a comment was posted")
	}
}

func TestATeamCalledEngineeringIsNeverWrittenTo(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.fake.RenameTeam("SHOP", "Engineering") // the policy's key now names the mirror
	_, err, _, _ := r.run(req(OpComment, "SHOP-1", map[string]any{"body": "hello"}))
	wantRefusal(t, err, ops.CodeScopePath)
	_, err, _, _ = r.run(req(OpMove, "SHOP-1", map[string]any{"state": "Blocked"}))
	wantRefusal(t, err, ops.CodeScopePath)
	_, _, out, err2 := r.run(req(OpStates, "board", nil))
	mustFail(t, out, err2, "Engineering")
	if r.fake.Count("IntakeComment")+r.fake.Count("IntakeSetState") != 0 {
		t.Error("a write was sent")
	}
}

func TestOnlyItemsWithTheLabelAreWrittenTo(t *testing.T) {
	r := newRig(t)
	r.seed()
	for _, q := range []*ops.Request{
		req(OpComment, "SHOP-3", map[string]any{"body": "hello"}),
		req(OpMove, "SHOP-3", map[string]any{"state": "Blocked"}),
	} {
		_, err, _, _ := r.run(q)
		ref := wantRefusal(t, err, ops.CodePolicyRefused)
		if !strings.Contains(ref.Why, `"claude"`) {
			t.Errorf("why: %s", ref.Why)
		}
	}
	_, err, _, _ := r.run(req(OpComment, "SHOP-99", map[string]any{"body": "hello"}))
	wantRefusal(t, err, ops.CodeParamsInvalid)
	if r.fake.Count("IntakeComment")+r.fake.Count("IntakeSetState") != 0 {
		t.Error("a write was sent")
	}
}

// ---- intake.list --------------------------------------------------------------

func TestListReturnsOpenItemsOfTheTeamWithTheLabel(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.fake.AddIssue(lineartest.Issue{Identifier: "SHOP-4", Title: "Talk to the baker", Description: "Line one\nLine two\x07", Labels: []string{"claude"}, State: "Blocked",
		Comments: []lineartest.Comment{{ID: "c1", Body: "Picked up by the orchestrator", Author: "Board Intake", CreatedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}}})
	cr, err, out, err2 := r.run(req(OpList, "board", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cr.Checks) == 0 {
		t.Error("no checks")
	}
	out = mustSucceed(t, out, err2)
	items := resultItems(t, out)
	// Newest change first; the completed item, the unlabelled one and the
	// Engineering one are not there.
	if got := identifiers(items); !slices.Equal(got, []string{"SHOP-4", "SHOP-1"}) {
		t.Fatalf("items %v", got)
	}
	if out.Result["untrusted_text"] != true || out.Result["team"] != "SHOP" || out.Result["label"] != "claude" || out.Result["source"] != SourceLive {
		t.Errorf("result head: %v", out.Result)
	}
	baker := items[0]
	if baker["description"] != "Line one\nLine two " { // control character replaced
		t.Errorf("description %q", baker["description"])
	}
	if st := baker["state"].(map[string]any); st["name"] != "Blocked" || st["type"] != "started" {
		t.Errorf("state %v", st)
	}
	if cm := baker["comments"].([]any); len(cm) != 1 || cm[0].(map[string]any)["body"] != "Picked up by the orchestrator" {
		t.Errorf("comments %v", baker["comments"])
	}
	signs := items[1]
	if l := signs["links"].([]any); len(l) != 1 || l[0].(map[string]any)["url"] != "https://github.com/example-org/storefront/issues/401" {
		t.Errorf("links %v", signs["links"])
	}
	if signs["assignee"] != "Gilliano" || signs["updated_at"] == "" || signs["url"] == "" {
		t.Errorf("fields %v", signs)
	}
	// The filter Linear got is the policy's, not the caller's.
	for _, rq := range r.fake.Requests() {
		if rq.Name != opList {
			continue
		}
		f := rq.Vars["filter"].(map[string]any)
		if f["team"].(map[string]any)["key"].(map[string]any)["eq"] != "SHOP" {
			t.Errorf("filter %v", f)
		}
	}
}

func TestListClosedToo(t *testing.T) {
	r := newRig(t)
	r.seed()
	_, _, out, err := r.run(req(OpList, "SHOP", map[string]any{"closed": true}))
	out = mustSucceed(t, out, err)
	if got := identifiers(resultItems(t, out)); !slices.Equal(got, []string{"SHOP-2", "SHOP-1"}) && !slices.Equal(got, []string{"SHOP-1", "SHOP-2"}) {
		t.Fatalf("items %v", got)
	}
	if out.Result["closed_too"] != true {
		t.Error("closed_too not set")
	}
}

func TestListParamsAreChecked(t *testing.T) {
	r := newRig(t)
	for _, p := range []map[string]any{{"refresh": "yes"}, {"closed": 1}, {"team": "ENG"}, {"first": 5}} {
		_, err := r.ad(OpList).Check(context.Background(), req(OpList, "board", p))
		wantRefusal(t, err, ops.CodeParamsInvalid)
	}
}

func TestListTextIsCappedAndASecretIsWithheld(t *testing.T) {
	r := newRig(t)
	canary := "canary-secret-value-0123456789abcdef"
	if err := r.reg.Set("some-vault-secret", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	r.fake.AddIssue(lineartest.Issue{Identifier: "SHOP-5", Title: "Long one", Description: strings.Repeat("word ", 1000), Labels: []string{"claude"}})
	r.fake.AddIssue(lineartest.Issue{Identifier: "SHOP-6", Title: "Has a secret", Description: "the key is " + canary, Labels: []string{"claude"},
		Comments: []lineartest.Comment{{ID: "c9", Body: "fine", Author: "x", CreatedAt: time.Now()}}})
	_, _, out, err := r.run(req(OpList, "board", nil))
	out = mustSucceed(t, out, err)
	byID := map[string]map[string]any{}
	for _, it := range resultItems(t, out) {
		byID[it["identifier"].(string)] = it
	}
	if d := byID["SHOP-5"]["description"].(string); len(d) > maxDescription || !strings.HasSuffix(d, "...") {
		t.Errorf("description of %d bytes", len(d))
	}
	sec := byID["SHOP-6"]
	if sec["withheld"] != true || sec["title"] != withheld || sec["description"] != "" || len(sec["comments"].([]any)) != 0 {
		t.Errorf("item with a secret: %v", sec)
	}
	for _, it := range resultItems(t, out) {
		if strings.Contains(strings.Join([]string{it["title"].(string), it["description"].(string)}, " "), canary) {
			t.Error("the canary is in the result")
		}
	}
}

func TestListIsServedFromTheCacheAndRefreshedOnDemand(t *testing.T) {
	r := newRig(t, rigOpts{interval: 15 * time.Minute})
	r.seed()
	list := func(params map[string]any) ops.Outcome {
		_, _, out, err := r.run(req(OpList, "board", params))
		return mustSucceed(t, out, err)
	}
	first := list(nil)
	if first.Result["source"] != SourceLive || r.fake.Count(opList) != 1 {
		t.Fatalf("first read: %v / %d", first.Result["source"], r.fake.Count(opList))
	}
	r.clock.Advance(10 * time.Minute)
	if out := list(nil); out.Result["source"] != SourceCache || r.fake.Count(opList) != 1 || out.Result["age_seconds"] != 600 {
		t.Fatalf("plain list: %v age %v calls %d", out.Result["source"], out.Result["age_seconds"], r.fake.Count(opList))
	}
	// A refresh inside the minimum gap is answered from the cache; after it, live.
	r.clock.Advance(-9*time.Minute - 40*time.Second) // 20 s after the first read
	if out := list(map[string]any{"refresh": true}); out.Result["source"] != SourceCache || r.fake.Count(opList) != 1 {
		t.Fatalf("early refresh: %v calls %d", out.Result["source"], r.fake.Count(opList))
	}
	r.clock.Advance(15 * time.Second)
	if out := list(map[string]any{"refresh": true}); out.Result["source"] != SourceLive || r.fake.Count(opList) != 2 {
		t.Fatalf("refresh after the gap: %v calls %d", out.Result["source"], r.fake.Count(opList))
	}
	// A cache older than two poll intervals is not trusted (the poller may be down).
	r.clock.Advance(31 * time.Minute)
	if out := list(nil); out.Result["source"] != SourceLive || r.fake.Count(opList) != 3 {
		t.Fatalf("stale list: %v calls %d", out.Result["source"], r.fake.Count(opList))
	}
}

func TestListWithNoPollerReadsOnDemand(t *testing.T) {
	r := newRig(t) // interval 0: no poller
	r.seed()
	list := func() ops.Outcome {
		_, _, out, err := r.run(req(OpList, "board", nil))
		return mustSucceed(t, out, err)
	}
	list()
	list() // inside the minimum gap
	if r.fake.Count(opList) != 1 {
		t.Errorf("reads: %d", r.fake.Count(opList))
	}
	r.clock.Advance(time.Minute)
	if out := list(); out.Result["source"] != SourceLive || r.fake.Count(opList) != 2 {
		t.Errorf("after the gap: %v %d", out.Result["source"], r.fake.Count(opList))
	}
}

func TestThePollerRefreshesTheBoardsThatWereAskedFor(t *testing.T) {
	r := newRig(t, rigOpts{interval: 15 * time.Minute})
	r.seed()
	ctx := context.Background()
	r.board.Poll(ctx) // nothing was asked for yet
	if r.fake.Count(opList) != 0 {
		t.Fatal("polled a board nobody asked for")
	}
	if _, _, out, err := r.run(req(OpList, "board", nil)); err != nil {
		t.Fatal(err)
	} else {
		mustSucceed(t, out, nil)
	}
	r.fake.AddIssue(lineartest.Issue{Identifier: "SHOP-8", Title: "New today", Labels: []string{"claude"}})
	r.clock.Advance(15 * time.Minute)
	r.board.Poll(ctx)
	if r.fake.Count(opList) != 2 {
		t.Fatalf("reads after a poll: %d", r.fake.Count(opList))
	}
	// The next list comes from the poll's cache and shows the new item.
	_, _, out, err := r.run(req(OpList, "board", nil))
	out = mustSucceed(t, out, err)
	if out.Result["source"] != SourceCache || !slices.Contains(identifiers(resultItems(t, out)), "SHOP-8") || r.fake.Count(opList) != 2 {
		t.Fatalf("list after the poll: %v %v", out.Result["source"], identifiers(resultItems(t, out)))
	}
	// A board nobody has asked for in a day is dropped from the poll.
	r.clock.Advance(25 * time.Hour)
	r.board.Poll(ctx)
	if r.fake.Count(opList) != 2 {
		t.Errorf("an idle board was polled: %d", r.fake.Count(opList))
	}
}

func TestAFailingPollIsLoggedOnceAndTheNextListReportsIt(t *testing.T) {
	r := newRig(t, rigOpts{interval: 15 * time.Minute})
	r.seed()
	ctx := context.Background()
	if _, _, out, err := r.run(req(OpList, "board", nil)); err != nil {
		t.Fatal(err)
	} else {
		mustSucceed(t, out, nil)
	}
	r.secrets.set(SecretClientSecret, "lin-client-secret-ROTATED-0123456789abcdef0123456789")
	r.toks.Invalidate()
	for range 3 {
		r.clock.Advance(15 * time.Minute)
		r.board.Poll(ctx)
	}
	if n := strings.Count(r.log.String(), "poll failed"); n != 1 {
		t.Errorf("failure logged %d times:\n%s", n, r.log.String())
	}
	if strings.Contains(r.log.String(), "ROTATED") || strings.Contains(r.log.String(), lineartest.ClientSecret) {
		t.Errorf("the log has a secret:\n%s", r.log.String())
	}
	// The cache is more than two intervals old: the list reads Linear and says what is wrong.
	r.clock.Advance(15 * time.Minute)
	_, _, out, err := r.run(req(OpList, "board", nil))
	mustFail(t, out, err, "invalid_client")
	// The secret is fixed: the poll recovers and says so.
	r.secrets.set(SecretClientSecret, lineartest.ClientSecret)
	r.board.Poll(ctx)
	if !strings.Contains(r.log.String(), "works again") {
		t.Errorf("no recovery line:\n%s", r.log.String())
	}
}

// ---- intake.comment ------------------------------------------------------------

func TestCommentIsPostedOnceOnALabelledItem(t *testing.T) {
	r := newRig(t)
	r.seed()
	body := "Picked up by the orchestrator\nhttps://github.com/example-org/storefront/issues/401"
	cr, err, out, err2 := r.run(req(OpComment, "SHOP-1", map[string]any{"body": body}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cr.Checks) != 3 {
		t.Errorf("checks %v", cr.Checks)
	}
	out = mustSucceed(t, out, err2)
	got := r.fake.Issue("SHOP-1")
	if len(got.Comments) != 1 || got.Comments[0].Body != body {
		t.Fatalf("comments on the issue: %+v", got.Comments)
	}
	if id := got.Comments[0].ID; id != CommentID("x-1") || out.Result["comment_id"] != id {
		t.Errorf("comment id %s / %v", id, out.Result["comment_id"])
	}
	if out.ExternalRef == "" || !strings.HasPrefix(out.ExternalRef, "https://linear.app/") || len(out.ExternalRef) > 300 {
		t.Errorf("external ref %q", out.ExternalRef)
	}
	// Nothing else about the issue changed.
	if got.Title != "Order market signs" || got.State != "Todo" || !slices.Equal(got.Labels, []string{"claude", "signs"}) {
		t.Errorf("the issue changed: %+v", got)
	}
}

func TestCommentBodyIsChecked(t *testing.T) {
	r := newRig(t)
	r.seed()
	ctx := context.Background()
	if err := r.reg.Set("canary", []byte("canary-secret-value-0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		params map[string]any
		code   string
	}{
		"missing":     {map[string]any{}, ops.CodeParamsInvalid},
		"blank":       {map[string]any{"body": " \n "}, ops.CodeParamsInvalid},
		"not text":    {map[string]any{"body": 12}, ops.CodeParamsInvalid},
		"too long":    {map[string]any{"body": strings.Repeat("a", MaxCommentBytes+1)}, ops.CodeParamsInvalid},
		"control":     {map[string]any{"body": "a\x1b[31mred"}, ops.CodeParamsInvalid},
		"bidi":        {map[string]any{"body": "safe \u202e evil"}, ops.CodeParamsInvalid},
		"extra param": {map[string]any{"body": "x", "label": "claude"}, ops.CodeParamsInvalid},
		"secret":      {map[string]any{"body": "the key is canary-secret-value-0123456789abcdef"}, ops.CodeRedactionBlocked},
	} {
		_, err := r.ad(OpComment).Check(ctx, req(OpComment, "SHOP-1", c.params))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if ref, ok := err.(*ops.Refusal); !ok || ref.Code != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r.fake.Count("IntakeComment") != 0 {
		t.Error("a comment was posted")
	}
}

// The label can be taken off between Check and the write: Execute reads the
// issue again, with the token that writes, and stops.
func TestLabelRemovedBetweenCheckAndWriteStopsTheComment(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.fake.OnGuard = func(s *lineartest.Server, n int) {
		if n == 2 { // the read in Execute; the first was Check's
			s.SetLabels("SHOP-1", "signs")
		}
	}
	q := req(OpComment, "SHOP-1", map[string]any{"body": "hello"})
	_, err, out, err2 := r.run(q)
	if err != nil {
		t.Fatalf("Check should have passed: %v", err)
	}
	mustFail(t, out, err2, `does not carry the label "claude"`)
	if r.fake.Count("IntakeComment") != 0 || len(r.fake.Issue("SHOP-1").Comments) != 0 {
		t.Error("a comment was posted after the label went")
	}
}

func TestLabelRemovedBetweenCheckAndWriteStopsTheMove(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.fake.OnGuard = func(s *lineartest.Server, n int) {
		if n == 2 {
			s.SetLabels("SHOP-1")
		}
	}
	_, err, out, err2 := r.run(req(OpMove, "SHOP-1", map[string]any{"state": "Blocked"}))
	if err != nil {
		t.Fatalf("Check should have passed: %v", err)
	}
	mustFail(t, out, err2, "label")
	if r.fake.Count("IntakeSetState") != 0 || r.fake.Issue("SHOP-1").State != "Todo" {
		t.Error("the item moved after the label went")
	}
}

func TestAnIssueThatMovesTeamBetweenCheckAndWriteIsNotWritten(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.fake.OnGuard = func(s *lineartest.Server, n int) {
		if n == 2 {
			s.MoveToTeam("SHOP-1", "ENG", "ENG-9")
		}
	}
	_, err, out, err2 := r.run(req(OpComment, "SHOP-1", map[string]any{"body": "hello"}))
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, out, err2, "ENG")
	if r.fake.Count("IntakeComment") != 0 {
		t.Error("a comment was posted")
	}
}

func TestACommentWhoseAnswerIsLostIsUnconfirmedAndNamesTheComment(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.fake.DropAnswer("IntakeComment")
	_, err, out, err2 := r.run(req(OpComment, "SHOP-1", map[string]any{"body": "hello"}))
	if err != nil {
		t.Fatal(err)
	}
	if err2 == nil || out.Failed {
		t.Fatalf("a lost answer must leave the op unconfirmed: %+v / %v", out, err2)
	}
	// The comment id is in the result so it can be looked up; the fake did post it.
	if out.Result["comment_id"] != CommentID("x-1") || len(r.fake.Issue("SHOP-1").Comments) != 1 {
		t.Errorf("result %v, comments %d", out.Result, len(r.fake.Issue("SHOP-1").Comments))
	}
	// Exactly one send: a lost answer is not retried.
	if r.fake.Count("IntakeComment") != 1 {
		t.Errorf("comment sent %d times", r.fake.Count("IntakeComment"))
	}
}

func TestARateLimitedWriteIsFailedAndNothingWasSent(t *testing.T) {
	r := newRig(t)
	r.seed()
	ctx := context.Background()
	q := req(OpComment, "SHOP-1", map[string]any{"body": "hello"})
	if _, err := r.ad(OpComment).Check(ctx, q); err != nil {
		t.Fatal(err)
	}
	r.fake.RateLimitNext(1)
	out, err := r.ad(OpComment).Execute(ctx, q)
	mustFail(t, out, err, "rate limit")
	if r.fake.Count("IntakeComment") != 0 {
		t.Error("a comment was sent")
	}
}

// ---- intake.move ----------------------------------------------------------------

func TestMoveToAStateTheTeamHasAndThePolicyLists(t *testing.T) {
	r := newRig(t)
	r.seed()
	cr, err, out, err2 := r.run(req(OpMove, "SHOP-1", map[string]any{"state": "Handed to engineering"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cr.Checks) != 3 {
		t.Errorf("checks %v", cr.Checks)
	}
	out = mustSucceed(t, out, err2)
	if got := r.fake.Issue("SHOP-1"); got.State != "Handed to engineering" || !slices.Equal(got.Labels, []string{"claude", "signs"}) || got.Title != "Order market signs" {
		t.Fatalf("issue after the move: %+v", got)
	}
	if out.Result["from"] != "Todo" || out.Result["to"] != "Handed to engineering" || out.Result["moved"] != true {
		t.Errorf("result %v", out.Result)
	}
	// Blocked and Completed, the states the operator named for the work's end.
	for _, st := range []string{"Blocked", "Completed"} {
		_, _, out, err := r.run(req(OpMove, "SHOP-1", map[string]any{"state": st}))
		mustSucceed(t, out, err)
		if got := r.fake.Issue("SHOP-1"); got.State != st || !slices.Contains(got.Labels, "claude") {
			t.Fatalf("after %s: %+v", st, got)
		}
	}
}

func TestMoveStateNamesMatchWithoutRegardToCase(t *testing.T) {
	r := newRig(t)
	r.seed()
	_, _, out, err := r.run(req(OpMove, "SHOP-1", map[string]any{"state": " blocked "}))
	out = mustSucceed(t, out, err)
	if out.Result["to"] != "Blocked" || r.fake.Issue("SHOP-1").State != "Blocked" {
		t.Errorf("result %v, state %s", out.Result, r.fake.Issue("SHOP-1").State)
	}
}

func TestMoveToAStateThePolicyDoesNotListIsRefused(t *testing.T) {
	r := newRig(t)
	r.seed()
	for _, st := range []string{"Backlog", "Todo", "Canceled", "Done", "Blocked; Completed", "Blocked,Completed"} {
		_, err, _, _ := r.run(req(OpMove, "SHOP-1", map[string]any{"state": st}))
		ref := wantRefusal(t, err, ops.CodePolicyRefused)
		if !strings.Contains(ref.Why, "allowed:") || !strings.Contains(ref.Why, "Blocked") {
			t.Errorf("%q: %s", st, ref.Why)
		}
	}
	if r.fake.Count("IntakeSetState") != 0 {
		t.Error("a move was sent")
	}
}

func TestMoveParamsAreChecked(t *testing.T) {
	r := newRig(t)
	r.seed()
	for _, p := range []map[string]any{{}, {"state": ""}, {"state": 5}, {"state": "Blocked", "labels": []any{}}, {"state": strings.Repeat("a", 81)}} {
		_, err := r.ad(OpMove).Check(context.Background(), req(OpMove, "SHOP-1", p))
		wantRefusal(t, err, ops.CodeParamsInvalid)
	}
}

func TestMoveIsRefusedWhileThePolicyListsNoStates(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.pol.States = nil // the shipped placeholder: the operator has not confirmed the names
	_, err, _, _ := r.run(req(OpMove, "SHOP-1", map[string]any{"state": "Blocked"}))
	ref := wantRefusal(t, err, ops.CodePolicyRefused)
	if !strings.Contains(ref.Why, "chap intake states") {
		t.Errorf("why: %s", ref.Why)
	}
}

func TestMoveToAPolicyStateTheTeamLacksIsRefused(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.pol.States = []string{"In review"} // not a state of SHOP
	_, err, _, _ := r.run(req(OpMove, "SHOP-1", map[string]any{"state": "In review"}))
	ref := wantRefusal(t, err, ops.CodeParamsInvalid)
	if !strings.Contains(ref.Why, "chap intake states") {
		t.Errorf("why: %s", ref.Why)
	}
}

func TestMoveToTheStateItIsInSendsNothing(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.fake.AddIssue(lineartest.Issue{Identifier: "SHOP-5", Title: "x", Labels: []string{"claude"}, State: "Blocked"})
	_, _, out, err := r.run(req(OpMove, "SHOP-5", map[string]any{"state": "Blocked"}))
	out = mustSucceed(t, out, err)
	if out.Result["moved"] != false || r.fake.Count("IntakeSetState") != 0 {
		t.Errorf("result %v, moves %d", out.Result, r.fake.Count("IntakeSetState"))
	}
}

func TestAWriteMakesTheNextListReadLinear(t *testing.T) {
	r := newRig(t, rigOpts{interval: 15 * time.Minute})
	r.seed()
	list := func() ops.Outcome {
		_, _, out, err := r.run(req(OpList, "board", nil))
		return mustSucceed(t, out, err)
	}
	list()
	if out := list(); out.Result["source"] != SourceCache {
		t.Fatal("second list not cached")
	}
	_, _, out, err := r.run(req(OpMove, "SHOP-1", map[string]any{"state": "Handed to engineering"}))
	mustSucceed(t, out, err)
	after := list()
	if after.Result["source"] != SourceLive {
		t.Fatal("a list after a write came from the cache")
	}
	var state string
	for _, it := range resultItems(t, after) {
		if it["identifier"] == "SHOP-1" {
			state = it["state"].(map[string]any)["name"].(string)
		}
	}
	if state != "Handed to engineering" {
		t.Errorf("SHOP-1 shows %q", state)
	}
}

// ---- intake.states ----------------------------------------------------------------

func TestStatesListsTheRealStatesAndMarksThePolicysAndTheMissing(t *testing.T) {
	r := newRig(t)
	r.seed()
	r.pol.States = []string{"Blocked", "Handed to engineering", "In review"}
	_, _, out, err := r.run(req(OpStates, "board", nil))
	out = mustSucceed(t, out, err)
	if out.Result["team"] != "SHOP" || out.Result["team_name"] != "Operations" {
		t.Errorf("head: %v", out.Result)
	}
	in := map[string]bool{}
	var names []string
	for _, e := range out.Result["states"].([]any) {
		s := e.(map[string]any)
		names = append(names, s["name"].(string))
		in[s["name"].(string)] = s["in_policy"].(bool)
	}
	if len(names) != 7 || !in["Blocked"] || !in["Handed to engineering"] || in["Todo"] || in["Completed"] {
		t.Errorf("states %v in_policy %v", names, in)
	}
	if miss := out.Result["policy_not_in_team"].([]any); len(miss) != 1 || miss[0] != "In review" {
		t.Errorf("missing %v", miss)
	}
	if r.fake.Count(opTeam) != 1 || r.fake.Count("IntakeSetState")+r.fake.Count("IntakeComment") != 0 {
		t.Error("unexpected calls")
	}
}

// ---- the lifecycle fields -----------------------------------------------------------

func TestAdaptersAreIdempotentPerExecution(t *testing.T) {
	// A repeat of Execute with the same execution id reuses the comment id, so
	// Linear refuses the second as a duplicate and no second comment appears.
	r := newRig(t)
	r.seed()
	q := req(OpComment, "SHOP-1", map[string]any{"body": "hello"})
	if _, err := r.ad(OpComment).Check(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	out, err := r.ad(OpComment).Execute(context.Background(), q)
	mustSucceed(t, out, err)
	out, err = r.ad(OpComment).Execute(context.Background(), q)
	mustFail(t, out, err, "exists")
	if n := len(r.fake.Issue("SHOP-1").Comments); n != 1 {
		t.Errorf("comments: %d", n)
	}
}

var _ = spec.Target{}

// A missing or refused credential is a refusal the operator can read, not a
// bare 503: retrying cannot fix it.
func TestMissingOrRefusedCredentialsAreRefusals(t *testing.T) {
	r := newRig(t)
	r.seed()
	delete(r.secrets.m, SecretClientSecret)
	_, err, _, _ := r.run(req(OpComment, "SHOP-1", map[string]any{"body": "hello"}))
	if ref := wantRefusal(t, err, ops.CodePolicyRefused); !strings.Contains(ref.Why, "not connected") {
		t.Errorf("why: %s", ref.Why)
	}
	r.secrets.set(SecretClientSecret, "lin-client-secret-ROTATED-0123456789abcdef0123456789")
	_, err, _, _ = r.run(req(OpMove, "SHOP-1", map[string]any{"state": "Blocked"}))
	ref := wantRefusal(t, err, ops.CodePolicyRefused)
	if !strings.Contains(ref.Why, "invalid_client") || strings.Contains(ref.Why, "ROTATED") {
		t.Errorf("why: %s", ref.Why)
	}
	// intake.list reports the same in its failed result.
	_, _, out, err2 := r.run(req(OpList, "board", nil))
	mustFail(t, out, err2, "invalid_client")
}
