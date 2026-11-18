package linear

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLinearsRateLimitStopsChapdUntilTheTimeItNamed(t *testing.T) {
	r := newRig(t)
	r.seed()
	ctx := context.Background()
	r.fake.RateLimitNext(1)
	_, err := r.client.TeamStates(ctx, "SHOP")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.Local || rl.RetryAfter != 120*time.Second || !Definite(err) {
		t.Fatalf("first call: %v", err)
	}
	sent := len(r.fake.Requests())
	// Inside the 120 s Retry-After nothing leaves chapd.
	r.clock.Advance(60 * time.Second)
	if _, err := r.client.TeamStates(ctx, "SHOP"); !errors.As(err, &rl) {
		t.Fatalf("second call: %v", err)
	}
	if len(r.fake.Requests()) != sent {
		t.Error("a request was sent while Linear's limit was used up")
	}
	r.clock.Advance(61 * time.Second)
	if _, err := r.client.TeamStates(ctx, "SHOP"); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
}

func TestChapdsOwnHourlyBudget(t *testing.T) {
	r := newRig(t, rigOpts{budget: 3})
	r.seed()
	ctx := context.Background()
	for i := range 3 {
		if _, err := r.client.TeamStates(ctx, "SHOP"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	_, err := r.client.TeamStates(ctx, "SHOP")
	var rl *RateLimitError
	if !errors.As(err, &rl) || !rl.Local || !Definite(err) {
		t.Fatalf("fourth call: %v", err)
	}
	if got := r.fake.Count("IntakeTeam"); got != 3 {
		t.Errorf("Linear saw %d calls", got)
	}
	r.clock.Advance(61 * time.Minute)
	if _, err := r.client.TeamStates(ctx, "SHOP"); err != nil {
		t.Fatalf("an hour later: %v", err)
	}
}

func TestFewRequestsRemainingStopsChapdUntilTheWindowResets(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.fake.SetRemaining(5)
	if _, err := r.client.TeamStates(ctx, "SHOP"); err != nil {
		t.Fatal(err)
	}
	_, err := r.client.TeamStates(ctx, "SHOP")
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("a call after Linear said 5 requests remain: %v", err)
	}
}

// The adapters can send five documents and no other, and the two mutations
// carry only the input fields they need: no label, title, description,
// assignee or archive change exists in this connector.
func TestOnlyTheFiveFixedDocumentsAreEverSent(t *testing.T) {
	r := newRig(t)
	r.seed()
	ctx := context.Background()
	docs := map[string]string{opList: queryList, opGuard: queryGuard, opTeam: queryTeam, opComment: mutationComment, opSetState: mutationSetState}

	for _, q := range []struct {
		op, ref string
		params  map[string]any
	}{
		{OpList, "board", nil},
		{OpList, "SHOP", map[string]any{"refresh": true, "closed": true}},
		{OpStates, "board", nil},
		{OpComment, "SHOP-1", map[string]any{"body": "Picked up by the orchestrator: https://github.com/example-org/storefront/issues/401"}},
		{OpMove, "SHOP-1", map[string]any{"state": "Handed to engineering"}},
		{OpMove, "SHOP-1", map[string]any{"state": "Blocked"}},
		{OpComment, "ENG-1", map[string]any{"body": "x"}}, // refused
	} {
		_, _, _, _ = r.run(req(q.op, q.ref, q.params))
	}
	_ = ctx
	var comments, moves int
	for _, rq := range r.fake.Requests() {
		want, ok := docs[rq.Name]
		if !ok || rq.Query != want {
			t.Fatalf("a document that is not one of the five was sent: %s\n%s", rq.Name, rq.Query)
		}
		switch rq.Name {
		case opComment:
			comments++
			in := rq.Vars["input"].(map[string]any)
			if keys := sortedKeys(in); !slices.Equal(keys, []string{"body", "id", "issueId"}) {
				t.Errorf("commentCreate input has %v", keys)
			}
			if len(rq.Vars) != 1 {
				t.Errorf("commentCreate variables: %v", rq.Vars)
			}
		case opSetState:
			moves++
			in := rq.Vars["input"].(map[string]any)
			if keys := sortedKeys(in); !slices.Equal(keys, []string{"stateId"}) {
				t.Errorf("issueUpdate input has %v", keys)
			}
			if keys := sortedKeys(rq.Vars); !slices.Equal(keys, []string{"id", "input"}) {
				t.Errorf("issueUpdate variables: %v", keys)
			}
		}
	}
	if comments != 1 || moves != 2 {
		t.Errorf("mutations sent: %d comments, %d moves", comments, moves)
	}
}

// Static check on the documents themselves: nothing that removes a label,
// edits text, deletes or archives can be written in them.
func TestTheDocumentsCannotChangeLabelsTextOrDelete(t *testing.T) {
	for name, doc := range map[string]string{"comment": mutationComment, "setState": mutationSetState} {
		for _, bad := range []string{"labelIds", "removeLabel", "addLabel", "issueLabel", "title", "description", "assignee", "archive", "Delete", "delete", "trash", "issueCreate", "teamId", "projectId", "cycleId"} {
			if strings.Contains(doc, bad) {
				t.Errorf("%s mentions %q", name, bad)
			}
		}
		if n := strings.Count(doc, "mutation"); n != 1 {
			t.Errorf("%s has %d mutations", name, n)
		}
	}
	for _, doc := range []string{queryList, queryGuard, queryTeam} {
		if strings.Contains(doc, "mutation") {
			t.Error("a query holds a mutation")
		}
	}
	if !strings.Contains(mutationSetState, "IssueUpdateInput") || !strings.Contains(mutationComment, "CommentCreateInput") {
		t.Error("the mutations changed their input types")
	}
}

func sortedKeys(m map[string]any) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	slices.Sort(k)
	return k
}

func TestCommentIDIsAVersion4UUIDFromTheExecution(t *testing.T) {
	a, b := CommentID("x-1"), CommentID("x-2")
	if a == b || a != CommentID("x-1") {
		t.Fatalf("ids: %s %s", a, b)
	}
	if len(a) != 36 || a[14] != '4' || !strings.ContainsRune("89ab", rune(a[19])) {
		t.Errorf("not a version 4 UUID: %s", a)
	}
}
