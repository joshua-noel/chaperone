package ops_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/denialtext"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// policies is the project -> pr: block table the adapters read. Only
// storefront has a block.
func (f *fx) policies(project string) (ops.PRPolicy, bool) {
	if project == "storefront" {
		return f.pol, true
	}
	return ops.PRPolicy{}, false
}

func (f *fx) mergeAdapter() ops.Adapter  { return ops.NewPRMergeAdapter(f.m, f.policies) }
func (f *fx) updateAdapter() ops.Adapter { return ops.NewPRUpdateAdapter(f.m, f.policies) }

func (f *fx) mergeReq(project string, n int, head string) *ops.Request {
	return &ops.Request{
		Op: "pr.merge", Project: project,
		Target: spec.Target{Adapter: "github", Ref: fmt.Sprintf("example-org/storefront#%d", n)},
		Params: map[string]any{"base": base, "head_sha": head, "method": "squash"},
	}
}

func wantRefusal(t *testing.T, err error, code, contains string) {
	t.Helper()
	var ref *ops.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("err = %v, want a *Refusal", err)
	}
	if ref.Code != code || !strings.Contains(ref.Why, contains) || ref.CanRequest {
		t.Fatalf("refusal = %+v, want %s containing %q and not requestable", ref, code, contains)
	}
}

func TestAdapterCheckLowTierGreenWritesNothing(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	res, err := f.mergeAdapter().Check(ctx, f.mergeReq("storefront", n, head))
	if err != nil {
		t.Fatal(err)
	}
	if res.NeedsApproval || len(res.Checks) == 0 {
		t.Fatalf("res = %+v", res)
	}
	for _, c := range res.Checks {
		if !c.Passed {
			t.Errorf("check %s failed: %s", c.Name, c.Detail)
		}
	}
	if f.writes() != 0 {
		t.Fatal("Check merged")
	}
	if ok, _ := f.r.Merged(n); ok {
		t.Fatal("Check merged the PR")
	}
	f.noLeak(t)
}

func TestAdapterCheckRefusesRedCI(t *testing.T) {
	f := newFx(t)
	n, head := f.open(t, "agent/red", "docs: update notes")
	f.r.SetCheck(head, verify("completed", "failure"))
	res, err := f.mergeAdapter().Check(ctx, f.mergeReq("storefront", n, head))
	wantRefusal(t, err, ops.CodePolicyRefused, ops.StopCIRed)
	if len(res.Checks) == 0 {
		t.Fatal("a refusal still carries the checks")
	}
	if f.writes() != 0 {
		t.Fatal("a merge was sent")
	}
	f.noLeak(t)
}

func TestAdapterRefusesProjectWithoutPRBlock(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	before := len(f.s.Requests())
	_, err := f.mergeAdapter().Check(ctx, f.mergeReq("acme-shop", n, head))
	wantRefusal(t, err, ops.CodePolicyRefused, "no pr: block")
	u := &ops.Request{
		Op: "pr.update", Project: "acme-shop", Target: spec.Target{Adapter: "github", Ref: "example-org/storefront"},
		Params: map[string]any{"number": float64(n), "expected_head_sha": head},
	}
	_, err = f.updateAdapter().Check(ctx, u)
	wantRefusal(t, err, ops.CodePolicyRefused, "no pr: block")
	if got := len(f.s.Requests()); got != before {
		t.Fatalf("a project without a pr: block reached GitHub (%d requests)", got-before)
	}
}

func TestAdapterRefusesOtherRepoThanTheProjects(t *testing.T) {
	f := newFx(t)
	f.pol.Repo = "example-org/storefront"
	n, head := f.green(t, "agent/ok")
	before := len(f.s.Requests())
	r := f.mergeReq("storefront", n, head)
	r.Target.Ref = fmt.Sprintf("example-org/other#%d", n)
	_, err := f.mergeAdapter().Check(ctx, r)
	wantRefusal(t, err, ops.CodePolicyRefused, "merges only in example-org/storefront")
	u := &ops.Request{
		Op: "pr.update", Project: "storefront", Target: spec.Target{Adapter: "github", Ref: "example-org/other"},
		Params: map[string]any{"number": float64(n), "expected_head_sha": head},
	}
	_, err = f.updateAdapter().Check(ctx, u)
	wantRefusal(t, err, ops.CodePolicyRefused, "merges only in example-org/storefront")
	if got := len(f.s.Requests()); got != before {
		t.Fatalf("a request for another repository reached GitHub (%d requests)", got-before)
	}
	// The project's own repository (case does not matter) is not refused.
	r.Target.Ref = fmt.Sprintf("Example-Org/Storefront#%d", n)
	if _, err := f.mergeAdapter().Check(ctx, r); err != nil && strings.Contains(err.Error(), "merges only in") {
		t.Fatalf("own repository refused: %v", err)
	}
}

func TestAdapterParamsInvalid(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	a := f.mergeAdapter()
	cases := map[string]func(r *ops.Request){
		"unknown param":  func(r *ops.Request) { r.Params["force"] = true },
		"wrong method":   func(r *ops.Request) { r.Params["method"] = "merge" },
		"no method":      func(r *ops.Request) { delete(r.Params, "method") },
		"short sha":      func(r *ops.Request) { r.Params["head_sha"] = head[:8] },
		"no base":        func(r *ops.Request) { delete(r.Params, "base") },
		"target no PR #": func(r *ops.Request) { r.Target.Ref = "example-org/storefront" },
		"target bad num": func(r *ops.Request) { r.Target.Ref = "example-org/storefront#0" },
		"not github":     func(r *ops.Request) { r.Target.Adapter = "gitlab" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := f.mergeReq("storefront", n, head)
			mutate(r)
			_, err := a.Check(ctx, r)
			wantRefusal(t, err, ops.CodeParamsInvalid, "")
		})
	}
	if len(f.s.Requests()) != 0 {
		t.Fatal("a malformed request reached GitHub")
	}
}

func TestAdapterMediumTierNeedsApprovalThenMerges(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/code", "internal/app/app.go")
	a := f.mergeAdapter()
	r := f.mergeReq("storefront", n, head)
	res, err := a.Check(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsApproval || res.ApprovalWhy == "" || len(res.Evidence) != 2 || !strings.Contains(res.Evidence[1].Text, "internal/app/app.go") {
		t.Fatalf("res = %+v", res)
	}
	// The first evidence block names the pull request: its title first, as the card headline reads it (approvals.EvidencePR).
	if ev := res.Evidence[0]; ev.Name != "pull request" || !strings.HasPrefix(ev.Text, "Title: ") || !strings.Contains(ev.Text, "\nAuthor: ") || !strings.Contains(ev.Text, "\nSize: ") {
		t.Fatalf("pull request evidence = %+v", ev)
	}
	if f.writes() != 0 {
		t.Fatal("Check merged")
	}
	// The pipeline reaches Execute only after the approval; Execute then merges.
	out, err := a.Execute(ctx, r)
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	if ok, _ := f.r.Merged(n); !ok || out.Result["merged"] != true || out.ExternalRef == "" || out.Result["merge_commit_sha"] == "" {
		t.Fatalf("out = %+v", out)
	}
	f.noLeak(t)
}

func TestAdapterExecuteMergesLowTier(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	out, err := f.mergeAdapter().Execute(ctx, f.mergeReq("storefront", n, head))
	if err != nil || out.Failed || out.Unconfirmed || out.ExternalRef == "" {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	if ok, _ := f.r.Merged(n); !ok || f.writes() != 1 {
		t.Fatalf("merged=%v writes=%d", ok, f.writes())
	}
	f.noLeak(t)
}

// The evidence keeps the whole title, byte for byte: it is what the approver reads, and what the merge compares with
// the PR's title later. A 72-character title of three-byte characters is 200+ bytes and must not be cut.
func TestAdapterEvidenceHoldsTheWholeTitle(t *testing.T) {
	f := newFx(t)
	title := "feat: " + strings.Repeat("\u8a9e", 66) // 72 characters, 204 bytes, non-ASCII
	n, head := f.open(t, "agent/long", title)
	f.r.SetCheck(head, verify("completed", "success"))
	res, err := f.mergeAdapter().Check(ctx, f.mergeReq("storefront", n, head))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evidence) == 0 || res.Evidence[0].Name != ops.PRSubjectEvidence {
		t.Fatalf("evidence = %+v", res.Evidence)
	}
	if first, _, _ := strings.Cut(res.Evidence[0].Text, "\n"); first != ops.PRTitlePrefix+title {
		t.Fatalf("first evidence line %q, want the whole title %q", first, title)
	}
}

// A PR with no title (GitHub does not allow one, a fake or a failure might return one) is refused before any card, and
// no "pull request" block is offered for a card that cannot be made.
func TestAdapterEmptyTitleHasNoSubjectEvidence(t *testing.T) {
	f := newFx(t)
	n, head := f.open(t, "agent/untitled", "")
	f.r.SetCheck(head, verify("completed", "success"))
	res, err := f.mergeAdapter().Check(ctx, f.mergeReq("storefront", n, head))
	wantRefusal(t, err, ops.CodePolicyRefused, "")
	for _, e := range res.Evidence {
		if e.Name == ops.PRSubjectEvidence {
			t.Fatalf("evidence for an untitled PR: %+v", e)
		}
	}
}

// The approved title is the one in the card's evidence. Released under it the merge goes through; if the title was
// edited after the card was made, both the release check and the merge refuse (CI_STALE), and nothing is merged.
func TestAdapterBindsTheMergeToTheApprovedTitle(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/bound", "internal/app/app.go") // medium tier: needs a card
	a := f.mergeAdapter()
	r := f.mergeReq("storefront", n, head)
	res, err := a.Check(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	card := res.Evidence // what the operator saw: Title: docs: update notes

	edited := f.mergeReq("storefront", n, head)
	edited.ApprovedEvidence = []ops.Evidence{{Name: ops.PRSubjectEvidence, Text: ops.PRTitlePrefix + "feat(cart): add a delivery fee\nAuthor: octo"}}
	_, err = a.Check(ctx, edited)
	wantRefusal(t, err, ops.CodePolicyRefused, ops.StopCIStale)
	out, err := a.Execute(ctx, edited)
	if err != nil || !out.Failed || out.Result["merged"] != false || out.Result["stop"] != ops.StopCIStale {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	if ok, _ := f.r.Merged(n); ok || f.writes() != 0 {
		t.Fatal("merged under another title than the approved one")
	}

	r.ApprovedEvidence = card
	if _, err := a.Check(ctx, r); err != nil {
		t.Fatalf("release check under the approved title: %v", err)
	}
	out, err = a.Execute(ctx, r)
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	if ok, _ := f.r.Merged(n); !ok {
		t.Fatal("not merged under the approved title")
	}
	f.noLeak(t)
}

// The refusal for an edited title is shown to the agent by chap and the console through denialtext.NextStep, with the
// why line exactly as the adapter writes it. A retitled PR is not a stale branch: the step is to ask again for a new
// card, never "update the branch".
func TestEditedTitleRefusalHasItsOwnNextStep(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/retitled", "internal/app/app.go")
	r := f.mergeReq("storefront", n, head)
	r.ApprovedEvidence = []ops.Evidence{{Name: ops.PRSubjectEvidence, Text: ops.PRTitlePrefix + "feat(cart): add a delivery fee\nAuthor: octo"}}
	_, err := f.mergeAdapter().Check(ctx, r)
	var ref *ops.Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("err = %v, want a *Refusal", err)
	}
	step := denialtext.NextStep(ref.Code, ref.Why, "main")
	if !strings.Contains(step, "ask again so a new card shows the title") || strings.Contains(step, "chap pr update") || strings.Contains(step, "up to date") {
		t.Fatalf("why %q gives the step %q", ref.Why, step)
	}
	// and the console's look (Recheck) words the same real refusal as a retitled PR, not as a stale branch
	if plain := ops.PlainRefusal(ref); !ops.Retitled(ref) || !strings.Contains(plain, "retitled") || strings.Contains(plain, "behind the base") {
		t.Fatalf("why %q gives the console sentence %q", ref.Why, plain)
	}
	// and a real stale branch keeps its own step
	f.r.Commit(base)
	_, err = f.mergeAdapter().Check(ctx, f.mergeReq("storefront", n, head))
	if !errors.As(err, &ref) {
		t.Fatalf("err = %v, want a *Refusal", err)
	}
	if step := denialtext.NextStep(ref.Code, ref.Why, "main"); !strings.Contains(step, "chap pr update") {
		t.Fatalf("a stale branch: why %q gives the step %q", ref.Why, step)
	}
}

// A card made before the title evidence existed has no "pull request" block (here only the tier-paths block): nothing
// is bound, the merge reads the title it finds, as before the change.
func TestPreChangeCardLeavesTheMergeUnbound(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/old-card", "internal/app/app.go")
	a := f.mergeAdapter()
	r := f.mergeReq("storefront", n, head)
	r.ApprovedEvidence = []ops.Evidence{{Name: "paths that set the tier (medium)", Text: "internal/app/app.go"}}
	if _, err := a.Check(ctx, r); err != nil {
		t.Fatalf("release check: %v", err)
	}
	out, err := a.Execute(ctx, r)
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	if ok, _ := f.r.Merged(n); !ok {
		t.Fatal("a card with no title evidence blocked the merge")
	}
	f.noLeak(t)
}

func TestAdapterExecuteFailsWhenCIWentRedAfterCheck(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/ok")
	a := f.mergeAdapter()
	r := f.mergeReq("storefront", n, head)
	if _, err := a.Check(ctx, r); err != nil {
		t.Fatal(err)
	}
	f.r.SetCheck(head, verify("completed", "failure")) // the re-run on the same head came back red
	out, err := a.Execute(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Failed || out.Result["merged"] != false || out.Result["stop"] != ops.StopCIRed {
		t.Fatalf("out = %+v", out)
	}
	if ok, _ := f.r.Merged(n); ok || f.writes() != 0 {
		t.Fatal("a red PR was merged")
	}
	f.noLeak(t)
}

func TestAdapterUpdateBranch(t *testing.T) {
	f := newFx(t)
	n, head := f.green(t, "agent/x")
	f.r.Commit(base)
	a := f.updateAdapter()
	r := &ops.Request{
		Op: "pr.update", Project: "storefront", Target: spec.Target{Adapter: "github", Ref: fmt.Sprintf("example-org/storefront#%d", n)},
		Params: map[string]any{"number": float64(n), "expected_head_sha": head, "update_branch": true},
	}
	if _, err := a.Check(ctx, r); err != nil {
		t.Fatal(err)
	}
	out, err := a.Execute(ctx, r)
	if err != nil || out.Failed || out.Result["updated"] != true || out.Result["old_head"] != head || out.Result["new_head"] == head {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	f.noLeak(t)

	// Not behind any more: the update is refused as a result, not an error.
	r.Params["expected_head_sha"] = f.r.PRHead(n)
	out, err = a.Execute(ctx, r)
	if err != nil || !out.Failed || out.Result["updated"] != false {
		t.Fatalf("out = %+v, err = %v", out, err)
	}

	for name, mutate := range map[string]func(){
		"title":                func() { r.Params["title"] = "x" },
		"body":                 func() { r.Params["body"] = "x" },
		"update_branch false":  func() { r.Params["update_branch"] = false },
		"number vs target":     func() { r.Params["number"] = float64(n + 1) },
		"unknown param":        func() { r.Params["force"] = true },
		"no expected head sha": func() { delete(r.Params, "expected_head_sha") },
	} {
		r2 := *r
		r2.Params = map[string]any{"number": float64(n), "expected_head_sha": head, "update_branch": true}
		r = &r2
		mutate()
		if _, err := a.Check(ctx, r); err == nil {
			t.Errorf("%s: want refusal", name)
		}
	}
}
