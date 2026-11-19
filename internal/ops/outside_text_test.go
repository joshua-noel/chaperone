package ops_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// Text that GitHub sends and a pull request author controls reaches the
// operator (the approval card, the checks) and the agent (the results). These
// tests plant hostile text in the fake GitHub and check that no control, bidi
// or zero-width character comes out of the GitHub adapters.

// hostileChars are what the adapters must never pass on.
const hostileChars = "\u202e\u202a\u2066\u2069\u200b\u200d\u2060\ufeff\u200f\x07\x1b\x00"

// strs collects every string in a result, with the path to it.
func strs(path string, v any, out map[string]string) {
	switch x := v.(type) {
	case string:
		out[path] = x
	case []string:
		for i, s := range x {
			out[fmt.Sprintf("%s[%d]", path, i)] = s
		}
	case []any:
		for i, e := range x {
			strs(fmt.Sprintf("%s[%d]", path, i), e, out)
		}
	case map[string]any:
		for k, e := range x {
			strs(path+"."+k, e, out)
		}
	}
}

func noHostile(t *testing.T, what string, v any) {
	t.Helper()
	all := map[string]string{}
	strs(what, v, all)
	for path, s := range all {
		if i := strings.IndexAny(s, hostileChars); i >= 0 {
			t.Errorf("%s holds the character U+%04X: %q", path, []rune(s[i:])[0], s)
		}
	}
}

func TestPRReadsCleanTheAuthorsText(t *testing.T) {
	f := newReadFx(t, nil)
	branch := "agent/\u202egnp"
	n, head := f.pr(branch, ghtest.PROptions{
		Title:  "feat: add\u200d a thing",
		Body:   "line one\r\nline two \x1b[31mred\x1b[0m \u202eevil\u202c\n\x00end",
		Author: "mallory\u202e",
		Labels: []string{"bug\u200b", "ci\x07"},
	})
	f.r.SetFiles(n, ghtest.File{Filename: "src/\u202egnp.exe", Additions: 1, Patch: "@@ -1 +1 @@\n+x\u202ey\n"},
		ghtest.File{Filename: "new\u200dname.go", PreviousFilename: "old\nname\u2066.go", Status: "renamed"})
	f.r.SetCheck(head, ghtest.Check{Name: "lint\n\x1b[31mred", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})

	for _, op := range ops.PRReadOps {
		t.Run(op, func(t *testing.T) {
			out := f.run(t, op, n, map[string]any{})
			r := mustSucceed(t, out)
			noHostile(t, op, r)
			noHostile(t, op+" external_ref", out.ExternalRef)
			if r["untrusted_text"] != true {
				t.Errorf("the result of %s is not marked untrusted_text", op)
			}
		})
	}

	// What stays: the words, and the lines of a body.
	view := mustSucceed(t, f.run(t, ops.OpPRView, n, map[string]any{}))
	if got := view["title"]; got != "feat: add  a thing" {
		t.Errorf("title = %q", got)
	}
	if got := view["body"].(string); !strings.Contains(got, "line one\nline two") || !strings.Contains(got, "red") || strings.Contains(got, "\r") {
		t.Errorf("body = %q", got)
	}
	files := mustSucceed(t, f.run(t, ops.OpPRFiles, n, map[string]any{}))["files"].([]any)
	if got := files[0].(map[string]any)["filename"]; got != "src/ gnp.exe" {
		t.Errorf("filename = %q", got)
	}
	if got := files[1].(map[string]any)["previous_filename"]; got != "old name .go" {
		t.Errorf("previous_filename = %q (a path is one line)", got)
	}
	runs := mustSucceed(t, f.run(t, ops.OpPRChecks, n, map[string]any{}))["runs"].([]any)
	if got := runs[0].(map[string]any)["name"]; got != "lint  [31mred" {
		t.Errorf("check name = %q", got)
	}
	diff := mustSucceed(t, f.run(t, ops.OpPRDiff, n, map[string]any{}))
	if d, _ := diff["diff"].(string); strings.ContainsAny(d, hostileChars) {
		t.Errorf("diff = %q", d)
	}
}

func TestPRMergeCleansThePathsOfTheCardAndTheResult(t *testing.T) {
	f := newFx(t)
	f.r.Branch("agent/hostile", base)
	head := f.r.Commit("agent/hostile")
	n := f.r.OpenPR(ghtest.PROptions{Title: "docs: update\u200d notes", Head: "agent/hostile", Base: base, Author: "mallory\u202e"})
	f.r.SetFiles(n, ghtest.File{Filename: "internal/app/\u202egnp.go"}, ghtest.File{Filename: "internal/app/b\u200d.go"})
	f.r.SetCheck(head, verify("completed", "success"))
	a := f.mergeAdapter()
	r := f.mergeReq("storefront", n, head)

	res, err := a.Check(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsApproval {
		t.Fatalf("res = %+v", res)
	}
	for _, c := range res.Checks {
		noHostile(t, "check "+c.Name, c.Detail)
	}
	noHostile(t, "approval why", res.ApprovalWhy)
	for _, e := range res.Evidence {
		noHostile(t, "evidence "+e.Name, e.Name+"\n"+e.Text)
	}
	if got := res.Evidence[1].Text; !strings.Contains(got, "internal/app/ gnp.go") || !strings.Contains(got, "internal/app/b .go") {
		t.Errorf("paths on the card = %q", got)
	}
	if first, _, _ := strings.Cut(res.Evidence[0].Text, "\n"); first != ops.PRTitlePrefix+"docs: update  notes" {
		t.Errorf("title on the card = %q", first)
	}

	// Released under the card the operator saw: the title on the card is the
	// title the merge compares, so a title with an invisible character merges.
	r.ApprovedEvidence = res.Evidence
	if _, err := a.Check(ctx, r); err != nil {
		t.Fatalf("release check: %v", err)
	}
	out, err := a.Execute(ctx, r)
	if err != nil || out.Failed || out.Unconfirmed {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	noHostile(t, "result", out.Result)
	noHostile(t, "external ref", out.ExternalRef)
	if ok, _ := f.r.Merged(n); !ok {
		t.Fatal("not merged under the approved title")
	}
	f.noLeak(t)
}

// A check that fails quotes GitHub's text (a state, a conclusion): cleaned.
func TestPRMergeRefusalTextIsCleaned(t *testing.T) {
	f := newFx(t)
	n, head := f.open(t, "agent/odd", "docs: update notes")
	f.r.SetCheck(head, verify("completed", "fail\u202eure\x1b[0m"))
	_, err := f.mergeAdapter().Check(ctx, f.mergeReq("storefront", n, head))
	wantRefusal(t, err, ops.CodePolicyRefused, "concluded")
	if err != nil {
		noHostile(t, "refusal", err.(*ops.Refusal).Why)
	}
}
