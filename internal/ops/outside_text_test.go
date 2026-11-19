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

// The card and the result say when text was cleaned, and never repeat the raw text.
func TestPRMergeSaysWhenItCleanedText(t *testing.T) {
	f := newFx(t)
	f.r.Branch("agent/hostile", base)
	head := f.r.Commit("agent/hostile")
	n := f.r.OpenPR(ghtest.PROptions{Title: "docs: update\u200d notes", Head: "agent/hostile", Base: base, Author: "mallory\u202e"})
	f.r.SetFiles(n, ghtest.File{Filename: "internal/app/\u202egnp.go"}, ghtest.File{Filename: "internal/app/b\u200d.go"}, ghtest.File{Filename: "internal/app/c.go"})
	f.r.SetCheck(head, verify("completed", "success"))
	a := f.mergeAdapter()
	r := f.mergeReq("storefront", n, head)
	res, err := a.Check(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	warning := func(checks []ops.Check) string {
		for _, c := range checks {
			if c.Name == "hidden_text" {
				if !c.Passed {
					t.Error("the hidden_text check must not fail the merge")
				}
				return c.Detail
			}
		}
		return ""
	}
	want := "1 title, 1 author name, 2 file paths held hidden or control characters; shown with each such character replaced by a space"
	if got := warning(res.Checks); got != want {
		t.Errorf("warning = %q, want %q", got, want)
	}
	r.ApprovedEvidence = res.Evidence
	out, err := a.Execute(ctx, r)
	if err != nil || out.Failed {
		t.Fatalf("out = %+v, err = %v", out, err)
	}
	found := false
	for _, c := range out.Result["checks"].([]any) {
		if m := c.(map[string]any); m["name"] == "hidden_text" && m["detail"] == want {
			found = true
		}
	}
	if !found {
		t.Errorf("the result does not carry the warning: %v", out.Result["checks"])
	}

	// A clean pull request carries no such check.
	g, gh := f.green(t, "agent/clean", "internal/app/clean.go")
	clean, err := a.Check(ctx, f.mergeReq("storefront", g, gh))
	if err != nil {
		t.Fatal(err)
	}
	if w := warning(clean.Checks); w != "" {
		t.Errorf("a clean pull request has the warning %q", w)
	}
}

func TestPRReadsSayWhenTheyCleanedText(t *testing.T) {
	f := newReadFx(t, nil)
	n, _ := f.pr("agent/\u202egnp", ghtest.PROptions{Title: "feat: add\u200d a thing", Body: "plain\r\nbody", Author: "octo"})
	f.r.SetFiles(n, ghtest.File{Filename: "src/\u202egnp.exe"}, ghtest.File{Filename: "ok.go"})
	view := mustSucceed(t, f.run(t, ops.OpPRView, n, map[string]any{}))
	if got, want := view["hidden_characters"], "1 title, 1 branch name held hidden or control characters; shown with each such character replaced by a space"; got != want {
		t.Errorf("pr.view hidden_characters = %v, want %q", got, want)
	}
	files := mustSucceed(t, f.run(t, ops.OpPRFiles, n, map[string]any{}))
	if got, want := files["hidden_characters"], "1 file path held hidden or control characters; shown with each such character replaced by a space"; got != want {
		t.Errorf("pr.files hidden_characters = %v, want %q", got, want)
	}
	// Clean text, a CRLF body included, has no such field.
	m, _ := f.pr("agent/plain", ghtest.PROptions{Body: "line\r\nline", Author: "octo"})
	if r := mustSucceed(t, f.run(t, ops.OpPRView, m, map[string]any{})); r["hidden_characters"] != nil {
		t.Errorf("a clean pull request has hidden_characters: %v", r["hidden_characters"])
	}
}

func TestResultURLsAreHTTPSOrEmpty(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/example-org/storefront/pull/1": "https://github.com/example-org/storefront/pull/1",
		"":                            "",
		"http://github.com/x":         "",
		"javascript:alert(1)":         "",
		"//github.com/x":              "",
		"https:///nohost":             "",
		"https://github.com/x\u202ey": "",
		"https://exa mple.com/":       "",
		"https://github.com/" + strings.Repeat("a", 300): "",
	} {
		if got := ops.SafeURL(in, 300); got != want {
			t.Errorf("SafeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLineTextCleansAndCaps(t *testing.T) {
	if got := ops.LineText("a\u202eb\nc\x1b", 300); got != "a b c " {
		t.Errorf("LineText = %q", got)
	}
	if got := ops.LineText(strings.Repeat("x", 400), 300); len(got) != 300 {
		t.Errorf("LineText length %d", len(got))
	}
}

// A path that a file system could read as another name is not a plain path: it cannot be classified, so it is
// high and needs an approval. Before, a hidden character or a trailing dot made a protected file miss its rule and
// fall to a low glob (agents<ZWNJ>.md missed **/agents.md and matched **/*.md), which merges with no card.
func TestPathsThatReadAsAnotherNameAreHigh(t *testing.T) {
	g := ops.PRTierGlobs{}
	protected := []string{
		// the files the task named, each with a hidden character in or after the name
		"agents\u200c.md", "claude\ufeff.md", "CODEOWNERS\u200c", ".gitattributes\u2060",
		"requirements\u200d.txt", "require\u200dments.txt", "pyproject\u200b.toml",
		"docs/agents\u200d.md", ".gitmodules\u200b", "go.mod\u200c", "package.json\u200d",
		// inside a protected directory or on a protected extension
		".github\u200c/workflows/ci.yml", "\ufeffscripts/run.go", "vendor\u202e/x.go", "web/payment\u200b/checkout.ts",
		"deploy\u200d.yml", "src/\u202egnp.exe", "tools/run\u200b.sh",
		// a Unicode format character (Cf) of each kind
		"agents\u202a.md", "agents\u2066.md", "agents\u200e.md", "agents\u200f.md", "agents\u061c.md", "agents\u00ad.md", "agents\u206a.md",
		// default-ignorable code points that are not Cf
		"agents\u034f.md", "agents\u115f.md", "agents\u1160.md", "agents\u17b4.md", "agents\u17b5.md", "agents\u180b.md",
		"agents\u180d.md", "agents\u180f.md", "agents\u3164.md", "agents\uffa0.md", "agents\ufe00.md", "agents\ufe0f.md",
		"agents\U000e0100.md", "agents\U000e01ef.md", "agents\U000e0041.md",
		// a name that ends in a dot or a space (Windows drops them), in the file or in a directory
		"AGENTS.md.", "agents.md ", "docs./notes.md", "docs /notes.md", ".github./workflows/ci.yml", "CLAUDE.md..",
		// a colon (an NTFS stream name)
		"agents.md::$DATA", "docs/notes.md:stream", "AGENTS.md:Zone.Identifier",
		// a control character: refused before
		".github/\x07/x.yml", "agents\x00.md",
	}
	for _, p := range protected {
		got := g.ClassifyPath(p)
		t.Logf("%q -> %s", p, got)
		if got != ops.TierHigh {
			t.Errorf("ClassifyPath(%q) = %s, want high", p, got)
		}
		res := g.Classify([]ops.PRFile{{Path: p}})
		if res.Tier != ops.TierHigh || !res.Unclassified {
			t.Errorf("Classify(%q) = %+v, want high and unclassified", p, res)
		}
		// A rename out of such a path is high as well.
		if res := g.Classify([]ops.PRFile{{Path: "docs/a.md", PreviousPath: p, Status: "renamed"}}); res.Tier != ops.TierHigh {
			t.Errorf("a rename out of %q is %s, want high", p, res.Tier)
		}
		// A test-path downgrade does not apply: a removed test file with such a name is never low or medium on the
		// strength of its test-looking name.
		if res := g.Classify([]ops.PRFile{{Path: "tests/" + p, Status: "removed"}}); res.Tier != ops.TierHigh {
			t.Errorf("a removed test path under %q is %s, want high", p, res.Tier)
		}
	}
	// Plain names are classified as before.
	for p, want := range map[string]ops.PRTier{
		"agents.md": ops.TierHigh, "docs/notes.md": ops.TierLow, "README.md": ops.TierLow, "docs/caf\u00e9.md": ops.TierLow,
		"internal/app/app.go": ops.TierMedium, "internal/app/app_test.go": ops.TierLow, "docs/v1.2/notes.md": ops.TierLow,
		"requirements.txt": ops.TierMedium, "pyproject.toml": ops.TierMedium, "CODEOWNERS": ops.TierHigh,
	} {
		if got := g.ClassifyPath(p); got != want {
			t.Errorf("ClassifyPath(%q) = %s, want %s", p, got, want)
		}
	}
}
