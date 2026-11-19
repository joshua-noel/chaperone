package main

import (
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
)

// Two test-only operations that stand for what the next connector may need and
// no shipped operation uses yet: a repository with no number, a repeatable
// list flag, a required whole number with a maximum, a fixed word, and a ref
// that is also a param. They are not in the shipped catalog.
func widgetOps(t *testing.T) []kit.Op {
	t.Helper()
	add := kit.Op{
		Name:          "widgets.add",
		Class:         kit.Routine,
		Reversibility: kit.Reversible,
		Summary:       "Add a widget.",
		Usage:         "chap widgets add --size <n> --label <l>",
		RatePerMinute: 6,
		Doc:           "Target is the repository.",
		Target:        kit.Target{Adapter: "github", Repo: true},
		Params: []kit.Param{
			{Name: "size", Kind: kit.Int, Required: true, Min: 1, Max: 100, Placeholder: "n", Help: "the size, 1 to 100"},
			{Name: "labels", Kind: kit.List, Required: true, MaxItems: 5, MinLength: 1, MaxLength: 20, Flag: "label", Placeholder: "l", Help: "a label"},
			{Name: "ref", Kind: kit.String, Pattern: githubspec.SHAPattern, CLIPattern: `^[0-9a-f]{7}$`, Why: "--ref must be a 7-character lowercase hex id", Placeholder: "id", Help: "a commit"},
			{Name: "offset", Kind: kit.Int, Min: 5, Placeholder: "n", Help: "where to start"},
			{Name: "mode", Kind: kit.String, Required: true, Const: "fixed"},
		},
		CLI: kit.CLI{DryRun: "check only"},
	}
	run := kit.Op{
		Name:          "widgets.run",
		Class:         kit.Routine,
		Reversibility: kit.Reversible,
		Summary:       "Run a widget.",
		Usage:         "chap widgets run <w-id>",
		RatePerMinute: 6,
		Doc:           "Target is the run.",
		Target:        kit.Target{Adapter: "runner", Pattern: `^w-[0-9]{1,4}$`, Why: "%q is not a widget like w-12", Positional: "w-id"},
		Params:        []kit.Param{{Name: "widget", Kind: kit.String, Required: true, Pattern: `^w-[0-9]{1,4}$`, FromRef: true}},
	}
	for _, o := range []kit.Op{add, run} {
		if err := o.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	return []kit.Op{add, run}
}

func withWidgets(t *testing.T) {
	t.Helper()
	ops := widgetOps(t)
	prev := declaredOps
	declaredOps = func() []kit.Op { return append(prev(), ops...) }
	t.Cleanup(func() { declaredOps = prev })
}

func TestGeneratedCommandFromRepoListIntAndConst(t *testing.T) {
	withWidgets(t)
	t.Run("usage", func(t *testing.T) {
		ta := newTestApp(t, env{})
		code := ta.run([]string{"widgets", "add", "-h"})
		want := "usage: chap widgets add --size <n> --label <l> [--label <l>] [--ref <id>] [--offset <n>] [--repo owner/name] [--dry-run]\n"
		if code != 0 || !strings.HasPrefix(ta.out.String(), want) {
			t.Errorf("exit %d, help:\n%s", code, ta.out)
		}
	})
	t.Run("sends the request, the repository from --repo", func(t *testing.T) {
		chapd := newFakeChapd(t, *ok200("op-intake-states"))
		ta := newTestApp(t, env{chapd: chapd, token: "orch"})
		args := []string{"widgets", "add", "--size", "7", "--label", "a,b", "--label", "c", "--ref", "0588aa4", "--offset", "9", "--repo", "example-org/storefront", "--project", "p", "--dry-run"}
		if code := ta.run(args); code != 0 {
			t.Fatalf("exit %d: %s", code, ta.errb)
		}
		want := `{"dry_run":true,"op":"widgets.add","params":{"labels":["a","b","c"],"mode":"fixed","offset":9,"ref":"0588aa4","size":7},"project":"p","target":{"adapter":"github","ref":"example-org/storefront"}}`
		if len(chapd.reqs) != 1 || !strings.HasSuffix(chapd.reqs[0], "\n"+want) {
			t.Errorf("requests = %q, want a body %s", chapd.reqs, want)
		}
	})
	t.Run("the repository from the git remote", func(t *testing.T) {
		chapd := newFakeChapd(t, *ok200("op-intake-states"))
		ta := newTestApp(t, env{chapd: chapd, token: "orch", git: gitOrigin})
		if code := ta.run([]string{"widgets", "add", "--size", "7", "--label", "a", "--project", "p"}); code != 0 {
			t.Fatalf("exit %d: %s", code, ta.errb)
		}
		if len(chapd.reqs) != 1 || !strings.Contains(chapd.reqs[0], `"ref":"acme/shop"`) {
			t.Errorf("requests = %q", chapd.reqs)
		}
	})
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"a required int left out":    {[]string{"widgets", "add", "--label", "a"}, "--size is required"},
		"a required list left out":   {[]string{"widgets", "add", "--size", "3"}, "--label is required"},
		"an int above the maximum":   {[]string{"widgets", "add", "--size", "101", "--label", "a"}, "--size must be 1 to 100"},
		"a negative int":             {[]string{"widgets", "add", "--size", "-4", "--label", "a"}, "--size must be 1 to 100"},
		"an int with no maximum":     {[]string{"widgets", "add", "--size", "3", "--label", "a", "--offset", "2"}, "--offset must be 5 or more"},
		"a flag the declaration has": {[]string{"widgets", "add", "--size", "3", "--label", "a", "--mode", "x"}, "flag provided but not defined: -mode"},
		"a stricter command pattern": {[]string{"widgets", "add", "--size", "3", "--label", "a", "--ref", githubspec.SHAPattern}, "--ref must be a 7-character lowercase hex id"},
		"a bad repo":                 {[]string{"widgets", "add", "--size", "3", "--label", "a", "--repo", "nope"}, "--repo must be owner/name"},
	} {
		t.Run(name, func(t *testing.T) {
			chapd := newFakeChapd(t, *ok200("op-intake-states"))
			ta := newTestApp(t, env{chapd: chapd, token: "orch"})
			code := ta.run(c.args)
			if code != exitUsage || len(chapd.reqs) != 0 || !strings.Contains(ta.errb.String(), c.want) {
				t.Errorf("exit %d, requests %q, stderr %q, want %q", code, chapd.reqs, ta.errb, c.want)
			}
		})
	}
}

// A ref that is also a param, and a usage error that names the ref given.
func TestGeneratedCommandRefAsParam(t *testing.T) {
	withWidgets(t)
	chapd := newFakeChapd(t, *ok200("op-intake-states"))
	ta := newTestApp(t, env{chapd: chapd, token: "orch"})
	if code := ta.run([]string{"widgets", "run", "w-12", "--project", "p"}); code != 0 {
		t.Fatalf("exit %d: %s", code, ta.errb)
	}
	want := `{"op":"widgets.run","params":{"widget":"w-12"},"project":"p","target":{"adapter":"runner","ref":"w-12"}}`
	if len(chapd.reqs) != 1 || !strings.HasSuffix(chapd.reqs[0], "\n"+want) {
		t.Errorf("requests = %q, want a body %s", chapd.reqs, want)
	}
	chapd = newFakeChapd(t, *ok200("op-intake-states"))
	ta = newTestApp(t, env{chapd: chapd, token: "orch"})
	code := ta.run([]string{"widgets", "run", "x-1"})
	if code != exitUsage || len(chapd.reqs) != 0 || !strings.Contains(ta.errb.String(), `"x-1" is not a widget like w-12`+"\nusage: chap widgets run <w-id>") {
		t.Errorf("exit %d, requests %q, stderr %q", code, chapd.reqs, ta.errb)
	}
}

// What the shipped GitHub commands send, from their declarations: the requests
// the hand-written commands sent. A change here is a change of behaviour.
func TestGitHubCommandsSendWhatTheyAlwaysSent(t *testing.T) {
	const repo = "example-org/storefront"
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"pr.view": {[]string{"pr", "view", "214"},
			`{"op":"pr.view","params":{},"project":"p","target":{"adapter":"github","ref":"` + repo + `#214"}}`},
		"pr.diff with a head": {[]string{"pr", "diff", "214", "--expected-head", sha1},
			`{"op":"pr.diff","params":{"expected_head_sha":"` + sha1 + `"},"project":"p","target":{"adapter":"github","ref":"` + repo + `#214"}}`},
		"pr.checks dry run": {[]string{"pr", "checks", "214", "--dry-run"},
			`{"dry_run":true,"op":"pr.checks","params":{},"project":"p","target":{"adapter":"github","ref":"` + repo + `#214"}}`},
		"pr.files, both numbers": {[]string{"pr", "files", "214", "--page", "2", "--per-page", "100"},
			`{"op":"pr.files","params":{"page":2,"per_page":100},"project":"p","target":{"adapter":"github","ref":"` + repo + `#214"}}`},
		"pr.files, none": {[]string{"pr", "files", "214", "--page", "0"},
			`{"op":"pr.files","params":{},"project":"p","target":{"adapter":"github","ref":"` + repo + `#214"}}`},
		"pr.update, everything": {[]string{"pr", "update", "7", "--expected-head", sha1, "--title", "t", "--body", "b", "--update-branch"},
			`{"op":"pr.update","params":{"body":"b","expected_head_sha":"` + sha1 + `","number":7,"title":"t","update_branch":true},"project":"p","target":{"adapter":"github","ref":"` + repo + `#7"}}`},
		"pr.update, the head only": {[]string{"pr", "update", "7", "--expected-head", sha1},
			`{"op":"pr.update","params":{"expected_head_sha":"` + sha1 + `","number":7},"project":"p","target":{"adapter":"github","ref":"` + repo + `#7"}}`},
		"issue.comment": {[]string{"issue", "comment", "9", "--body", "again"},
			`{"op":"issue.comment","params":{"body":"again"},"project":"p","target":{"adapter":"github","ref":"` + repo + `#9"}}`},
		"issue.reopen": {[]string{"issue", "reopen", "9"},
			`{"op":"issue.reopen","params":{},"project":"p","target":{"adapter":"github","ref":"` + repo + `#9"}}`},
		"ci.report": {[]string{"ci", "report", "r-7f3a"},
			`{"op":"ci.report","params":{"run_id":"r-7f3a"},"project":"p","target":{"adapter":"runner","ref":"r-7f3a"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			chapd := newFakeChapd(t, *ok200("op-intake-states"))
			ta := newTestApp(t, env{chapd: chapd, token: "orch"})
			args := append(append([]string(nil), c.args...), "--project", "p")
			if c.args[0] != "ci" {
				args = append(args, "--repo", repo)
			}
			if code := ta.run(args); code != 0 {
				t.Fatalf("exit %d: %s", code, ta.errb)
			}
			if len(chapd.reqs) != 1 || !strings.HasSuffix(chapd.reqs[0], "\n"+c.want) {
				t.Errorf("requests = %q, want a body %s", chapd.reqs, c.want)
			}
		})
	}
}

// The usage errors the hand-written commands gave, word for word.
func TestGitHubCommandsRefuseWhatTheyAlwaysRefused(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"pr.view number":         {[]string{"pr", "view", "0", "--repo", "a/b"}, "the PR number must be a positive integer\nusage: chap pr view <n> [--repo owner/name] [--dry-run]"},
		"pr.diff sha-256 head":   {[]string{"pr", "diff", "1", "--repo", "a/b", "--expected-head", strings.Repeat("a", 64)}, "--expected-head must be a 40-character lowercase hex sha"},
		"pr.files page":          {[]string{"pr", "files", "1", "--repo", "a/b", "--page", "-1"}, "--page must be 1 or more"},
		"pr.files per page":      {[]string{"pr", "files", "1", "--repo", "a/b", "--per-page", "101"}, "--per-page must be 1 to 100"},
		"pr.update without head": {[]string{"pr", "update", "1", "--repo", "a/b"}, "--expected-head must be a 40-character lowercase hex sha"},
		"pr.update empty head":   {[]string{"pr", "update", "1", "--repo", "a/b", "--expected-head", ""}, "--expected-head must be a 40-character lowercase hex sha"},
		"pr.update number":       {[]string{"pr", "update", "x", "--repo", "a/b", "--expected-head", sha1}, "the PR number must be a positive integer"},
		"issue.comment number":   {[]string{"issue", "comment", "0", "--repo", "a/b", "--body", "x"}, "the issue number must be a positive integer"},
		"issue.comment no body":  {[]string{"issue", "comment", "1", "--repo", "a/b"}, "--body or --body-file is required"},
		"issue.reopen number":    {[]string{"issue", "reopen", "x3", "--repo", "a/b"}, "the issue number must be a positive integer"},
		"ci.report run id":       {[]string{"ci", "report", "7f3a"}, `"7f3a" is not a run id like r-7f3a` + "\nusage: chap ci report <run-id> [--dry-run]"},
	} {
		t.Run(name, func(t *testing.T) {
			chapd := newFakeChapd(t, *ok200("op-intake-states"))
			ta := newTestApp(t, env{chapd: chapd, token: "orch"})
			code := ta.run(c.args)
			if code != exitUsage || len(chapd.reqs) != 0 || !strings.Contains(ta.errb.String(), c.want) {
				t.Errorf("exit %d, requests %q, stderr %q, want %q", code, chapd.reqs, ta.errb, c.want)
			}
		})
	}
}
