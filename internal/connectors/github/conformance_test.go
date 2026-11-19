package github_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/conformance"
	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/pintable"
	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/gh/ghtest"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// The shared connector suite against the real GitHub adapters (internal/ops)
// and the fake GitHub (internal/gh/ghtest). The fake mints its own tokens, so
// the suite cannot plant a canary as the credential here: the rig records every
// credential that goes over the wire (the App JWT and each installation
// token) and the suite looks for those.

const (
	projectName = "storefront"
	repoName    = "example-org/storefront"
	ciRun       = "r-7f3a"
)

// recorder is the HTTP transport of the client. It counts the calls that could
// change GitHub, which of them GitHub accepted, and remembers every credential
// sent. Minting and revoking the connector's own installation token is not a
// write to the repository.
type recorder struct {
	mu      sync.Mutex
	next    http.RoundTripper
	writes  int
	applied int
	creds   map[string]bool
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, cred, ok := strings.Cut(req.Header.Get("Authorization"), " "); ok {
		r.creds[cred] = true
	}
	own := (req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/access_tokens")) ||
		(req.Method == http.MethodDelete && strings.HasSuffix(req.URL.Path, "/installation/token"))
	if req.Method != http.MethodGet && req.Method != http.MethodHead && !own {
		r.writes++
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			r.applied++
		}
	}
	return resp, err
}

func (r *recorder) counts() (writes, applied int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writes, r.applied
}

func (r *recorder) credentials() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.creds))
	for c := range r.creds {
		out = append(out, c)
	}
	return out
}

// world is the seeded fake and the numbers the sample requests use. Plant moves
// the read PR to one with hostile text.
type world struct {
	s    *ghtest.Server
	repo *ghtest.Repo

	stalePR            int // behind the base: pr.update
	readPR, readHead   int
	readSHA            string // up to date, verify green: the reads and pr.merge
	redPR              int    // verify red
	newBranch          string // a branch with a commit and no PR: pr.open
	issue, closedIssue int    // labelled source:error-watcher
	plainIssue, pullNo int    // no label; a pull request seen as an issue
	runHead            string
}

func verify(conclusion string) ghtest.Check {
	return ghtest.Check{Name: "verify", AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: conclusion}
}

func newWorld(t testing.TB, in *ghtest.Installation) *world {
	w := &world{}
	r := in.AddRepo("storefront", "main")
	w.repo = r
	r.Branch("agent/stale", "main")
	staleSHA := r.Commit("agent/stale")
	w.stalePR = r.OpenPR(ghtest.PROptions{Title: "docs: update notes", Head: "agent/stale", Base: "main"})
	r.SetFiles(w.stalePR, ghtest.File{Filename: "docs/notes.md"})
	r.SetCheck(staleSHA, verify("success"))
	r.Commit("main") // the base moves on: agent/stale is now behind it
	r.Branch("agent/ok", "main")
	w.readSHA = r.Commit("agent/ok")
	w.readPR = r.OpenPR(ghtest.PROptions{Title: "docs: update notes", Head: "agent/ok", Base: "main", Body: "Fixes the notes.", Author: "alice", Labels: []string{"docs"}})
	r.SetFiles(w.readPR, ghtest.File{Filename: "docs/notes.md", Additions: 2, Patch: "@@ -1 +1,2 @@\n+one\n+two\n"})
	r.SetCheck(w.readSHA, verify("success"))
	r.Branch("agent/red", "main")
	redSHA := r.Commit("agent/red")
	w.redPR = r.OpenPR(ghtest.PROptions{Title: "docs: red", Head: "agent/red", Base: "main"})
	r.SetFiles(w.redPR, ghtest.File{Filename: "docs/notes.md"})
	r.SetCheck(redSHA, verify("failure"))
	w.newBranch = "feature/new"
	r.Branch(w.newBranch, "main")
	r.Commit(w.newBranch)
	w.issue = r.AddIssue(ghtest.IssueOptions{Title: "Error: boom", Labels: []string{ops.IssueLabel}})
	w.closedIssue = r.AddIssue(ghtest.IssueOptions{Title: "Error: old", Labels: []string{ops.IssueLabel}, Closed: true})
	w.plainIssue = r.AddIssue(ghtest.IssueOptions{Title: "A person's issue"})
	w.pullNo = r.AddIssue(ghtest.IssueOptions{Title: "A pull request", Labels: []string{ops.IssueLabel}, IsPull: true})
	w.runHead = w.readSHA
	return w
}

func (w *world) staleSHA() string { return w.repo.PRHead(w.stalePR) }
func (w *world) pr(n int) string  { return repoName + "#" + strconv.Itoa(n) }

// hostilePR opens a pull request whose text is planted and makes it the one
// the read samples and pr.merge use.
func (w *world) hostilePR(p conformance.Planted, title string, files []ghtest.File, checks ...ghtest.Check) {
	w.repo.Branch("agent/hostile", "main")
	sha := w.repo.Commit("agent/hostile")
	n := w.repo.OpenPR(ghtest.PROptions{
		Title: title, Head: "agent/hostile", Base: "main", Author: "mallory",
		Body: strings.TrimSpace(p.Long + " " + p.Secret),
	})
	w.repo.SetFiles(n, files...)
	w.repo.SetCheck(sha, verify("success"))
	for _, c := range checks {
		w.repo.SetCheck(sha, c)
	}
	w.readPR, w.readSHA = n, sha
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// newRig builds the fake, the App client and the adapters chapd registers for
// one declared connector (the same wiring as cmd/chapd/adapters.go).
func newRig(connector kit.Connector) func(t testing.TB, canary string) *conformance.Rig {
	return func(t testing.TB, _ string) *conformance.Rig {
		t.Helper()
		s := ghtest.New(t)
		rec := &recorder{next: http.DefaultTransport, creds: map[string]bool{}}
		c, err := gh.New(gh.Config{
			AppID: s.AppID(), Keys: gh.StaticKey{Key: s.Key()}, BaseURL: s.URL(), Now: s.Now,
			HTTPClient: &http.Client{
				Transport:     rec,
				Timeout:       30 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		in := s.AddInstallation(7, "example-org", map[string]string{
			"contents": "write", "pull_requests": "write", "checks": "write", "issues": "write", "deployments": "write", "metadata": "read",
		})
		w := newWorld(t, in)
		w.s = s
		minter := &ops.InstallationMinter{Client: c}
		projectOf := func(name string) (ops.PRProject, bool) {
			if name == projectName {
				return ops.PRProject{Repo: repoName, Base: "main"}, true
			}
			return ops.PRProject{}, false
		}
		mergePolicy := func(name string) (ops.PRPolicy, bool) {
			if name == projectName {
				return ops.PRPolicy{Version: "conformance-1", Repo: repoName, Base: "main"}, true
			}
			return ops.PRPolicy{}, false
		}
		ciPolicy := func(name string) (ops.PRPolicy, bool) {
			p, ok := mergePolicy(name)
			p.LocalCI = &ops.PRLocalCI{Check: "local-ci"}
			return p, ok
		}
		runs := func(_ context.Context, id string) (ops.CIRun, error) {
			base := ops.CIRun{RunID: id, Project: projectName, Profile: "ci", Repo: repoName, Head: w.runHead, Ended: true, Outcome: "done"}
			switch id {
			case ciRun:
				return base, nil
			case "r-aaaa":
				base.Ended, base.Outcome = false, ""
				return base, nil
			case "r-bbbb":
				base.Profile = "code"
				return base, nil
			}
			return ops.CIRun{}, ops.ErrCIRunUnknown
		}

		ads := map[string]ops.Adapter{}
		if connector.Name == githubspec.CI.Name {
			a, err := ops.NewCIReportAdapter(ops.CIReportConfig{GitHub: c, Tokens: minter, Runs: runs, Policy: ciPolicy})
			if err != nil {
				t.Fatal(err)
			}
			ads[githubspec.NameCIReport] = a
		} else {
			merger, err := ops.NewPRMerger(ops.PRMergerConfig{GitHub: c, Tokens: minter})
			if err != nil {
				t.Fatal(err)
			}
			ads[githubspec.NamePRMerge] = ops.NewPRMergeAdapter(merger, mergePolicy)
			ads[githubspec.NamePRUpdate] = ops.NewPRUpdateAdapter(merger, mergePolicy)
			opener, err := ops.NewPROpen(ops.PROpenConfig{GitHub: c, Tokens: minter, Project: projectOf})
			if err != nil {
				t.Fatal(err)
			}
			ads[githubspec.NamePROpen] = opener
			for _, op := range []string{ops.OpIssueOpen, ops.OpIssueComment, ops.OpIssueReopen} {
				if ads[op], err = ops.NewIssueAdapter(op, ops.IssueConfig{GitHub: c, Tokens: minter, Project: projectOf}); err != nil {
					t.Fatal(err)
				}
			}
			for _, op := range ops.PRReadOps {
				if ads[op], err = ops.NewPRReadAdapter(op, ops.PRReadConfig{GitHub: c, Tokens: minter, Project: projectOf}); err != nil {
					t.Fatal(err)
				}
			}
		}
		bound, err := kit.Bind(connector, ads)
		if err != nil {
			t.Fatal(err)
		}
		return &conformance.Rig{
			Adapters:      bound,
			WriteCalls:    func() int { n, _ := rec.counts(); return n },
			WritesApplied: func() int { _, n := rec.counts(); return n },
			Secrets:       rec.credentials,
			World:         w,
		}
	}
}

// ---- samples ----------------------------------------------------------------

type build func(w *world) (ref string, params map[string]any)

func orchestrator() *ops.Caller {
	return &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main", Projects: []string{projectName}}
}

func sample(name, op, adapter string, b build, change func(*ops.Request)) conformance.Sample {
	return refused(name, "", op, adapter, b, change)
}

func refused(name, code, op, adapter string, b build, change func(*ops.Request)) conformance.Sample {
	return conformance.Sample{Name: name, Code: code, Req: func(r *conformance.Rig) *ops.Request {
		ref, params := b(r.World.(*world))
		q := &ops.Request{
			ID: "q-abc123", Op: op, Project: projectName, Target: spec.Target{Adapter: adapter, Ref: ref},
			Params: params, Caller: orchestrator(),
		}
		if change != nil {
			change(q)
		}
		return q
	}}
}

func asRun(q *ops.Request) {
	q.Caller = &ops.Caller{Kind: ops.KindRun, RunID: "r-1", Project: projectName}
}
func otherProject(q *ops.Request) { q.Project = "another-project" }

func onRepo(ref string, params map[string]any) build {
	return func(*world) (string, map[string]any) { return ref, params }
}

func readPR(params map[string]any) build {
	return func(w *world) (string, map[string]any) { return w.pr(w.readPR), params }
}

func withHead(params map[string]any) build {
	return func(w *world) (string, map[string]any) {
		p := map[string]any{"expected_head_sha": w.readSHA}
		for k, v := range params {
			p[k] = v
		}
		return w.pr(w.readPR), p
	}
}

// readOp is the samples shared by the four read operations.
func readOp(op string, valid []conformance.Sample, plant func(*conformance.Rig, conformance.Planted), known string) conformance.Op {
	invalid := []conformance.Sample{
		refused("a run asks", ops.CodePolicyRefused, op, githubspec.Adapter, readPR(nil), asRun),
		refused("another repository", ops.CodeScopePath, op, githubspec.Adapter, onRepo("example-org/other#1", nil), nil),
		refused("a ref with no number", ops.CodeParamsInvalid, op, githubspec.Adapter, onRepo(repoName, nil), nil),
		refused("another adapter", ops.CodeParamsInvalid, op, "gitlab", readPR(nil), nil),
		refused("a project with no pr block", ops.CodePolicyRefused, op, githubspec.Adapter, readPR(nil), otherProject),
	}
	if op != ops.OpPRView {
		invalid = append(invalid, refused("a short head sha", ops.CodeParamsInvalid, op, githubspec.Adapter,
			readPR(map[string]any{"expected_head_sha": "abc123"}), nil))
	}
	return conformance.Op{
		Valid: valid, Invalid: invalid, ReadOnly: true, Text: conformance.ServiceText, Plant: plant,
		Known: map[conformance.CheckID]string{conformance.CheckServiceText: known},
	}
}

// pr.view, pr.diff, pr.checks and pr.files return text written by the PR's
// author. They cap it, and chapd redacts the result as a whole, but they do
// not set untrusted_text, clean control characters or withhold secret-shaped
// text as rule 5 of docs/connectors.md says.
const readsGap = "the result carries the pull request author's text with no untrusted_text flag, control and format characters kept, and secret-shaped text not withheld. It is capped, chapd redacts the whole result, and the MCP front and chap mark it as data, but the adapter does none of what rule 5 of docs/connectors.md asks"

func TestConformanceGitHub(t *testing.T) {
	newPR := func(w *world) (string, map[string]any) {
		return repoName, map[string]any{"title": "feat: a new thing", "head": w.newBranch, "base": "main"}
	}
	label := []any{ops.IssueLabel}
	cases := map[string]conformance.Op{
		githubspec.NamePRView: readOp(ops.OpPRView,
			[]conformance.Sample{sample("the read PR", ops.OpPRView, githubspec.Adapter, readPR(nil), nil)},
			func(r *conformance.Rig, p conformance.Planted) {
				r.World.(*world).hostilePR(p, orDefault(p.Control, "docs: plain title"), []ghtest.File{{Filename: "docs/notes.md"}})
			}, readsGap),
		githubspec.NamePRDiff: readOp(ops.OpPRDiff,
			[]conformance.Sample{
				sample("the read PR", ops.OpPRDiff, githubspec.Adapter, readPR(nil), nil),
				sample("with the expected head", ops.OpPRDiff, githubspec.Adapter, withHead(nil), nil),
			},
			func(r *conformance.Rig, p conformance.Planted) {
				name := strings.TrimSpace(p.Control + " " + p.Secret)
				r.World.(*world).hostilePR(p, "docs: plain title", []ghtest.File{{Filename: orDefault(name, "docs/notes.md"), Additions: 1, Patch: "@@ -1 +1 @@\n+" + p.Long + p.Secret + "\n"}})
			}, readsGap),
		githubspec.NamePRChecks: readOp(ops.OpPRChecks,
			[]conformance.Sample{
				sample("the read PR", ops.OpPRChecks, githubspec.Adapter, readPR(nil), nil),
				sample("with the expected head", ops.OpPRChecks, githubspec.Adapter, withHead(nil), nil),
			},
			func(r *conformance.Rig, p conformance.Planted) {
				name := strings.TrimSpace(p.Control + " " + p.Secret)
				r.World.(*world).hostilePR(p, "docs: plain title", []ghtest.File{{Filename: "docs/notes.md"}},
					ghtest.Check{Name: orDefault(name, "lint"), AppID: gh.GitHubActionsAppID, Status: "completed", Conclusion: "success"})
			}, readsGap),
		githubspec.NamePRFiles: readOp(ops.OpPRFiles,
			[]conformance.Sample{
				sample("the read PR", ops.OpPRFiles, githubspec.Adapter, readPR(nil), nil),
				sample("a page", ops.OpPRFiles, githubspec.Adapter, withHead(map[string]any{"page": 1.0, "per_page": 10.0}), nil),
			},
			func(r *conformance.Rig, p conformance.Planted) {
				name := strings.TrimSpace(p.Control + " " + p.Secret)
				r.World.(*world).hostilePR(p, "docs: plain title", []ghtest.File{{Filename: orDefault(name, "docs/notes.md")}})
			}, readsGap),

		githubspec.NamePROpen: {
			Valid: []conformance.Sample{sample("a branch with a commit", ops.OpPROpen, githubspec.Adapter, newPR, nil)},
			Invalid: []conformance.Sample{
				refused("another base", ops.CodeScopeBranch, ops.OpPROpen, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return repoName, map[string]any{"title": "t", "head": w.newBranch, "base": "develop"}
				}, nil),
				refused("another repository", ops.CodeScopePath, ops.OpPROpen, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return "example-org/other", map[string]any{"title": "t", "head": w.newBranch, "base": "main"}
				}, nil),
				refused("head is base", ops.CodeParamsInvalid, ops.OpPROpen, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return repoName, map[string]any{"title": "t", "head": "main", "base": "main"}
				}, nil),
				refused("a run with no task scope", ops.CodeScopePath, ops.OpPROpen, githubspec.Adapter, newPR, asRun),
				refused("a project with no pr block", ops.CodeParamsInvalid, ops.OpPROpen, githubspec.Adapter, newPR, otherProject),
				refused("another adapter", ops.CodeParamsInvalid, ops.OpPROpen, "gitlab", newPR, nil),
			},
			Text:  conformance.NoServiceText,
			Plant: func(*conformance.Rig, conformance.Planted) {}, // the result holds a number and a URL only: no text of the service is read
		},
		githubspec.NamePRUpdate: {
			Valid: []conformance.Sample{sample("a PR behind its base", githubspec.NamePRUpdate, githubspec.Adapter, func(w *world) (string, map[string]any) {
				return w.pr(w.stalePR), map[string]any{"expected_head_sha": w.staleSHA()}
			}, nil)},
			Invalid: []conformance.Sample{
				refused("a title", ops.CodeParamsInvalid, githubspec.NamePRUpdate, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.stalePR), map[string]any{"expected_head_sha": w.staleSHA(), "title": "new"}
				}, nil),
				refused("a short head sha", ops.CodeParamsInvalid, githubspec.NamePRUpdate, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.stalePR), map[string]any{"expected_head_sha": "abc123"}
				}, nil),
				refused("no PR number", ops.CodeParamsInvalid, githubspec.NamePRUpdate, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return repoName, map[string]any{"expected_head_sha": w.staleSHA()}
				}, nil),
				refused("another repository", ops.CodePolicyRefused, githubspec.NamePRUpdate, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return "example-org/other#1", map[string]any{"expected_head_sha": w.staleSHA()}
				}, nil),
				refused("a project with no pr block", ops.CodePolicyRefused, githubspec.NamePRUpdate, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.stalePR), map[string]any{"expected_head_sha": w.staleSHA()}
				}, otherProject),
			},
			Text:  conformance.NoServiceText,
			Plant: func(*conformance.Rig, conformance.Planted) {}, // the result holds shas and a message of the fake's own
		},
		githubspec.NamePRMerge: {
			Valid: []conformance.Sample{sample("a green PR", githubspec.NamePRMerge, githubspec.Adapter, mergeBuild, nil)},
			Invalid: []conformance.Sample{
				refused("verify is red", ops.CodePolicyRefused, githubspec.NamePRMerge, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.redPR), map[string]any{"base": "main", "head_sha": w.repo.PRHead(w.redPR), "method": "squash"}
				}, nil),
				refused("a short head sha", ops.CodeParamsInvalid, githubspec.NamePRMerge, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.readPR), map[string]any{"base": "main", "head_sha": "abc123", "method": "squash"}
				}, nil),
				refused("not squash", ops.CodeParamsInvalid, githubspec.NamePRMerge, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.readPR), map[string]any{"base": "main", "head_sha": w.readSHA, "method": "merge"}
				}, nil),
				refused("another repository", ops.CodePolicyRefused, githubspec.NamePRMerge, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return "example-org/other#1", map[string]any{"base": "main", "head_sha": w.readSHA, "method": "squash"}
				}, nil),
				refused("a project with no pr block", ops.CodePolicyRefused, githubspec.NamePRMerge, githubspec.Adapter, mergeBuild, otherProject),
			},
			Text: conformance.NoServiceText,
			Plant: func(r *conformance.Rig, p conformance.Planted) {
				r.World.(*world).hostilePR(p, "docs: update notes", []ghtest.File{{Filename: strings.TrimSpace("docs/" + p.Control + ".md")}})
			},
			Known: map[conformance.CheckID]string{conformance.CheckServiceText: mergePaths},
		},

		githubspec.NameIssueOpen: {
			Valid: []conformance.Sample{sample("a labelled issue", ops.OpIssueOpen, githubspec.Adapter, onRepo(repoName, map[string]any{
				"title": "Error: boom", "body": "Stack trace.", "labels": label}), nil)},
			Invalid: []conformance.Sample{
				refused("no watcher label", ops.CodePolicyRefused, ops.OpIssueOpen, githubspec.Adapter, onRepo(repoName, map[string]any{"title": "t", "labels": []any{"bug"}}), nil),
				refused("another repository", ops.CodeScopePath, ops.OpIssueOpen, githubspec.Adapter, onRepo("example-org/other", map[string]any{"title": "t", "labels": label}), nil),
				refused("a run asks", ops.CodePolicyRefused, ops.OpIssueOpen, githubspec.Adapter, onRepo(repoName, map[string]any{"title": "t", "labels": label}), asRun),
				refused("a title of two lines", ops.CodeParamsInvalid, ops.OpIssueOpen, githubspec.Adapter, onRepo(repoName, map[string]any{"title": "a\nb", "labels": label}), nil),
				refused("a ref with a number", ops.CodeParamsInvalid, ops.OpIssueOpen, githubspec.Adapter, onRepo(repoName+"#1", map[string]any{"title": "t", "labels": label}), nil),
			},
			NotRepeatable: issueRepeat,
			Text:          conformance.NoServiceText,
			Plant:         func(*conformance.Rig, conformance.Planted) {}, // the result holds a number and a URL only
		},
		githubspec.NameIssueComment: {
			Valid: []conformance.Sample{sample("a labelled issue", ops.OpIssueComment, githubspec.Adapter, issueBuild(map[string]any{"body": "Seen again."}), nil)},
			Invalid: []conformance.Sample{
				refused("an issue with no label", ops.CodePolicyRefused, ops.OpIssueComment, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.plainIssue), map[string]any{"body": "x"}
				}, nil),
				refused("a pull request", ops.CodePolicyRefused, ops.OpIssueComment, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.pullNo), map[string]any{"body": "x"}
				}, nil),
				refused("another repository", ops.CodeScopePath, ops.OpIssueComment, githubspec.Adapter, onRepo("example-org/other#1", map[string]any{"body": "x"}), nil),
				refused("a run asks", ops.CodePolicyRefused, ops.OpIssueComment, githubspec.Adapter, issueBuild(map[string]any{"body": "x"}), asRun),
				refused("an issue that does not exist", ops.CodeParamsInvalid, ops.OpIssueComment, githubspec.Adapter, onRepo(repoName+"#999", map[string]any{"body": "x"}), nil),
			},
			NotRepeatable: issueRepeat,
			Text:          conformance.NoServiceText,
			Plant: func(r *conformance.Rig, p conformance.Planted) {
				w := r.World.(*world)
				w.issue = w.repo.AddIssue(ghtest.IssueOptions{Title: orDefault(strings.TrimSpace(p.Control+" "+p.Secret), "Error: boom"), Labels: []string{ops.IssueLabel}})
			},
		},
		githubspec.NameIssueReopen: {
			Valid: []conformance.Sample{sample("a closed labelled issue", ops.OpIssueReopen, githubspec.Adapter, func(w *world) (string, map[string]any) {
				return w.pr(w.closedIssue), map[string]any{}
			}, nil)},
			Invalid: []conformance.Sample{
				refused("an issue with no label", ops.CodePolicyRefused, ops.OpIssueReopen, githubspec.Adapter, func(w *world) (string, map[string]any) {
					return w.pr(w.plainIssue), map[string]any{}
				}, nil),
				refused("another repository", ops.CodeScopePath, ops.OpIssueReopen, githubspec.Adapter, onRepo("example-org/other#1", nil), nil),
				refused("a run asks", ops.CodePolicyRefused, ops.OpIssueReopen, githubspec.Adapter, issueBuild(nil), asRun),
			},
			Text: conformance.NoServiceText,
			Plant: func(r *conformance.Rig, p conformance.Planted) {
				w := r.World.(*world)
				w.closedIssue = w.repo.AddIssue(ghtest.IssueOptions{Title: orDefault(strings.TrimSpace(p.Control+" "+p.Secret), "Error: old"), Labels: []string{ops.IssueLabel}, Closed: true})
			},
		},
	}
	conformance.Run(t, conformance.Connector{
		Declared: githubspec.Connector, Pins: pintable.Pins, NewRig: newRig(githubspec.Connector), Ops: cases,
	})
}

func mergeBuild(w *world) (string, map[string]any) {
	return w.pr(w.readPR), map[string]any{"base": "main", "head_sha": w.readSHA, "method": "squash"}
}

func issueBuild(params map[string]any) build {
	return func(w *world) (string, map[string]any) { return w.pr(w.issue), params }
}

// issueRepeat is the finding: GitHub's issue API has no idempotency key, and
// the adapters send the write again when Execute is called again with the
// same execution id. chapd never does that (an op that was executing when the
// process died becomes unconfirmed and is not run again), so the declaration
// records the behaviour instead of hiding it.
const issueRepeat = "GitHub has no idempotency key for creating an issue or a comment, and the adapter does not look for its earlier write: a second Execute with the same execution id posts again. chapd does not call Execute twice for one op (a crash leaves it unconfirmed)"

func TestConformanceCI(t *testing.T) {
	report := func(id string) build {
		return func(*world) (string, map[string]any) { return id, map[string]any{"run_id": id} }
	}
	conformance.Run(t, conformance.Connector{
		Declared: githubspec.CI,
		Pins:     pintable.Pins,
		NewRig:   newRig(githubspec.CI),
		Ops: map[string]conformance.Op{
			githubspec.NameCIReport: {
				Valid: []conformance.Sample{sample("a finished ci run", githubspec.NameCIReport, githubspec.CIAdapter, report(ciRun), nil)},
				Invalid: []conformance.Sample{
					refused("a run asks", ops.CodePolicyRefused, githubspec.NameCIReport, githubspec.CIAdapter, report(ciRun), asRun),
					refused("a run that has not ended", ops.CodePolicyRefused, githubspec.NameCIReport, githubspec.CIAdapter, report("r-aaaa"), nil),
					refused("a run of another profile", ops.CodePolicyRefused, githubspec.NameCIReport, githubspec.CIAdapter, report("r-bbbb"), nil),
					refused("a run chapd does not know", ops.CodePolicyRefused, githubspec.NameCIReport, githubspec.CIAdapter, report("r-9999"), nil),
					refused("a target that is not the run id", ops.CodeParamsInvalid, githubspec.NameCIReport, githubspec.CIAdapter, func(*world) (string, map[string]any) {
						return "r-9999", map[string]any{"run_id": ciRun}
					}, nil),
					refused("a project with no pr block", ops.CodePolicyRefused, githubspec.NameCIReport, githubspec.CIAdapter, report(ciRun), otherProject),
				},
				NotRepeatable: "a second report posts a second check run; pr.merge reads the latest check run of that name on the head, so the repeat replaces the first and the effect is the same (ADR-002, amendment 10)",
				Text:          conformance.NoServiceText,
				Plant:         func(*conformance.Rig, conformance.Planted) {}, // the result is chapd's own record of the run
			},
		},
	})
}

// mergePaths is a finding on the one gated operation. The risk_tier check
// names the paths that set the tier, and result.checks repeats it. The paths
// are the pull request author's text. A format character (a bidi override, a
// zero-width joiner) goes through both unchanged; a control character is
// replaced by "?" in the check line only. The result has no untrusted_text
// flag. The approval card shows the same paths as evidence, which it labels
// untrusted, but the check line and the stored result are not marked.
const mergePaths = "risk_tier detail and result.checks carry the paths of the pull request's changed files (the author's text) with format characters (U+202E, U+200D) unchanged and no untrusted_text flag"
