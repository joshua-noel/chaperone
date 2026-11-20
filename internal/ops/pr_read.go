package ops

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/gh"
)

// This file is `pr.view`, `pr.diff`, `pr.checks` and `pr.files`: the read-only
// side of a pull request, for the orchestrator token (and, later, a the dashboard
// client; docs/adr/002 amendment 12).
//
// The rules, all enforced here and none from the caller:
//
//   - Only the orchestrator token asks. No run profile lists the ops, and the
//     adapter also refuses a run caller.
//   - The repository is the project's (`pr.repo` of its policy file), never the
//     caller's: a request for another repository is refused, and so is a
//     project with no `pr:` block.
//   - Every op only reads. The one GitHub token is minted after the last check,
//     holds the read permissions below and nothing else (no `contents`, no
//     write of any kind), is used for the reads of this one op and is revoked.
//     A dry run, an approval request and a release re-check never reach GitHub:
//     Check validates the request and nothing more.
//   - Nothing GitHub sends is trusted: a title, body, diff or check name is text
//     for a person or a program to read, never an instruction. Sizes are
//     capped (the diff, the body, the file page) and the result says when it
//     cut something.
//   - No secret is returned. The result passes chapd's redaction before it is
//     stored: one that holds anything shaped like a registered secret is stored
//     as {"blocked":"REDACTION_BLOCKED"}, whole.
//   - A read that fails is `failed`, never `unconfirmed`: nothing was written,
//     so the caller may ask again. chapd does not retry; the rate limits of the
//     policy pack (per caller and op, per minute and per hour) bound the load
//     on GitHub, and GitHub's own refusal for rate limiting is reported with its
//     retry time.

// The op kinds.
const (
	OpPRView   = githubspec.NamePRView
	OpPRDiff   = githubspec.NamePRDiff
	OpPRChecks = githubspec.NamePRChecks
	OpPRFiles  = githubspec.NamePRFiles
)

// PRReadOps lists the four read ops, in the order the manual shows them.
var PRReadOps = []string{OpPRView, OpPRDiff, OpPRChecks, OpPRFiles}

// Size limits of a result.
const (
	// PRDiffMax is the most diff bytes a pr.diff result carries. Past it the
	// diff is cut at a line end and the result says `truncated`.
	PRDiffMax = 256 << 10
	// PRBodyMax is the most body bytes a pr.view result carries.
	PRBodyMax = 64 << 10
	// PRFilesPerPage is the default page size of pr.files; PRFilesMaxPerPage is its largest.
	PRFilesPerPage    = githubspec.FilesPerPage
	PRFilesMaxPerPage = githubspec.FilesMaxPerPage
	// prFilesMaxItems is GitHub's own cap: it lists at most 3000 files of a pull request.
	prFilesMaxItems = 3000
	prLabelsMax     = 50
)

var headSHARE = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// prReadHint is the operator-facing reason a token with the read permissions
// could not be minted.
const prReadHint = "the chaperone-app GitHub App must hold the Pull requests permission (read) on the repository, and the Checks permission (read) for pr.checks, and the installation must have accepted them"

// PRReadAPI is the part of *[gh.Client] that the pr read ops use.
type PRReadAPI interface {
	GetPull(ctx context.Context, tok *gh.Token, repo gh.Repo, number int) (*gh.Pull, error)
	GetPullDiff(ctx context.Context, tok *gh.Token, repo gh.Repo, number int) ([]byte, error)
	ListPullFilesPage(ctx context.Context, tok *gh.Token, repo gh.Repo, number, page, perPage int) ([]gh.PullFile, error)
	ListCheckRuns(ctx context.Context, tok *gh.Token, repo gh.Repo, sha string, q gh.CheckRunQuery) ([]gh.CheckRun, error)
	RevokeToken(ctx context.Context, tok *gh.Token) error
}

var _ PRReadAPI = (*gh.Client)(nil)

// PRReadConfig builds a [PRReadAdapter].
type PRReadConfig struct {
	GitHub PRReadAPI
	Tokens TokenMinter
	// Project resolves the repository of the project the caller names (the
	// Base is not used). ok is false for a project with no `pr:` block.
	Project func(project string) (PRProject, bool)
}

// PRReadAdapter is the [Adapter] of one pr read op kind.
type PRReadAdapter struct {
	op      string
	gh      PRReadAPI
	tokens  TokenMinter
	project func(string) (PRProject, bool)
}

var _ Adapter = (*PRReadAdapter)(nil)

// NewPRReadAdapter returns the adapter of op (one of [PRReadOps]).
func NewPRReadAdapter(op string, cfg PRReadConfig) (*PRReadAdapter, error) {
	switch op {
	case OpPRView, OpPRDiff, OpPRChecks, OpPRFiles:
	default:
		return nil, fmt.Errorf("ops: %q is not a pr read op", op)
	}
	if cfg.GitHub == nil || cfg.Tokens == nil || cfg.Project == nil {
		return nil, errors.New("ops: pr read ops need GitHub, Tokens and Project")
	}
	return &PRReadAdapter{op: op, gh: cfg.GitHub, tokens: cfg.Tokens, project: cfg.Project}, nil
}

// prReadParams is a validated request.
type prReadParams struct {
	repo       gh.Repo
	number     int
	expectHead string // params.expected_head_sha; empty when the caller named none
	page       int    // pr.files
	perPage    int    // pr.files
}

// prReadKeys are the params each read op takes: the declared ones.
var prReadKeys = map[string][]string{
	OpPRView:   githubspec.PRView.ParamNames(),
	OpPRDiff:   githubspec.PRDiff.ParamNames(),
	OpPRChecks: githubspec.PRChecks.ParamNames(),
	OpPRFiles:  githubspec.PRFiles.ParamNames(),
}

func (a *PRReadAdapter) perms() map[string]string {
	if a.op == OpPRChecks {
		return gh.PermsReadPullChecks()
	}
	return gh.PermsReadPull()
}

// parse validates the request. A failure is a *Refusal.
func (a *PRReadAdapter) parse(req *Request) (prReadParams, error) {
	c := req.Caller
	switch {
	case c == nil:
		return prReadParams{}, &Refusal{Code: CodePolicyRefused, Surface: "scope", Why: a.op + " needs a caller"}
	case c.Kind == KindOrchestrator, c.Kind == KindKey:
	default:
		return prReadParams{}, &Refusal{Code: CodePolicyRefused, Surface: "scope",
			Why: a.op + " is for the orchestrator token and for keys only, never for a run"}
	}
	repo, n, err := targetPR(req, false)
	if err != nil {
		return prReadParams{}, err
	}
	// A key is bound to the repositories it was granted (ADR-008 unit binding): refused
	// here, before any call to GitHub, by the repository's name as chapd normalised it.
	if c.Kind == KindKey && !containsFold(c.KeyUnits, repo.String()) {
		return prReadParams{}, &Refusal{Code: CodeScopePath, Surface: "scope",
			Why: "this key covers " + clamp(strings.Join(c.KeyUnits, ", "), 100) + " only, not " + clamp(repo.String(), 100)}
	}
	p := prReadParams{repo: repo, number: n}
	if err := onlyParams(req.Params, prReadKeys[a.op]...); err != nil {
		why := err.Error()
		var ref *Refusal
		if errors.As(err, &ref) {
			why = ref.Why
		}
		return prReadParams{}, paramsInvalid("%s; %s takes %s", why, a.op, prReadParamList(a.op))
	}
	if v, ok := req.Params["expected_head_sha"]; ok {
		s, isStr := v.(string)
		if !isStr || !headSHARE.MatchString(s) {
			return prReadParams{}, paramsInvalid("expected_head_sha must be a full lowercase commit sha")
		}
		p.expectHead = s
	}
	if a.op == OpPRFiles {
		p.page, p.perPage = 1, PRFilesPerPage
		if v, ok, err := paramInt(req.Params, "page"); err != nil {
			return prReadParams{}, err
		} else if ok {
			p.page = v
		}
		if v, ok, err := paramInt(req.Params, "per_page"); err != nil {
			return prReadParams{}, err
		} else if ok {
			p.perPage = v
		}
		if p.perPage > PRFilesMaxPerPage {
			return prReadParams{}, paramsInvalid("per_page is at most %d", PRFilesMaxPerPage)
		}
		if (p.page-1)*p.perPage >= prFilesMaxItems {
			return prReadParams{}, paramsInvalid("GitHub lists at most %d files of a pull request; page %d of %d starts past that", prFilesMaxItems, p.page, p.perPage)
		}
	}
	pr, ok := a.project(req.Project)
	if !ok {
		return prReadParams{}, noPRBlock(req.Project, a.op)
	}
	if !strings.EqualFold(pr.Repo, repo.String()) {
		return prReadParams{}, &Refusal{Code: CodeScopePath, Surface: "scope",
			Why: "project " + clip(req.Project, 60) + " is " + clip(pr.Repo, 100) + ", not " + clip(repo.String(), 100)}
	}
	return p, nil
}

func prReadParamList(op string) string {
	if len(prReadKeys[op]) == 0 {
		return "no params"
	}
	return strings.Join(prReadKeys[op], ", ")
}

// Check implements [Adapter]. It reads nothing from GitHub.
func (a *PRReadAdapter) Check(_ context.Context, req *Request) (CheckResult, error) {
	p, err := a.parse(req)
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Checks: []Check{
		{Name: "repo", Passed: true, Detail: p.repo.String() + "#" + strconv.Itoa(p.number)},
		{Name: "read_only", Passed: true, Detail: a.op + " only reads"},
	}}, nil
}

// mint gets a read token for the one op, and says in plain words when GitHub
// refuses the permission (the App lacks it).
func (a *PRReadAdapter) mint(ctx context.Context, repo gh.Repo) (*gh.Token, error) {
	tok, err := a.tokens.Mint(ctx, repo, a.perms())
	var api *gh.APIError
	if err != nil && errors.As(err, &api) && (api.Status == http.StatusUnprocessableEntity || api.Status == http.StatusForbidden) {
		return nil, &Refusal{Code: CodePolicyRefused, Surface: "scope",
			Why: clip(fmt.Sprintf("GitHub would not give chapd a read token for %s (%d): %s", a.op, api.Status, prReadHint), 300)}
	}
	return tok, err
}

func (a *PRReadAdapter) release(ctx context.Context, tok *gh.Token) {
	_ = a.gh.RevokeToken(context.WithoutCancel(ctx), tok) // it expires on its own if this fails
	tok.Wipe()
}

// Execute implements [Adapter]. Every failure is a `failed` outcome: nothing
// was written, so the op is never `unconfirmed`.
func (a *PRReadAdapter) Execute(ctx context.Context, req *Request) (Outcome, error) {
	p, err := a.parse(req)
	if err != nil {
		return failedOutcome(err.Error()), nil
	}
	tok, err := a.mint(ctx, p.repo)
	if err != nil {
		var ref *Refusal
		if errors.As(err, &ref) {
			return failedOutcome(untrusted.Line(ref.Why)), nil
		}
		return failedOutcome("chapd could not get a GitHub token; nothing was read, ask again"), nil
	}
	defer a.release(ctx, tok)

	pull, err := a.gh.GetPull(ctx, tok, p.repo, p.number)
	if err != nil {
		return a.fromGitHub(err, p), nil
	}
	if p.expectHead != "" && pull.Head.SHA != p.expectHead {
		return Outcome{Failed: true, Result: map[string]any{
			"error":    fmt.Sprintf("the head of #%d is not %s any more: ask again without expected_head_sha, or with the new head", p.number, p.expectHead[:12]),
			"head_sha": untrusted.Line(pull.Head.SHA),
		}}, nil
	}
	var res map[string]any
	var hidden hiddenText
	switch a.op {
	case OpPRView:
		res = viewResult(pull, p.repo)
		hidden.see("title", "titles", pull.Title, false)
		hidden.see("body", "bodies", pull.Body, true)
		hidden.see("branch name", "branch names", pull.Head.Ref, false)
		hidden.see("branch name", "branch names", pull.Base.Ref, false)
		if pull.User != nil {
			hidden.see("author name", "author names", pull.User.Login, false)
		}
		for _, l := range pull.Labels {
			hidden.see("label", "labels", l.Name, false)
		}
	case OpPRDiff:
		raw, err := a.gh.GetPullDiff(ctx, tok, p.repo, p.number)
		if err != nil {
			return a.fromGitHub(err, p), nil
		}
		res = diffResult(pull, raw)
		hidden.see("diff", "diffs", strings.ToValidUTF8(string(raw), "\uFFFD"), true)
	case OpPRChecks:
		runs, err := a.gh.ListCheckRuns(ctx, tok, p.repo, pull.Head.SHA, gh.CheckRunQuery{})
		if err != nil {
			return a.fromGitHub(err, p), nil
		}
		res = checksResult(pull, runs)
		for _, r := range runs {
			hidden.see("check name", "check names", r.Name, false)
		}
	default: // OpPRFiles
		files, err := a.gh.ListPullFilesPage(ctx, tok, p.repo, p.number, p.page, p.perPage)
		if err != nil {
			return a.fromGitHub(err, p), nil
		}
		res = filesResult(pull, files, p)
		for _, f := range files {
			hidden.see("file path", "file paths", f.Filename, false)
			if f.PreviousFilename != "" {
				hidden.see("file path", "file paths", f.PreviousFilename, false)
			}
		}
	}
	res["untrusted_text"] = true
	if w := hidden.text(); w != "" {
		res["hidden_characters"] = w
	}
	return Outcome{ExternalRef: safeURL(pull.HTMLURL, 300), Result: res}, nil
}

// fromGitHub turns a GitHub error into a failed outcome with words a person
// can act on.
func (a *PRReadAdapter) fromGitHub(err error, p prReadParams) Outcome {
	var api *gh.APIError
	switch {
	case errors.Is(err, gh.ErrNotFound):
		return failedOutcome("pull request #" + strconv.Itoa(p.number) + " does not exist in " + p.repo.String())
	case errors.Is(err, gh.ErrRateLimited):
		msg := "GitHub is rate limiting chapd"
		out := Outcome{Failed: true, Result: map[string]any{}}
		if errors.As(err, &api) && api.RateLimit != nil {
			if d := api.RateLimit.RetryAfter; d > 0 {
				out.Result["retry_after_seconds"] = int(d.Round(time.Second) / time.Second)
				msg += "; retry in " + strconv.Itoa(int(d.Round(time.Second)/time.Second)) + " s"
			} else if !api.RateLimit.Reset.IsZero() {
				msg += "; it resets at " + api.RateLimit.Reset.UTC().Format(time.RFC3339)
			}
		}
		out.Result["error"] = clip(msg, 300)
		return out
	case errors.Is(err, gh.ErrListTruncated):
		return failedOutcome(a.op + " cannot list this completely: " + untrusted.Line(err.Error()))
	case errors.As(err, &api):
		return failedOutcome(fmt.Sprintf("GitHub refused %s (%d): %s", a.op, api.Status, untrusted.Line(api.Detail())))
	}
	return failedOutcome("chapd could not reach GitHub for " + a.op + "; nothing was changed, ask again")
}

// ---- results ---------------------------------------------------------------

func viewResult(p *gh.Pull, repo gh.Repo) map[string]any {
	body, bodyCut := cutText(untrusted.Strip(p.Body), PRBodyMax)
	labels := make([]string, 0, len(p.Labels))
	for _, l := range p.Labels {
		if len(labels) == prLabelsMax {
			break
		}
		labels = append(labels, clip(untrusted.Line(l.Name), 100))
	}
	head := map[string]any{"ref": untrusted.Line(p.Head.Ref), "sha": untrusted.Line(p.Head.SHA), "repo": "", "fork": true}
	if p.Head.Repo != nil {
		head["repo"] = untrusted.Line(p.Head.Repo.FullName)
		head["fork"] = !strings.EqualFold(p.Head.Repo.FullName, repo.String())
	}
	author := ""
	if p.User != nil {
		author = untrusted.Line(p.User.Login)
	}
	var mergeable any // null while GitHub computes it
	if p.Mergeable != nil {
		mergeable = *p.Mergeable
	}
	res := map[string]any{
		"number": p.Number, "title": untrusted.Line(p.Title), "body": body, "body_truncated": bodyCut,
		"state": untrusted.Line(p.State), "draft": p.Draft, "merged": p.Merged, "author": author, "labels": labels,
		"head": head, "base": map[string]any{"ref": untrusted.Line(p.Base.Ref), "sha": untrusted.Line(p.Base.SHA)},
		"mergeable": mergeable, "mergeable_state": untrusted.Line(p.MergeableState),
		"url": safeURL(p.HTMLURL, 300), "created_at": untrusted.Line(p.CreatedAt), "updated_at": untrusted.Line(p.UpdatedAt),
		"commits": p.Commits, "additions": p.Additions, "deletions": p.Deletions, "changed_files": p.ChangedFiles,
	}
	if p.ClosedAt != "" {
		res["closed_at"] = untrusted.Line(p.ClosedAt)
	}
	if p.MergedAt != "" {
		res["merged_at"] = untrusted.Line(p.MergedAt)
	}
	if p.MergeCommitSHA != "" {
		res["merge_commit_sha"] = untrusted.Line(p.MergeCommitSHA)
	}
	return res
}

// cutText returns s cut to at most max bytes on a rune boundary, and whether it cut.
func cutText(s string, max int) (string, bool) {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= max {
		return s, false
	}
	return clamp(s, max), true
}

func diffResult(p *gh.Pull, raw []byte) map[string]any {
	text := untrusted.Strip(strings.ToValidUTF8(string(raw), "\uFFFD"))
	truncated := len(text) > PRDiffMax
	if truncated {
		text = clamp(text, PRDiffMax)
		if i := strings.LastIndexByte(text, '\n'); i >= 0 {
			text = text[:i+1] // end on a whole line
		}
	}
	return map[string]any{
		"number": p.Number, "head_sha": untrusted.Line(p.Head.SHA), "base_ref": untrusted.Line(p.Base.Ref),
		"diff": text, "size": len(raw), "returned": len(text), "truncated": truncated, "cap": PRDiffMax,
	}
}

func filesResult(p *gh.Pull, files []gh.PullFile, q prReadParams) map[string]any {
	list := make([]any, 0, len(files))
	for _, f := range files {
		m := map[string]any{"filename": untrusted.Line(f.Filename), "status": untrusted.Line(f.Status), "additions": f.Additions, "deletions": f.Deletions, "has_patch": f.Patch != ""}
		if f.PreviousFilename != "" {
			m["previous_filename"] = untrusted.Line(f.PreviousFilename)
		}
		list = append(list, m)
	}
	total := min(p.ChangedFiles, prFilesMaxItems)
	return map[string]any{
		"number": p.Number, "head_sha": untrusted.Line(p.Head.SHA), "page": q.page, "per_page": q.perPage,
		"total": p.ChangedFiles, "count": len(list), "has_more": q.page*q.perPage < total, "files": list,
	}
}

// Check run conclusions that count as passed or failed. A run that is not
// completed is pending; any other conclusion (a missing one included) is
// reported in its own count so nothing is hidden inside "passed".
var (
	conclusionPassed = map[string]bool{"success": true, "neutral": true, "skipped": true}
	conclusionFailed = map[string]bool{"failure": true, "timed_out": true, "cancelled": true, "action_required": true, "startup_failure": true, "stale": true}
)

func checksResult(p *gh.Pull, runs []gh.CheckRun) map[string]any {
	sorted := append([]gh.CheckRun(nil), runs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].ID < sorted[j].ID
	})
	var passed, failed, pending, other int
	list := make([]any, 0, len(sorted))
	for _, r := range sorted {
		switch {
		case r.Status != "completed":
			pending++
		case conclusionPassed[r.Conclusion]:
			passed++
		case conclusionFailed[r.Conclusion]:
			failed++
		default:
			other++
		}
		m := map[string]any{"id": r.ID, "name": clip(untrusted.Line(r.Name), 100), "status": untrusted.Line(r.Status), "conclusion": untrusted.Line(r.Conclusion), "app_id": r.AppID, "url": safeURL(r.HTMLURL, 300)}
		if !r.StartedAt.IsZero() {
			m["started_at"] = r.StartedAt.UTC().Format(time.RFC3339)
		}
		list = append(list, m)
	}
	return map[string]any{
		"number": p.Number, "head_sha": untrusted.Line(p.Head.SHA),
		"summary": map[string]any{"total": len(sorted), "passed": passed, "failed": failed, "pending": pending, "other": other},
		"runs":    list,
	}
}
