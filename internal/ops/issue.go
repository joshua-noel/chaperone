package ops

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/gh"
)

// This file is `issue.open`, `issue.comment` and `issue.reopen` (a decision of the operator:
// the error watcher files its issues through Chaperone, not with a GitHub credential of its own).
//
// The rules, all enforced here and none from the caller:
//
//   - Only the orchestrator token asks (the error watcher holds one scoped to
//     these three ops and one project). No run profile lists the ops, and the
//     adapter refuses a run as well.
//   - The repository is the project's (`pr.repo` of its policy file), never the
//     caller's. A request for another repository is refused.
//   - Every issue the watcher touches carries the label [IssueLabel]. issue.open
//     must request it; issue.comment and issue.reopen read the target issue
//     first and refuse one that lacks it, and refuse a pull request (GitHub's
//     issues API answers for those too). Execute reads the issue again with
//     the write token before it writes, so a label removed between Check and
//     Execute stops the write.
//   - The token is minted after the last check with `issues` permission only
//     (no contents, no pull_requests), used for the one write, and revoked.
//   - Title, body and label counts are capped; unknown params are refused.
//
// A write is sent at most once. An answer that does not show whether the write
// happened leaves the op `unconfirmed`, as for pr.open.

// The op kinds.
const (
	OpIssueOpen    = "issue.open"
	OpIssueComment = "issue.comment"
	OpIssueReopen  = "issue.reopen"
)

// IssueLabel is the label every issue of the error watcher carries. It is the
// whole policy of these ops: no label, no write.
const IssueLabel = "source:error-watcher"

const (
	issueTitleMax  = 200
	issueBodyMax   = 10000
	issueLabelsMax = 10
	issueLabelMax  = 50
)

// IssueAPI is the part of *[gh.Client] that the issue ops use.
type IssueAPI interface {
	GetIssue(ctx context.Context, tok *gh.Token, repo gh.Repo, number int) (*gh.Issue, error)
	CreateIssue(ctx context.Context, tok *gh.Token, repo gh.Repo, in gh.NewIssue) (*gh.Issue, error)
	CreateIssueComment(ctx context.Context, tok *gh.Token, repo gh.Repo, number int, text string) (*gh.IssueComment, error)
	ReopenIssue(ctx context.Context, tok *gh.Token, repo gh.Repo, number int) (*gh.Issue, error)
	RevokeToken(ctx context.Context, tok *gh.Token) error
}

var _ IssueAPI = (*gh.Client)(nil)

// IssueConfig builds an [IssueAdapter].
type IssueConfig struct {
	GitHub IssueAPI
	Tokens TokenMinter
	// Project resolves the repository of the project the orchestrator names
	// (the Base is not used). ok is false for a project with no `pr:` block.
	Project func(project string) (PRProject, bool)
}

// IssueAdapter is the [Adapter] of one issue op kind.
type IssueAdapter struct {
	op      string
	gh      IssueAPI
	tokens  TokenMinter
	project func(string) (PRProject, bool)
}

var _ Adapter = (*IssueAdapter)(nil)

// NewIssueAdapter returns the adapter of op (OpIssueOpen, OpIssueComment or
// OpIssueReopen).
func NewIssueAdapter(op string, cfg IssueConfig) (*IssueAdapter, error) {
	switch op {
	case OpIssueOpen, OpIssueComment, OpIssueReopen:
	default:
		return nil, fmt.Errorf("ops: %q is not an issue op", op)
	}
	if cfg.GitHub == nil || cfg.Tokens == nil || cfg.Project == nil {
		return nil, errors.New("ops: issue ops need GitHub, Tokens and Project")
	}
	return &IssueAdapter{op: op, gh: cfg.GitHub, tokens: cfg.Tokens, project: cfg.Project}, nil
}

// issueParams is a validated request.
type issueParams struct {
	repo   gh.Repo
	number int // 0 for issue.open
	title  string
	body   string
	labels []string
}

func (a *IssueAdapter) hasNumber() bool { return a.op != OpIssueOpen }

var issueKeys = map[string]map[string]bool{
	OpIssueOpen:    {"title": true, "body": true, "labels": true},
	OpIssueComment: {"body": true},
	OpIssueReopen:  {},
}

// parse validates the request. A failure is a *Refusal.
func (a *IssueAdapter) parse(req *Request) (issueParams, error) {
	bad := func(why string) (issueParams, error) {
		return issueParams{}, &Refusal{Code: CodeParamsInvalid, Why: why}
	}
	if req.Target.Adapter != "github" {
		return bad("target.adapter must be github")
	}
	ref, num, hasNum := strings.Cut(req.Target.Ref, "#")
	repo, err := gh.ParseRepo(ref)
	if err != nil {
		return bad("target.ref must be owner/name, with #<issue number> for comment and reopen")
	}
	var p issueParams
	p.repo = repo
	switch {
	case a.hasNumber() && !hasNum:
		return bad("target.ref must be owner/name#<issue number>")
	case !a.hasNumber() && hasNum:
		return bad("target.ref must be owner/name for issue.open")
	case a.hasNumber():
		n, err := strconv.Atoi(num)
		if err != nil || n < 1 || strconv.Itoa(n) != num {
			return bad("the issue number must be a positive integer")
		}
		p.number = n
	}
	for k := range req.Params {
		if !issueKeys[a.op][k] {
			return bad("unknown param " + clamp(k, 40) + "; " + a.op + " takes " + issueParamList(a.op))
		}
	}
	text := func(k string, required bool, max int) (string, bool) {
		v, ok := req.Params[k]
		if !ok {
			return "", !required
		}
		s, ok := v.(string)
		if !ok || !utf8.ValidString(s) || len(s) > max || required && strings.TrimSpace(s) == "" {
			return "", false
		}
		return s, true
	}
	switch a.op {
	case OpIssueOpen:
		var ok bool
		if p.title, ok = text("title", true, issueTitleMax); !ok || strings.ContainsAny(p.title, "\r\n") {
			return bad(fmt.Sprintf("title is required, one line of 1-%d characters", issueTitleMax))
		}
		if p.body, ok = text("body", false, issueBodyMax); !ok {
			return bad(fmt.Sprintf("body must be text of at most %d bytes", issueBodyMax))
		}
		labels, err := issueLabels(req.Params["labels"])
		if err != nil {
			return bad(err.Error())
		}
		p.labels = labels
	case OpIssueComment:
		var ok bool
		if p.body, ok = text("body", true, issueBodyMax); !ok {
			return bad(fmt.Sprintf("body is required, 1-%d bytes of text", issueBodyMax))
		}
	}

	c := req.Caller
	if c == nil || c.Kind != KindOrchestrator {
		return issueParams{}, &Refusal{Code: CodePolicyRefused, Surface: "scope",
			Why: a.op + " is for the orchestrator token only (the error watcher's), never for a run"}
	}
	pr, ok := a.project(req.Project)
	if !ok {
		return bad("project " + clamp(req.Project, 60) + " has no repository settings")
	}
	if !strings.EqualFold(pr.Repo, repo.String()) {
		return issueParams{}, &Refusal{Code: CodeScopePath, Surface: "scope",
			Why: "project " + clamp(req.Project, 60) + " is " + clamp(pr.Repo, 100) + ", not " + clamp(repo.String(), 100)}
	}
	if a.op == OpIssueOpen && !hasLabel(p.labels, IssueLabel) {
		return issueParams{}, &Refusal{Code: CodePolicyRefused,
			Why: "issue.open needs the label " + IssueLabel + " in params.labels: Chaperone files issues for the error watcher only"}
	}
	return p, nil
}

func issueParamList(op string) string {
	switch op {
	case OpIssueOpen:
		return "title, body, labels"
	case OpIssueComment:
		return "body"
	}
	return "no params"
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// issueLabels reads params.labels: a list of up to issueLabelsMax short names.
func issueLabels(v any) ([]string, error) {
	errBad := fmt.Errorf("labels must be a list of 1-%d names of at most %d characters", issueLabelsMax, issueLabelMax)
	var out []string
	switch x := v.(type) {
	case nil:
		return nil, errBad
	case []string:
		out = append(out, x...)
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, errBad
			}
			out = append(out, s)
		}
	default:
		return nil, errBad
	}
	if len(out) == 0 || len(out) > issueLabelsMax {
		return nil, errBad
	}
	for _, l := range out {
		if strings.TrimSpace(l) == "" || len(l) > issueLabelMax || !utf8.ValidString(l) || strings.ContainsAny(l, ",\r\n") {
			return nil, errBad
		}
	}
	return out, nil
}

// permHint is the operator-facing reason a token with the issues permission
// could not be minted.
const permHint = "the chaperone-app GitHub App must hold the Issues permission (read and write) on the repository, and the installation must have accepted it"

// mint gets a token for the one call, and says in plain words when GitHub
// refuses the permission (the App lacks it). A refusal of that kind is
// permanent until the operator changes the App; anything else may pass.
func (a *IssueAdapter) mint(ctx context.Context, repo gh.Repo, perms map[string]string) (*gh.Token, error) {
	tok, err := a.tokens.Mint(ctx, repo, perms)
	var api *gh.APIError
	if err != nil && errors.As(err, &api) && (api.Status == http.StatusUnprocessableEntity || api.Status == http.StatusForbidden) {
		return nil, &Refusal{Code: CodePolicyRefused, Surface: "scope",
			Why: clamp(fmt.Sprintf("GitHub would not give chapd a token with the issues permission (%d): %s", api.Status, permHint), 300)}
	}
	return tok, err
}

func (a *IssueAdapter) release(ctx context.Context, tok *gh.Token) {
	_ = a.gh.RevokeToken(context.WithoutCancel(ctx), tok) // it expires on its own if this fails
	tok.Wipe()
}

// target reads the issue and applies the label rule. A refusal is a *Refusal;
// an error that is not one means GitHub could not be asked.
func (a *IssueAdapter) target(ctx context.Context, tok *gh.Token, p issueParams) (*gh.Issue, error) {
	is, err := a.gh.GetIssue(ctx, tok, p.repo, p.number)
	if err != nil {
		if errors.Is(err, gh.ErrNotFound) {
			return nil, &Refusal{Code: CodeParamsInvalid, Why: "issue #" + strconv.Itoa(p.number) + " does not exist in " + p.repo.String()}
		}
		return nil, err
	}
	if is.PullRequest != nil {
		return nil, &Refusal{Code: CodePolicyRefused, Why: "#" + strconv.Itoa(p.number) + " is a pull request, not an issue"}
	}
	if !is.HasLabel(IssueLabel) {
		return nil, &Refusal{Code: CodePolicyRefused, Why: "issue #" + strconv.Itoa(p.number) + " does not carry the label " + IssueLabel + ": Chaperone writes to the error watcher's issues only"}
	}
	return is, nil
}

// Check implements [Adapter]. issue.open reads nothing from GitHub; the other
// two read the target issue for its labels.
func (a *IssueAdapter) Check(ctx context.Context, req *Request) (CheckResult, error) {
	p, err := a.parse(req)
	if err != nil {
		return CheckResult{}, err
	}
	checks := []Check{
		{Name: "repo", Passed: true, Detail: p.repo.String()},
		{Name: "label", Passed: true, Detail: IssueLabel},
	}
	if !a.hasNumber() {
		return CheckResult{Checks: checks}, nil
	}
	tok, err := a.mint(ctx, p.repo, gh.PermsIssueRead())
	if err != nil {
		return CheckResult{}, err
	}
	is, err := a.target(ctx, tok, p)
	a.release(ctx, tok)
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Checks: append(checks, Check{Name: "issue", Passed: true, Detail: "#" + strconv.Itoa(p.number) + " is " + is.State})}, nil
}

// Execute implements [Adapter].
func (a *IssueAdapter) Execute(ctx context.Context, req *Request) (Outcome, error) {
	p, err := a.parse(req)
	if err != nil {
		return failedOutcome(err.Error()), nil
	}
	tok, err := a.mint(ctx, p.repo, gh.PermsIssueWrite())
	if err != nil {
		var ref *Refusal
		if errors.As(err, &ref) {
			return failedOutcome(ref.Why), nil
		}
		return failedOutcome("chapd could not get a GitHub token"), nil // nothing was sent
	}
	defer a.release(ctx, tok)

	var cur *gh.Issue
	if a.hasNumber() {
		// The label may have gone since Check: read again with the token that writes.
		if cur, err = a.target(ctx, tok, p); err != nil {
			var ref *Refusal
			if errors.As(err, &ref) {
				return failedOutcome(ref.Why), nil
			}
			return failedOutcome("chapd could not read the issue before writing, so nothing was written: " + err.Error()), nil
		}
	}
	switch a.op {
	case OpIssueOpen:
		is, err := a.gh.CreateIssue(ctx, tok, p.repo, gh.NewIssue{Title: p.title, Body: p.body, Labels: p.labels})
		if err != nil {
			return a.fromGitHub(err)
		}
		return Outcome{ExternalRef: clamp(is.HTMLURL, 300),
			Result: map[string]any{"number": float64(is.Number), "url": clamp(is.HTMLURL, 300)}}, nil
	case OpIssueComment:
		cm, err := a.gh.CreateIssueComment(ctx, tok, p.repo, p.number, p.body)
		if err != nil {
			return a.fromGitHub(err)
		}
		return Outcome{ExternalRef: clamp(cm.HTMLURL, 300),
			Result: map[string]any{"number": float64(p.number), "comment_id": float64(cm.ID), "url": clamp(cm.HTMLURL, 300)}}, nil
	default: // OpIssueReopen
		if cur.State == "open" {
			return Outcome{ExternalRef: clamp(cur.HTMLURL, 300),
				Result: map[string]any{"number": float64(p.number), "url": clamp(cur.HTMLURL, 300), "reopened": false}}, nil
		}
		is, err := a.gh.ReopenIssue(ctx, tok, p.repo, p.number)
		if err != nil {
			return a.fromGitHub(err)
		}
		return Outcome{ExternalRef: clamp(is.HTMLURL, 300),
			Result: map[string]any{"number": float64(p.number), "url": clamp(is.HTMLURL, 300), "reopened": true}}, nil
	}
}

// fromGitHub turns a GitHub error into an outcome: a refusal GitHub made is
// `failed`; a 5xx or transport error may have written, so it is returned and
// the op becomes `unconfirmed`.
func (a *IssueAdapter) fromGitHub(err error) (Outcome, error) {
	var api *gh.APIError
	switch {
	case errors.Is(err, gh.ErrInvalidArgument):
		return failedOutcome(err.Error()), nil
	case errors.As(err, &api) && api.Status >= 400 && api.Status < 500 && api.Status != http.StatusRequestTimeout:
		return failedOutcome(fmt.Sprintf("GitHub refused %s (%d): %s", a.op, api.Status, api.Detail())), nil
	}
	return Outcome{}, err
}
