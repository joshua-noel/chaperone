package ops

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/gh"
)

// This file is `pr.open` (ticket L1-09): open a pull request from a branch of
// the project's repository into the project's base.
//
// A run may open a pull request from its own task branch into its own base,
// for its own repository, and nothing else. The orchestrator names a project;
// the repository and the base come from the project, never from the caller.
// The write token is minted after the last check, used for the one POST, and
// revoked at once. The POST is sent at most once: an answer that does not show
// whether the pull request exists leaves the op `unconfirmed`.

// OpPROpen is the op kind.
const OpPROpen = githubspec.NamePROpen

// PRProject is the repository and the pull request base of a project.
type PRProject struct {
	Repo string // "owner/name"
	Base string
}

// PROpenAPI is the part of *[gh.Client] that pr.open uses.
type PROpenAPI interface {
	CreatePull(ctx context.Context, tok *gh.Token, repo gh.Repo, in gh.NewPull) (*gh.Pull, error)
	RevokeToken(ctx context.Context, tok *gh.Token) error
}

var _ PROpenAPI = (*gh.Client)(nil)

// PROpenConfig builds a [PROpen].
type PROpenConfig struct {
	GitHub PROpenAPI
	Tokens TokenMinter
	// Project resolves the project an orchestrator names. ok is false for a
	// project that has no pull request settings (then pr.open is refused for
	// the orchestrator).
	Project func(project string) (PRProject, bool)
}

// PROpen is the pr.open [Adapter].
type PROpen struct {
	gh      PROpenAPI
	tokens  TokenMinter
	project func(string) (PRProject, bool)
}

var _ Adapter = (*PROpen)(nil)

// NewPROpen returns the adapter.
func NewPROpen(cfg PROpenConfig) (*PROpen, error) {
	if cfg.GitHub == nil || cfg.Tokens == nil {
		return nil, errors.New("ops: PROpen needs GitHub and Tokens")
	}
	return &PROpen{gh: cfg.GitHub, tokens: cfg.Tokens, project: cfg.Project}, nil
}

const (
	prTitleMax = githubspec.TitleMax
	prBodyMax  = githubspec.PRBodyMax
)

// keySet is the set of the names, for a "refuse a param the op does not
// declare" check.
func keySet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// prOpenParams is a validated params object.
type prOpenParams struct {
	repo  gh.Repo
	in    gh.NewPull
	draft bool
}

var prOpenKeys = keySet(githubspec.PROpen.ParamNames())

// parse validates the request and returns what to send. A failure is a
// *Refusal.
func (p *PROpen) parse(req *Request) (prOpenParams, error) {
	bad := func(why string) (prOpenParams, error) {
		return prOpenParams{}, &Refusal{Code: CodeParamsInvalid, Why: why}
	}
	if req.Target.Adapter != githubspec.Adapter {
		return bad("target.adapter must be github")
	}
	repo, err := gh.ParseRepo(req.Target.Ref)
	if err != nil {
		return bad("target.ref must be owner/name")
	}
	for k := range req.Params {
		if !prOpenKeys[k] {
			return bad("unknown param " + clamp(k, 40) + "; pr.open takes " + strings.Join(githubspec.PROpen.ParamNames(), ", "))
		}
	}
	str := func(k string, required bool, max int) (string, bool) {
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
	title, ok := str("title", true, prTitleMax)
	if !ok {
		return bad(fmt.Sprintf("title is required, 1-%d characters", prTitleMax))
	}
	body, ok := str("body", false, prBodyMax)
	if !ok {
		return bad(fmt.Sprintf("body must be text of at most %d bytes", prBodyMax))
	}
	head, ok := str("head", true, githubspec.BranchMax)
	if !ok {
		return bad("head is required: the branch to open the pull request from (params.head; `chap pr open` takes the current git branch or --branch)")
	}
	base, ok := str("base", true, githubspec.BranchMax)
	if !ok {
		return bad("base is required")
	}
	var draft bool
	if v, ok := req.Params["draft"]; ok {
		if draft, ok = v.(bool); !ok {
			return bad("draft must be true or false")
		}
	}
	if strings.Contains(head, ":") {
		return bad("head must be a branch of this repository, not owner:branch")
	}
	if head == base {
		return bad("head and base are the same branch")
	}

	c := req.Caller
	scope := func(why string) (prOpenParams, error) {
		return prOpenParams{}, &Refusal{Code: CodeScopeBranch, Why: why, Surface: "scope"}
	}
	switch c.Kind {
	case KindRun:
		if c.Repo == "" {
			return prOpenParams{}, &Refusal{Code: CodeScopePath, Surface: "scope",
				Why: "this op has no task scope stored with it, so it cannot be judged; open the pull request again"}
		}
		if !strings.EqualFold(c.Repo, repo.String()) {
			return prOpenParams{}, &Refusal{Code: CodeScopePath, Surface: "scope",
				Why: "this run's token covers " + clamp(c.Repo, 100) + " only, not " + clamp(repo.String(), 100)}
		}
		if head != c.Branch {
			return scope("this run may open a pull request from " + clamp(c.Branch, 120) + " only, not " + clamp(head, 120))
		}
		if base != c.Base {
			return scope("this run's pull request base is " + clamp(c.Base, 120) + ", not " + clamp(base, 120))
		}
	case KindOrchestrator:
		var pr PRProject
		ok := false
		if p.project != nil {
			pr, ok = p.project(req.Project)
		}
		if !ok {
			return bad("project " + clamp(req.Project, 60) + " has no pull request settings")
		}
		if !strings.EqualFold(pr.Repo, repo.String()) {
			return prOpenParams{}, &Refusal{Code: CodeScopePath, Surface: "scope",
				Why: "project " + clamp(req.Project, 60) + " is " + clamp(pr.Repo, 100) + ", not " + clamp(repo.String(), 100)}
		}
		if base != pr.Base {
			return scope("the pull request base of " + clamp(req.Project, 60) + " is " + clamp(pr.Base, 120) + ", not " + clamp(base, 120))
		}
	default:
		return bad("unknown caller kind")
	}
	return prOpenParams{repo: repo, draft: draft, in: gh.NewPull{Title: title, Body: body, Head: head, Base: base, Draft: draft}}, nil
}

// Check implements [Adapter]. It reads nothing from GitHub: the rules are about
// who may open what, and GitHub answers for the rest when the PR is created.
func (p *PROpen) Check(_ context.Context, req *Request) (CheckResult, error) {
	pp, err := p.parse(req)
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Checks: []Check{
		{Name: "repo", Passed: true, Detail: pp.repo.String()},
		{Name: "branches", Passed: true, Detail: pp.in.Head + " -> " + pp.in.Base},
	}}, nil
}

// Execute implements [Adapter].
func (p *PROpen) Execute(ctx context.Context, req *Request) (Outcome, error) {
	pp, err := p.parse(req)
	if err != nil {
		return Outcome{Failed: true, Result: map[string]any{"error": lineText(err.Error(), 300)}}, nil
	}
	tok, err := p.tokens.Mint(ctx, pp.repo, gh.PermsOpenPull())
	if err != nil {
		// Nothing was sent.
		return Outcome{Failed: true, Result: map[string]any{"error": "chapd could not get a GitHub token"}}, nil
	}
	pull, cerr := p.gh.CreatePull(ctx, tok, pp.repo, pp.in)
	_ = p.gh.RevokeToken(context.WithoutCancel(ctx), tok) // it expires on its own if this fails
	tok.Wipe()
	if cerr != nil {
		var api *gh.APIError
		switch {
		case errors.Is(cerr, gh.ErrInvalidArgument):
			return Outcome{Failed: true, Result: map[string]any{"error": lineText(cerr.Error(), 300)}}, nil
		case errors.As(cerr, &api) && api.Status >= 400 && api.Status < 500 && api.Status != http.StatusRequestTimeout:
			return Outcome{Failed: true, Result: map[string]any{
				"error": lineText(fmt.Sprintf("GitHub refused the pull request (%d): %s", api.Status, api.Detail()), 500),
			}}, nil
		}
		return Outcome{}, cerr // 5xx or transport: it may exist
	}
	return Outcome{
		ExternalRef: safeURL(pull.HTMLURL, 300),
		Result:      map[string]any{"number": float64(pull.Number), "url": safeURL(pull.HTMLURL, 300), "draft": pp.draft},
	}, nil
}
