package ops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/joshua-noel/chaperone/internal/spec"
	"github.com/joshua-noel/chaperone/internal/store"
)

// This file is the op side of the git proxy (ticket L1-09, ADR-002 "Push
// path"). The proxy (internal/gitproxy) reads the wire protocol; every decision
// that is policy, and every ledger write, is made here, so a push is an op like
// any other: op.request when it is asked for, op.result when GitHub answered,
// and a structured denial when it is refused.
//
// A fetch is not an op. It is only held to the run's repository (SCOPE_PATH).

// OpBranchPush is the op kind a push is recorded as.
const OpBranchPush = "branch.push"

// GitHandler serves /git/ (the smart-HTTP reverse proxy). ServeGit returns an
// error before it has written anything when the request is refused; the
// server turns it into the denial text git prints. After it has written, it
// returns nil.
type GitHandler interface {
	ServeGit(w http.ResponseWriter, r *http.Request, c *Caller) error
}

// GitUpdate is one command of a receive-pack update-request: old-id SP new-id
// SP refname.
type GitUpdate struct {
	Old, New, Ref string
}

// IsDelete reports whether the command deletes the ref (the new id is all zeros).
func (u GitUpdate) IsDelete() bool { return u.New != "" && strings.Trim(u.New, "0") == "" }

// GitPush is what the proxy read from the head of a push request, before any
// pack byte went upstream.
type GitPush struct {
	// Repo is "owner/name" from the URL.
	Repo string
	// Updates holds the first commands of the request; the proxy stops reading
	// after the second, so more than one entry already means "refused".
	Updates []GitUpdate
	// More is true when the request had more commands than Updates holds.
	More bool
	// PushCert is true when the request carries a signed push certificate.
	PushCert bool
	// Malformed is a short reason when the update-request could not be read
	// (empty when it was).
	Malformed string
}

// GitPushOp is one admitted push: the op row is `executing` and waits for
// [GitPushOp.Finish].
type GitPushOp struct {
	s   *Service
	rec *record
}

// ID is the op's request id.
func (g *GitPushOp) ID() string { return g.rec.ID }

// GitPushResult is what became of the push.
type GitPushResult struct {
	// Outcome is "succeeded", "failed" or "unconfirmed" (the push was sent and
	// the report did not show whether it landed).
	Outcome string
	// Detail is one line of why, for a failure; never a credential.
	Detail string
}

func (s *Service) gitScope(ctx context.Context, c *Caller, repo, verb string) error {
	why := "this run's token covers " + clamp(c.Repo, 100) + " only, not " + clamp(repo, 100)
	switch c.Kind {
	case KindRun:
		if c.Repo != "" && strings.EqualFold(c.Repo, repo) {
			return nil
		}
	case KindKey:
		why = "a key cannot use the git proxy (a key holds no pull-request write op)"
	case KindOrchestrator:
		// The auth middleware never lets the orchestrator reach the proxy; refused here as well.
	default:
		why = "this caller's kind is not handled by the git proxy"
	}
	return s.deny(ctx, c, denial{Project: gitProject(c), Surface: "scope", Verb: verb, Target: repo, Code: CodeScopePath, Why: why})
}

func gitProject(c *Caller) string {
	if c.Project != "" {
		return c.Project
	}
	return "unknown"
}

// GitRead admits a fetch (discovery or upload-pack) of repo: it is served only
// for the repository of the run's token.
func (s *Service) GitRead(ctx context.Context, c *Caller, repo string) error {
	return s.gitScope(ctx, c, repo, "git.fetch")
}

// GitPushDiscovery is the early refusal at `info/refs?service=git-receive-pack`,
// so `git push` fails before it builds a pack: right repository, branch.push in
// the token, branch.push enabled by policy. It records a denial but no op row.
func (s *Service) GitPushDiscovery(ctx context.Context, c *Caller, repo string) error {
	if err := s.gitScope(ctx, c, repo, OpBranchPush); err != nil {
		return err
	}
	project := gitProject(c)
	eff := s.policy.For(project)
	d := denial{Project: project, Verb: OpBranchPush, Target: repo}
	switch why := s.notInToken(c, eff, project, OpBranchPush); {
	case why != "":
		d.Code, d.Why = CodeOpNotInToken, why
	case eff.Invalid != nil:
		d.Code, d.Why = CodePolicyRefused, eff.Invalid.Error()
	case !eff.Enabled(OpBranchPush):
		d.Code, d.Why = CodeOpDisabled, OpBranchPush+" is disabled by policy for "+project
	default:
		return nil
	}
	return s.deny(ctx, c, d)
}

// BeginGitPush decides one push. A refusal is returned as a *DeniedError after
// its op row (requested, then denied) and denial are ledgered. An admitted push
// gets its op row, op.request and the allowed and executing transitions in one
// transaction; the caller then sends the pack and calls [GitPushOp.Finish].
//
// Refused: a repository other than the token's (SCOPE_PATH); branch.push not in
// the token or not enabled; the rate limit; a push certificate, more than one
// ref, a delete, or any ref but refs/heads/<task_scope.branch> (SCOPE_BRANCH,
// which is also what a tag or the base branch gets); an unreadable request
// (OP_PARAMS_INVALID).
func (s *Service) BeginGitPush(ctx context.Context, c *Caller, p GitPush) (*GitPushOp, error) {
	project := gitProject(c)
	if err := s.gitScope(ctx, c, p.Repo, OpBranchPush); err != nil {
		return nil, err
	}
	entry, ok := s.policy.Catalog().Lookup(OpBranchPush)
	if !ok {
		return nil, s.unavailable("the policy catalog has no "+OpBranchPush, nil)
	}
	eff := s.policy.For(project)
	sub, err := s.gitSubmission(c, p, project)
	if err != nil {
		return nil, s.unavailable("could not build the push request", err)
	}
	refuse := func(surface, code, why string) (*GitPushOp, error) {
		return nil, s.denyWithOp(ctx, c, sub, project, entry, eff, denial{
			Project: project, Surface: surface, Verb: OpBranchPush, Target: p.Repo, Code: code, Why: why,
		})
	}

	if why := s.notInToken(c, eff, project, OpBranchPush); why != "" {
		return refuse("op", CodeOpNotInToken, why)
	}
	if eff.Invalid != nil {
		return refuse("op", CodePolicyRefused, eff.Invalid.Error())
	}
	if !eff.Enabled(OpBranchPush) {
		return refuse("op", CodeOpDisabled, OpBranchPush+" is disabled by policy for "+project)
	}
	if retry, err := s.rateLimited(ctx, c, OpBranchPush, eff); err != nil {
		return nil, s.unavailable("could not check the rate limit", err)
	} else if retry > 0 {
		d := denial{Project: project, Verb: OpBranchPush, Target: p.Repo, Code: CodePolicyRefused, Status: http.StatusTooManyRequests, RetryAfter: retry,
			Why: fmt.Sprintf("rate limit: %s allows %d calls per minute per caller; retry in %d s", OpBranchPush, eff.Rate(OpBranchPush), retry)}
		return nil, s.denyWithOp(ctx, c, sub, project, entry, eff, d)
	}

	if why := gitPushRefusal(c, p); why != "" {
		if p.Malformed != "" || len(p.Updates) == 0 && !p.PushCert {
			return refuse("op", CodeParamsInvalid, why)
		}
		return refuse("scope", CodeScopeBranch, why)
	}

	rec := s.newRecord(c, sub, project, entry, eff)
	checks, _ := json.Marshal([]Check{
		{Name: "repo", Passed: true, Detail: p.Repo},
		{Name: "ref", Passed: true, Detail: p.Updates[0].Ref},
	})
	execID := s.newID("x-")
	err = s.db.Immediate(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := insertRecord(ctx, tx, rec); err != nil {
			return err
		}
		if err := s.led.AppendTx(ctx, tx, rec.requestEvent()); err != nil {
			return err
		}
		if err := (transition{From: StateRequested, To: StateAllowed, Now: s.now(), ChecksJSON: string(checks)}).apply(ctx, tx, rec.ID); err != nil {
			return err
		}
		return transition{From: StateAllowed, To: StateExecuting, Now: s.now(), ExecutionID: execID}.apply(ctx, tx, rec.ID)
	})
	if err != nil {
		return nil, s.unavailable("could not record the push", err)
	}
	rec.State, rec.ExecutionID = StateExecuting, execID
	return &GitPushOp{s: s, rec: rec}, nil
}

// gitPushRefusal returns why a push is refused on its content, or "".
func gitPushRefusal(c *Caller, p GitPush) string {
	switch {
	case p.Malformed != "":
		return "the push request could not be read: " + clamp(p.Malformed, 200)
	case p.PushCert:
		return "signed pushes (push-cert) are not accepted; push without --signed"
	case len(p.Updates) == 0:
		return "the push request has no ref update"
	case len(p.Updates) > 1 || p.More:
		return "one push may update one ref, " + clamp("refs/heads/"+c.Branch, 120) + "; this one named more"
	}
	u := p.Updates[0]
	want := "refs/heads/" + c.Branch
	switch {
	case u.IsDelete():
		return "deleting " + clamp(u.Ref, 120) + " is not allowed"
	case u.Ref != want:
		return "this run may push " + clamp(want, 120) + " only, not " + clamp(u.Ref, 120)
	}
	return ""
}

// gitSubmission builds the op the push is recorded as. The params carry the
// first command and the number of commands; a random attempt id keeps two
// pushes of the same commit apart, because the same-caller same-hash rule
// would otherwise hold a retry back behind an unconfirmed earlier try.
func (s *Service) gitSubmission(c *Caller, p GitPush, project string) (*Submission, error) {
	var first GitUpdate
	if len(p.Updates) > 0 {
		first = p.Updates[0]
	}
	n := len(p.Updates)
	if p.More {
		n++
	}
	params := map[string]any{
		"attempt": s.newID("a-"), "commands": float64(n), "ref": first.Ref, "old": first.Old, "new": first.New,
	}
	jcs, err := spec.JCS(params)
	if err != nil {
		return nil, err
	}
	target := spec.Target{Adapter: "github", Ref: p.Repo}
	hash, err := spec.OpHash(map[string]any{
		"spec_version": spec.SpecVersion, "project": project, "op": OpBranchPush,
		"target": map[string]any{"adapter": target.Adapter, "ref": target.Ref}, "params": params,
	})
	if err != nil {
		return nil, err
	}
	return &Submission{Op: OpBranchPush, Project: project, Target: target, Params: params, ParamsJSON: string(jcs), OpHash: hash}, nil
}

// Finish records what became of the push (op.result) and ends the op.
func (g *GitPushOp) Finish(ctx context.Context, res GitPushResult) error {
	to, outcome := StateUnconfirmed, "unconfirmed"
	var out Outcome
	switch res.Outcome {
	case "succeeded":
		to, outcome = StateSucceeded, "succeeded"
		out.ExternalRef = clamp("github:"+g.rec.TargetRef+"@"+g.newSHA(), 300)
		out.Result = map[string]any{"ref": lineText(g.ref(), 300), "new": lineText(g.newSHA(), 300)}
	case "failed":
		to, outcome = StateFailed, "failed"
		out.Failed = true
		out.Result = map[string]any{"ref": lineText(g.ref(), 300), "error": lineText(res.Detail, 300)}
	case "unconfirmed":
		out.Unconfirmed = true
	default:
		return errors.New("ops: unknown git push outcome " + res.Outcome)
	}
	err := g.s.settle(context.WithoutCancel(ctx), g.rec, StateExecuting, to, outcome, "", out, g.rec.ExecutionID)
	if err != nil {
		g.s.log.Error("ops: could not record the push result", "request", shortID(g.rec.ID), "err", err)
	}
	return err
}

func (g *GitPushOp) params() map[string]any {
	tree, err := spec.ParseStrict([]byte(g.rec.ParamsJSON))
	if err != nil {
		return nil
	}
	m, _ := tree.(map[string]any)
	return m
}

func (g *GitPushOp) ref() string { s, _ := g.params()["ref"].(string); return s }

func (g *GitPushOp) newSHA() string { s, _ := g.params()["new"].(string); return s }

// git serves /git/ through the configured handler; a refusal it returns is
// written as the denial text git prints.
func (s *Server) git(w http.ResponseWriter, r *http.Request, c *Caller) {
	if err := s.cfg.Git.ServeGit(w, r, c); err != nil {
		s.fail(w, r, err)
	}
}
