package ops

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// This file bridges [PRMerger] (L1-10) to the op pipeline: it is the
// [Adapter] of `pr.merge` and of `pr.update`.
//
// The pipeline has already done ADR-002 step 1 (token scope, op enabled, rate
// limit) when Check runs. The adapters add one more rule of their own: a
// project whose policy file has no `pr:` block is refused with
// OP_POLICY_REFUSED. The baseline turns both ops on for every project, so the
// `pr:` block is what says which projects Chaperone may merge for, into which
// branch, behind which checks.

// PRPolicyFunc returns the merge policy of a project. ok is false when the
// project has none (no policy file, or no `pr:` block in it).
type PRPolicyFunc func(project string) (PRPolicy, bool)

// PRPolicyFromEngine reads the `pr:` block of a project from the policy engine.
// The policy version is the project's effective version, so a verdict and the
// approval card name the exact policy they were judged under.
func PRPolicyFromEngine(e *policy.Engine) PRPolicyFunc {
	return func(project string) (PRPolicy, bool) {
		eff := e.For(project)
		if eff.Invalid != nil || eff.PR == nil {
			return PRPolicy{}, false
		}
		p := PRPolicy{
			Version:     eff.Version,
			Repo:        eff.PR.Repo,
			Base:        eff.PR.Base,
			ExtraChecks: eff.PR.ExtraChecks,
			Tiers:       PRTierGlobs{High: eff.PR.Tiers.High, Medium: eff.PR.Tiers.Medium, Low: eff.PR.Tiers.Low},
		}
		if l := eff.PR.LocalCI; l != nil {
			p.LocalCI = &PRLocalCI{Check: l.Check, Instead: l.Mode == policy.LocalCIInstead}
		}
		return p, true
	}
}

// NewPRMergeAdapter returns the `pr.merge` adapter.
func NewPRMergeAdapter(m *PRMerger, pol PRPolicyFunc) Adapter {
	return &prMergeAdapter{m: m, pol: pol}
}

// NewPRUpdateAdapter returns the `pr.update` adapter.
func NewPRUpdateAdapter(m *PRMerger, pol PRPolicyFunc) Adapter {
	return &prUpdateAdapter{m: m, pol: pol}
}

func paramsInvalid(format string, a ...any) error {
	return &Refusal{Code: CodeParamsInvalid, Why: clip(fmt.Sprintf(format, a...), 400)}
}

func noPRBlock(project, op string) error {
	return &Refusal{Code: CodePolicyRefused, Why: clip(fmt.Sprintf(
		"%s is refused for project %s: its policy file has no pr: block (merge base and checks)", op, project), 400)}
}

// projectPR returns the project's merge policy for a request on repo. The
// project's `pr:` block names its repository: a request for any other
// repository is refused, so a token scoped to one project cannot merge into
// another project's repository.
func projectPR(pol PRPolicyFunc, r *Request, repo gh.Repo, op string) (PRPolicy, error) {
	p, ok := pol(r.Project)
	if !ok {
		return PRPolicy{}, noPRBlock(r.Project, op)
	}
	if p.Repo != "" && !strings.EqualFold(p.Repo, repo.String()) {
		return PRPolicy{}, &Refusal{Code: CodePolicyRefused, Why: clip(fmt.Sprintf(
			"%s is refused: project %s merges only in %s, not %s", op, r.Project, p.Repo, repo), 400)}
	}
	return p, nil
}

// targetPR parses a target ref "owner/repo#N" (number optional when optNum).
func targetPR(r *Request, optNum bool) (gh.Repo, int, error) {
	if r.Target.Adapter != githubspec.Adapter {
		return gh.Repo{}, 0, paramsInvalid("target adapter must be github, got %q", clip(r.Target.Adapter, 40))
	}
	ref, num, hasNum := strings.Cut(r.Target.Ref, "#")
	repo, err := gh.ParseRepo(ref)
	if err != nil {
		return gh.Repo{}, 0, paramsInvalid("target ref must be owner/repo#N")
	}
	n := 0
	if hasNum {
		if n, err = strconv.Atoi(num); err != nil || n <= 0 || strconv.Itoa(n) != num {
			return gh.Repo{}, 0, paramsInvalid("target ref has a bad pull request number")
		}
	} else if !optNum {
		return gh.Repo{}, 0, paramsInvalid("target ref must be owner/repo#N")
	}
	return repo, n, nil
}

// paramString reads a required string param.
func paramString(p map[string]any, key string) (string, error) {
	s, ok := p[key].(string)
	if !ok || s == "" {
		return "", paramsInvalid("param %s is required and must be a string", key)
	}
	return s, nil
}

// onlyParams refuses a param the op does not define.
func onlyParams(p map[string]any, allowed ...string) error {
	for k := range p {
		found := false
		for _, a := range allowed {
			found = found || k == a
		}
		if !found {
			return paramsInvalid("unknown param %q", clip(k, 40))
		}
	}
	return nil
}

// paramInt reads an integer param. JSON numbers arrive as float64.
func paramInt(p map[string]any, key string) (int, bool, error) {
	v, ok := p[key]
	if !ok {
		return 0, false, nil
	}
	switch n := v.(type) {
	case float64:
		if n >= 1 && n <= 1<<31 && n == float64(int(n)) {
			return int(n), true, nil
		}
	case int:
		if n >= 1 {
			return n, true, nil
		}
	}
	return 0, true, paramsInvalid("param %s must be a positive integer", key)
}

func verdictChecks(v PRVerdict) []Check {
	out := make([]Check, 0, len(v.Checks))
	for _, c := range v.Checks {
		out = append(out, Check{Name: c.Name, Passed: c.Passed, Detail: c.Detail})
	}
	return out
}

// verdictResult is the redacted-by-caller result map of an op: the verdict an
// agent or the console reads (the API's `result`).
func verdictResult(v PRVerdict) map[string]any {
	checks := make([]any, 0, len(v.Checks))
	for _, c := range v.Checks {
		m := map[string]any{"name": c.Name, "passed": c.Passed}
		if c.Detail != "" {
			m["detail"] = c.Detail
		}
		checks = append(checks, m)
	}
	out := map[string]any{"outcome": string(v.Outcome), "head": v.Head, "checks": checks}
	if v.Tier != "" {
		out["tier"] = string(v.Tier)
	}
	if v.Stop != "" {
		out["stop"] = v.Stop
	}
	if v.Why != "" {
		out["why"] = v.Why
	}
	return out
}

// refusalOf turns a refused verdict into the pipeline's refusal. The stop code
// (CI_RED, CI_STALE) leads the text so the denial names it.
func refusalOf(v PRVerdict) error {
	why := v.Why
	if v.Stop != "" {
		why = v.Stop + ": " + why
	}
	code := v.Cause
	if code == "" {
		code = CodePolicyRefused
	}
	return &Refusal{Code: code, Why: clip(why, 400)}
}

// ---- pr.merge --------------------------------------------------------------

type prMergeAdapter struct {
	m   *PRMerger
	pol PRPolicyFunc
}

func (a *prMergeAdapter) request(r *Request) (PRMergeRequest, error) {
	repo, n, err := targetPR(r, false)
	if err != nil {
		return PRMergeRequest{}, err
	}
	if err := onlyParams(r.Params, githubspec.PRMerge.ParamNames()...); err != nil {
		return PRMergeRequest{}, err
	}
	base, err := paramString(r.Params, "base")
	if err != nil {
		return PRMergeRequest{}, err
	}
	head, err := paramString(r.Params, "head_sha")
	if err != nil {
		return PRMergeRequest{}, err
	}
	if method, _ := r.Params["method"].(string); method != "squash" {
		return PRMergeRequest{}, paramsInvalid("param method must be squash")
	}
	pol, err := projectPR(a.pol, r, repo, "pr.merge")
	if err != nil {
		return PRMergeRequest{}, err
	}
	req := PRMergeRequest{Repo: repo, Number: n, Base: base, HeadSHA: head, Policy: pol, ApprovedTitle: approvedTitle(r.ApprovedEvidence)}
	if err := req.validate(); err != nil {
		return PRMergeRequest{}, paramsInvalid("%v", err)
	}
	return req, nil
}

// Check is ADR-002 steps 2-6 as a dry run: nothing is written and no write
// token is minted.
func (a *prMergeAdapter) Check(ctx context.Context, r *Request) (CheckResult, error) {
	req, err := a.request(r)
	if err != nil {
		return CheckResult{}, err
	}
	req.DryRun = true
	res, err := a.m.Merge(ctx, req)
	if err != nil {
		return CheckResult{}, err
	}
	v := res.Verdict
	cr := CheckResult{Checks: verdictChecks(v)}
	if s := v.Subject; s.Title != "" {
		cr.Evidence = append(cr.Evidence, Evidence{Name: PRSubjectEvidence, Text: s.text()})
	}
	if len(v.TierPaths) > 0 {
		paths := v.TierPaths
		more := ""
		if len(paths) > 40 {
			paths, more = paths[:40], fmt.Sprintf("\n... and %d more", len(v.TierPaths)-40)
		}
		cr.Evidence = append(cr.Evidence, Evidence{Name: "paths that set the tier (" + string(v.Tier) + ")", Text: clip(strings.Join(paths, "\n"), 4000) + more})
	}
	switch v.Outcome {
	case PRRefuse:
		return cr, refusalOf(v)
	case PRApproval:
		cr.NeedsApproval, cr.ApprovalWhy = true, v.Why
		// The tier check is the question the card answers, not a failed
		// precondition: left failing it would make the card impossible (the
		// approvals engine refuses a card with a failed check, since no
		// approval can cure one). Every other check passed to get here.
		for i := range cr.Checks {
			if cr.Checks[i].Name == "risk_tier" {
				cr.Checks[i].Passed = true
			}
		}
	}
	return cr, nil
}

// Execute runs steps 2-9 and merges exactly the head that was named.
//
// Approved is true: Execute is reached only for a request the pipeline let
// through, and the pipeline lets a medium or high tier request through only
// after a valid approval bound to this op hash (whose params include head_sha),
// because Check reports NeedsApproval for it. A low tier request needs none.
func (a *prMergeAdapter) Execute(ctx context.Context, r *Request) (Outcome, error) {
	req, err := a.request(r)
	if err != nil {
		return Outcome{Failed: true, Result: map[string]any{"error": err.Error()}}, nil
	}
	req.Approved = true
	res, err := a.m.Merge(ctx, req)
	switch {
	case errors.Is(err, ErrMergeUnconfirmed):
		return Outcome{Unconfirmed: true, Result: map[string]any{"error": clip(err.Error(), 400)}}, nil
	case err != nil:
		// Every other error comes before the write or after a read-back that
		// showed the PR open: it did not merge.
		return Outcome{Failed: true, Result: map[string]any{"error": clip(err.Error(), 400)}}, nil
	}
	out := Outcome{Result: verdictResult(res.Verdict)}
	out.Result["merged"] = res.Merged
	if len(res.Warnings) > 0 {
		ws := make([]any, len(res.Warnings))
		for i, w := range res.Warnings {
			ws[i] = clip(w, 300)
		}
		out.Result["warnings"] = ws
	}
	if !res.Merged {
		out.Failed = true // a precondition failed after the check (the head or base moved)
		return out, nil
	}
	out.Result["merge_commit_sha"] = res.MergeCommitSHA
	out.ExternalRef = res.ExternalRef
	return out, nil
}

// ---- pr.update -------------------------------------------------------------

type prUpdateAdapter struct {
	m   *PRMerger
	pol PRPolicyFunc
}

func (a *prUpdateAdapter) request(r *Request) (PRUpdateRequest, error) {
	repo, refN, err := targetPR(r, true)
	if err != nil {
		return PRUpdateRequest{}, err
	}
	if err := onlyParams(r.Params, githubspec.PRUpdate.ParamNames()...); err != nil {
		return PRUpdateRequest{}, err
	}
	n, hasN, err := paramInt(r.Params, "number")
	if err != nil {
		return PRUpdateRequest{}, err
	}
	switch {
	case !hasN && refN == 0:
		return PRUpdateRequest{}, paramsInvalid("param number is required")
	case hasN && refN != 0 && n != refN:
		return PRUpdateRequest{}, paramsInvalid("param number differs from the target's pull request number")
	case !hasN:
		n = refN
	}
	head, err := paramString(r.Params, "expected_head_sha")
	if err != nil {
		return PRUpdateRequest{}, err
	}
	if _, ok := r.Params["title"]; ok {
		return PRUpdateRequest{}, paramsInvalid("pr.update here only brings the base into the branch; title is not supported")
	}
	if _, ok := r.Params["body"]; ok {
		return PRUpdateRequest{}, paramsInvalid("pr.update here only brings the base into the branch; body is not supported")
	}
	if v, ok := r.Params["update_branch"]; ok && v != true {
		return PRUpdateRequest{}, paramsInvalid("update_branch must be true (nothing else is supported)")
	}
	pol, err := projectPR(a.pol, r, repo, "pr.update")
	if err != nil {
		return PRUpdateRequest{}, err
	}
	req := PRUpdateRequest{Repo: repo, Number: n, ExpectedHeadSHA: head, Policy: pol}
	probe := PRMergeRequest{Repo: repo, Number: n, HeadSHA: head, Policy: pol}
	if err := probe.validate(); err != nil {
		return PRUpdateRequest{}, paramsInvalid("%v", err)
	}
	return req, nil
}

// Check validates the request and the project policy. The branch state is read
// by Execute, under the repository lock, because UpdateBranch has no dry run.
func (a *prUpdateAdapter) Check(_ context.Context, r *Request) (CheckResult, error) {
	if _, err := a.request(r); err != nil {
		return CheckResult{}, err
	}
	return CheckResult{}, nil
}

// Execute brings the base into the PR branch.
func (a *prUpdateAdapter) Execute(ctx context.Context, r *Request) (Outcome, error) {
	req, err := a.request(r)
	if err != nil {
		return Outcome{Failed: true, Result: map[string]any{"error": err.Error()}}, nil
	}
	res, err := a.m.UpdateBranch(ctx, req)
	if err != nil {
		return Outcome{}, err // unconfirmed: GitHub may have accepted the update
	}
	out := Outcome{Result: verdictResult(res.Verdict)}
	out.Result["updated"] = res.Updated
	if len(res.Warnings) > 0 {
		ws := make([]any, len(res.Warnings))
		for i, w := range res.Warnings {
			ws[i] = clip(w, 300)
		}
		out.Result["warnings"] = ws
	}
	if !res.Updated {
		out.Failed = true
		return out, nil
	}
	out.Result["old_head"], out.Result["new_head"] = res.OldHead, res.NewHead
	if res.Message != "" {
		out.Result["message"] = res.Message
	}
	out.ExternalRef = res.ExternalRef
	return out, nil
}
