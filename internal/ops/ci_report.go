package ops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/gh"
)

// This file is `ci.report` (ADR-002 amendment 10): it states the result of a local CI run, a `ci` run in a
// the runner room, on GitHub as a check run of Chaperone's own App, which `pr.merge` accepts when the project's policy
// says so (`pr.local_ci`).
//
// Rules the code keeps:
//
//   - The caller names a run and nothing else. The repository, the commit and the conclusion are read from chapd's
//     own record of the run (`task_scope.repo` and `task_scope.base`, signed by the runner into the run token, and the
//     outcome the runner named when it ended the run, or `killed` when chapd ended it), never from the request.
//   - Only the orchestrator asks. A run never reports on itself or on another run: a room must not vouch for its
//     own result.
//   - Only a finished run of the `ci` profile in the project's own repository is reported. A run that is still
//     active, a run of another profile, a run that ended before chapd kept its outcome, and a repository other than
//     the policy's are refused before any GitHub call.
//   - `done` is `success`. `failed`, `killed` and `blocked` are `failure`. Nothing else is ever posted.
//   - GitHub is written with one token narrowed to the repository and `checks: write`, minted after the last check,
//     used for one lookup and one POST and revoked at once, whatever the answer.
//   - A repeat posts nothing new: a second Execute with the same execution id finds the run it posted (it carries
//     the execution id as its external_id) and reports that one; see post. A second report for the same run under another execution id is a new check run, and pr.merge
//     reads the latest check run of that name on the head, so it replaces the first.

// ciReportAdapterTarget is the target adapter of a ci.report request; the ref is the run's ID.
const ciReportAdapterTarget = githubspec.CIAdapter

// ciProfile is the profile a reported run must have had.
const ciProfile = "ci"

// CIRun is chapd's own record of one run, as ci.report needs it.
type CIRun struct {
	RunID   string
	Project string
	Profile string // the run token's profile name
	Repo    string // task_scope.repo
	Head    string // task_scope.base: for a ci run, the exact commit it checked
	Ended   bool
	Outcome string // done, failed, killed or blocked; empty while active and for a run that ended before it was kept
}

// ErrCIRunUnknown is what a [CIRunFunc] returns for a run chapd has no record of.
var ErrCIRunUnknown = errors.New("ops: no such run")

// CIRunFunc reads chapd's record of a run.
type CIRunFunc func(ctx context.Context, runID string) (CIRun, error)

// CIReportAPI is the part of *[gh.Client] that ci.report uses.
type CIReportAPI interface {
	CreateCheckRun(ctx context.Context, tok *gh.Token, repo gh.Repo, in gh.CheckRunRequest) (*gh.CheckRun, error)
	ListCheckRuns(ctx context.Context, tok *gh.Token, repo gh.Repo, sha string, q gh.CheckRunQuery) ([]gh.CheckRun, error)
	AppNumericID(ctx context.Context, repo gh.Repo) (int64, error)
	RevokeToken(ctx context.Context, tok *gh.Token) error
}

var _ CIReportAPI = (*gh.Client)(nil)

// CIReportConfig builds the `ci.report` adapter.
type CIReportConfig struct {
	GitHub CIReportAPI
	Tokens TokenMinter
	Runs   CIRunFunc
	Policy PRPolicyFunc
}

type ciReportAdapter struct{ cfg CIReportConfig }

// NewCIReportAdapter returns the `ci.report` adapter.
func NewCIReportAdapter(cfg CIReportConfig) (Adapter, error) {
	if cfg.GitHub == nil || cfg.Tokens == nil || cfg.Runs == nil || cfg.Policy == nil {
		return nil, errors.New("ops: ci.report needs GitHub, Tokens, Runs and Policy")
	}
	return &ciReportAdapter{cfg: cfg}, nil
}

// ciReport is a report that passed every check: what Execute posts.
type ciReport struct {
	repo       gh.Repo
	head       string
	runID      string
	check      string
	outcome    string
	conclusion string
}

func ciRefusal(format string, a ...any) error {
	return &Refusal{Code: CodePolicyRefused, Why: clip(fmt.Sprintf(format, a...), 400)}
}

// conclusionOf maps a run's outcome to the only two conclusions ci.report posts.
func conclusionOf(outcome string) string {
	if outcome == "done" {
		return "success"
	}
	return "failure"
}

// resolve checks the request against policy and chapd's own record of the run. It reads nothing from GitHub.
func (a *ciReportAdapter) resolve(ctx context.Context, r *Request) (ciReport, []Check, error) {
	var rep ciReport
	if r.Caller == nil || r.Caller.Kind != KindOrchestrator {
		return rep, nil, ciRefusal("ci.report is asked for by the orchestrator only; a run never reports a result")
	}
	if r.Target.Adapter != ciReportAdapterTarget {
		return rep, nil, paramsInvalid("target adapter must be %s, got %q", ciReportAdapterTarget, clip(r.Target.Adapter, 40))
	}
	if err := onlyParams(r.Params, githubspec.CIReport.ParamNames()...); err != nil {
		return rep, nil, err
	}
	runID, err := paramString(r.Params, "run_id")
	if err != nil {
		return rep, nil, err
	}
	if r.Target.Ref != runID {
		return rep, nil, paramsInvalid("target ref must be the run_id")
	}

	pol, ok := a.cfg.Policy(r.Project)
	switch {
	case !ok:
		return rep, nil, noPRBlock(r.Project, "ci.report")
	case pol.LocalCI == nil:
		return rep, nil, ciRefusal("ci.report is refused for project %s: its policy file has no pr.local_ci block", r.Project)
	}

	run, err := a.cfg.Runs(ctx, runID)
	if errors.Is(err, ErrCIRunUnknown) {
		return rep, nil, ciRefusal("ci.report is refused: chapd has no record of run %s", clip(runID, 40))
	}
	if err != nil {
		return rep, nil, fmt.Errorf("ci.report: read run %s: %w", clip(runID, 40), err)
	}

	checks := []Check{}
	fail := func(name, format string, a ...any) (ciReport, []Check, error) {
		why := fmt.Sprintf(format, a...)
		checks = append(checks, Check{Name: name, Detail: clip(why, 300)})
		return ciReport{}, checks, ciRefusal("ci.report is refused: %s", why)
	}
	pass := func(name, detail string) {
		checks = append(checks, Check{Name: name, Passed: true, Detail: clip(detail, 300)})
	}

	if run.Project != r.Project {
		return fail("run_project", "run %s belongs to another project", runID)
	}
	pass("run_project", "")
	if run.Profile != ciProfile {
		return fail("run_profile", "run %s has profile %s, not %s", runID, oneWord(run.Profile), ciProfile)
	}
	pass("run_profile", "")
	if !run.Ended {
		return fail("run_ended", "run %s has not ended", runID)
	}
	if run.Outcome == "" {
		return fail("run_ended", "chapd kept no outcome for run %s (it ended before chapd recorded outcomes)", runID)
	}
	pass("run_ended", run.Outcome)
	repo, err := gh.ParseRepo(run.Repo)
	if err != nil || !strings.EqualFold(run.Repo, pol.Repo) {
		return fail("run_repo", "run %s checked %s, and project %s reports only for %s", runID, oneWord(run.Repo), r.Project, pol.Repo)
	}
	pass("run_repo", run.Repo)
	if !headRE.MatchString(run.Head) {
		return fail("run_head", "run %s has no pinned commit", runID)
	}
	pass("run_head", short(run.Head))

	rep = ciReport{repo: repo, head: run.Head, runID: runID, check: pol.LocalCI.Check, outcome: run.Outcome, conclusion: conclusionOf(run.Outcome)}
	return rep, checks, nil
}

// Check validates the request against policy and chapd's record of the run. It makes no GitHub call.
func (a *ciReportAdapter) Check(ctx context.Context, r *Request) (CheckResult, error) {
	_, checks, err := a.resolve(ctx, r)
	return CheckResult{Checks: checks}, err
}

// Execute posts the check run.
func (a *ciReportAdapter) Execute(ctx context.Context, r *Request) (Outcome, error) {
	rep, _, err := a.resolve(ctx, r)
	if err != nil {
		return Outcome{Failed: true, Result: map[string]any{"error": clip(err.Error(), 400)}}, nil
	}

	tok, err := a.cfg.Tokens.Mint(ctx, rep.repo, gh.PermsReportCI())
	if err != nil {
		msg := "could not mint a token with checks: write: " + err.Error()
		var api *gh.APIError
		if errors.As(err, &api) && api.Status == 422 {
			msg = "GitHub refused a token with checks: write: the App does not hold that permission on " + rep.repo.String() + " yet (operator step, docs/runbooks/ci-report.md)"
		}
		return Outcome{Failed: true, Result: map[string]any{"error": clip(msg, 400)}}, nil
	}
	run, reused, perr := a.post(ctx, tok, rep, r.ExecutionID)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	rerr := a.cfg.GitHub.RevokeToken(rctx, tok)
	tok.Wipe()
	if perr != nil {
		return Outcome{Failed: true, Result: map[string]any{"error": clip(perr.Error(), 400)}}, nil
	}
	out := Outcome{
		Result: map[string]any{
			"run_id": rep.runID, "head_sha": rep.head, "check": rep.check, "conclusion": rep.conclusion,
			"outcome": rep.outcome, "check_run_id": run.ID,
		},
		ExternalRef: safeURL(run.HTMLURL, 300),
	}
	if reused {
		out.Result["already_posted"] = true
	}
	if rerr != nil {
		out.Result["warnings"] = []any{clip("revoke installation token: "+rerr.Error(), 300)}
	}
	return out, nil
}

func ciTitle(rep ciReport) string {
	if rep.conclusion == "success" {
		return "Local CI passed"
	}
	return "Local CI failed (" + rep.outcome + ")"
}

// ciSummary is the check run's text. It holds only what chapd itself knows: the run, the commit and the outcome.
func ciSummary(rep ciReport) string {
	return fmt.Sprintf("Run %s of the ci profile ended %s on commit %s.\n\nPosted by Chaperone's ci.report from its own record of the run (ADR-002, amendment 10).", rep.runID, rep.outcome, rep.head)
}

// post creates the check run, unless this execution already did. The run carries the execution id as its
// `external_id`, so a second Execute with the same id (which chapd does not make today) finds the first run by its
// name, head, App and external_id and returns it instead of posting again. When the lookup cannot be made, nothing is
// posted: without it a repeat could not be told from a first try. An Execute with no execution id (a test) posts.
func (a *ciReportAdapter) post(ctx context.Context, tok *gh.Token, rep ciReport, execID string) (run *gh.CheckRun, reused bool, err error) {
	if execID != "" {
		own, lerr := a.cfg.GitHub.AppNumericID(ctx, rep.repo)
		var runs []gh.CheckRun
		if lerr == nil {
			runs, lerr = a.cfg.GitHub.ListCheckRuns(ctx, tok, rep.repo, rep.head, gh.CheckRunQuery{CheckName: rep.check, AppID: own, All: true})
		}
		if lerr != nil {
			return nil, false, fmt.Errorf("look for an earlier report of this run: %w; nothing was posted", lerr)
		}
		for i := range runs {
			if r := runs[i]; r.Name == rep.check && r.HeadSHA == rep.head && r.AppID == own && r.ExternalID == execID {
				return &r, true, nil
			}
		}
	}
	run, err = a.cfg.GitHub.CreateCheckRun(ctx, tok, rep.repo, gh.CheckRunRequest{
		Name: rep.check, HeadSHA: rep.head, Conclusion: rep.conclusion,
		Title:      ciTitle(rep),
		Summary:    ciSummary(rep),
		ExternalID: execID,
	})
	if err != nil {
		return nil, false, fmt.Errorf("post check run: %w", err)
	}
	return run, false, nil
}
