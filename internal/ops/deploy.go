package ops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/untrusted"
	"github.com/joshua-noel/chaperone/internal/gh"
)

// This file is `deploy` (ticket L1-15): deploy one commit of the Storefront
// pilot on the WSL host.
//
// The path of one deploy:
//
//  1. Check (at submit, at the approval request, and again at release) runs the
//     policy checks in this order and stops at the first that fails, so **no
//     approval card exists for a deploy that would be refused**:
//     the SHA is on the project's base branch; `verify` (and the project's
//     extra checks) succeeded on that exact SHA, reusing pr.merge's judge; the
//     load gate says `normal` and was read less than 5 minutes ago; the last
//     valid backup is non-empty and younger than the project's limit; the
//     pilot's readiness says `ok`.
//  2. The op is class `high`: the pipeline creates the card (ADR-004 section 3),
//     the operator approves it in the console, and the approval is bound to the
//     op hash, which covers the SHA. An approval for deploy A cannot release
//     deploy B (`APPROVAL_HASH_MISMATCH`).
//  3. Execute reads the pilot once more, asks [HostRunner] to sign a grant for
//     the fixed `deploy` runbook with this SHA and wait for `chap-host`, then
//     reads the pilot's readiness until it says `ok` or the wait ends. A pilot
//     that is not `ok` afterwards is `failed` and raises an alert.
//  4. On success Chaperone records the deploy as a GitHub deployment (environment
//     `pilot`) with the App's own `deployments: write` token, replacing the
//     operator's `gh` login in record-deploy.mjs. A recording that fails is a
//     warning, not a failed deploy: the pilot is already running the commit.
//
// This code never runs a script and never touches WSL, Docker or the pilot
// except through the two read-only objects it is given: [HealthChecker] and
// [HostRunner].

// Deploy defaults.
const (
	// DefaultPostHealthWait is how long Execute waits for the pilot to say `ok`
	// after the runbook ended: the web unit restarts at the end of a deploy.
	DefaultPostHealthWait = 3 * time.Minute
	// DefaultPostHealthEvery is the pause between readiness reads.
	DefaultPostHealthEvery = 5 * time.Second

	deployTargetAdapter = "wsl-host"
	deployTargetRef     = "pilot"
	// DeployEnvironment is the GitHub deployment environment record-deploy.mjs uses.
	DeployEnvironment = "pilot"
	// AlertDeployFailed is the key of the alert a bad deploy raises.
	AlertDeployFailed = "deploy-failed"
)

var backupFileRE = regexp.MustCompile(`^pilot-[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{4}\.dump$`)

// DeployPolicy is what `deploy` knows about one project.
type DeployPolicy struct {
	// PR carries the repository, the base branch and the extra checks. The
	// project's `pr:` block supplies them: a deploy is of a commit on the
	// branch Chaperone merges into.
	PR PRPolicy
	// MaxBackupAge is the age limit of the last valid backup. Zero means
	// [DefaultBackupMaxAge].
	MaxBackupAge time.Duration
	// GateMaxAge is the age limit of the load gate reading. Zero means
	// [DefaultGateMaxAge].
	GateMaxAge time.Duration
}

// DeployPolicyFunc returns the deploy policy of a project. ok is false for a
// project that may not deploy (then the op is refused).
type DeployPolicyFunc func(project string) (DeployPolicy, bool)

// DeployAPI is the part of *[gh.Client] that deploy uses.
type DeployAPI interface {
	Compare(ctx context.Context, tok *gh.Token, repo gh.Repo, base, head string) (*gh.Comparison, error)
	ListCheckRuns(ctx context.Context, tok *gh.Token, repo gh.Repo, sha string, q gh.CheckRunQuery) ([]gh.CheckRun, error)
	CreateDeployment(ctx context.Context, tok *gh.Token, repo gh.Repo, in gh.DeploymentRequest) (*gh.Deployment, error)
	CreateDeploymentStatus(ctx context.Context, tok *gh.Token, repo gh.Repo, deploymentID int64, in gh.DeploymentStatusRequest) (*gh.DeploymentStatus, error)
	RevokeToken(ctx context.Context, tok *gh.Token) error
}

var _ DeployAPI = (*gh.Client)(nil)

// DeployAlerter raises the alert for a bad deploy. It must not block for long
// and must not fail an op; the implementation logs its own errors.
type DeployAlerter interface {
	RaiseDeployAlert(ctx context.Context, key, text string)
}

// DeployConfig builds the deploy [Adapter].
type DeployConfig struct {
	GitHub DeployAPI
	Tokens TokenMinter
	Policy DeployPolicyFunc
	Facts  HostFacts
	Health HealthChecker
	Host   HostRunner
	// Alert is optional.
	Alert DeployAlerter
	Now   func() time.Time
	// Location is the time zone of the HH:MM blast-radius times. Default: local.
	Location *time.Location
	// PostHealthWait and PostHealthEvery default to the Default* constants.
	PostHealthWait, PostHealthEvery time.Duration
}

// Deploy is the `deploy` [Adapter].
type Deploy struct{ cfg DeployConfig }

var _ Adapter = (*Deploy)(nil)

// NewDeploy returns the adapter.
func NewDeploy(cfg DeployConfig) (*Deploy, error) {
	if cfg.GitHub == nil || cfg.Tokens == nil || cfg.Policy == nil || cfg.Health == nil || cfg.Host == nil {
		return nil, errors.New("ops: deploy needs GitHub, Tokens, Policy, Health and Host")
	}
	if cfg.Facts.GatePath == "" || cfg.Facts.BackupPath == "" {
		return nil, errors.New("ops: deploy needs the paths of the load gate and the last valid backup")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.PostHealthWait <= 0 {
		cfg.PostHealthWait = DefaultPostHealthWait
	}
	if cfg.PostHealthEvery <= 0 {
		cfg.PostHealthEvery = DefaultPostHealthEvery
	}
	return &Deploy{cfg: cfg}, nil
}

// ---- request ---------------------------------------------------------------

type deployRequest struct {
	sha    string
	repo   gh.Repo
	policy DeployPolicy
}

func (d *Deploy) request(r *Request) (deployRequest, error) {
	if r.Target.Adapter != deployTargetAdapter || r.Target.Ref != deployTargetRef {
		return deployRequest{}, paramsInvalid("target must be {adapter: %s, ref: %s}", deployTargetAdapter, deployTargetRef)
	}
	if err := onlyParams(r.Params, "sha"); err != nil {
		return deployRequest{}, err
	}
	sha, err := paramString(r.Params, "sha")
	if err != nil {
		return deployRequest{}, err
	}
	if !deploySHA.MatchString(sha) {
		return deployRequest{}, paramsInvalid("param sha must be a full lower-case 40-character commit SHA")
	}
	pol, ok := d.cfg.Policy(r.Project)
	if !ok {
		return deployRequest{}, &Refusal{Code: CodePolicyRefused, Why: clip(fmt.Sprintf(
			"deploy is refused for project %s: its policy has no deploy settings", r.Project), 400)}
	}
	repo, err := gh.ParseRepo(pol.PR.Repo)
	if err != nil {
		return deployRequest{}, &Refusal{Code: CodePolicyRefused, Why: clip(fmt.Sprintf(
			"deploy is refused for project %s: its policy names no repository", r.Project), 400)}
	}
	if err := pol.PR.validate(); err != nil {
		return deployRequest{}, &Refusal{Code: CodePolicyRefused, Why: clip(fmt.Sprintf(
			"deploy is refused for project %s: %v", r.Project, err), 400)}
	}
	if pol.MaxBackupAge <= 0 {
		pol.MaxBackupAge = DefaultBackupMaxAge
	}
	if pol.GateMaxAge <= 0 {
		pol.GateMaxAge = DefaultGateMaxAge
	}
	return deployRequest{sha: sha, repo: repo, policy: pol}, nil
}

// ---- Check -----------------------------------------------------------------

// Check runs the five policy checks in order and stops at the first failure.
// It reads GitHub, two small files and the pilot's readiness; it writes
// nothing and mints only a read token, which it revokes.
func (d *Deploy) Check(ctx context.Context, r *Request) (CheckResult, error) {
	req, err := d.request(r)
	if err != nil {
		return CheckResult{}, err
	}
	v := PRVerdict{Outcome: PRAllow, Head: req.sha, PolicyVersion: r.PolicyVer}
	var ev deployEvidence

	if err := d.checkGitHub(ctx, req, &v, &ev); err != nil {
		return CheckResult{}, err
	}
	if !v.failed() {
		d.checkGate(req, &v, &ev)
	}
	if !v.failed() {
		d.checkBackup(req, &v, &ev)
	}
	if !v.failed() {
		d.checkHealth(ctx, &v, &ev)
	}

	cr := CheckResult{Checks: verdictChecks(v)}
	if v.failed() {
		v.refuse(v.Stop)
		return cr, refusalOf(v)
	}
	cr.Evidence = []Evidence{{Name: "deploy checks", Text: ev.text(req)}}
	return cr, nil
}

// deployEvidence is what the card shows besides the SHA: the facts the checks
// read, as short fixed-shape lines.
type deployEvidence struct {
	gate, backup string
	verify       []string
}

func (e deployEvidence) text(req deployRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: pilot (WSL host, sm-pilot)\nCommit: %s\nOn base: %s (%s)\n", req.sha, req.policy.PR.Base, req.repo)
	for _, v := range e.verify {
		b.WriteString(v + "\n")
	}
	fmt.Fprintf(&b, "Load gate: %s\nLast valid backup: %s\nPilot health before: ok\n", e.gate, e.backup)
	b.WriteString("Runbook: pilot.sh deploy (changelog assembly, migration rehearsal, deploy, record)")
	return b.String()
}

func (d *Deploy) checkGitHub(ctx context.Context, req deployRequest, v *PRVerdict, ev *deployEvidence) (err error) {
	tok, err := d.cfg.Tokens.Mint(ctx, req.repo, gh.PermsDeployRead())
	if err != nil {
		return fmt.Errorf("deploy: %w", err)
	}
	defer func() {
		_ = d.revoke(ctx, tok) // it expires within the hour if GitHub did not take the revoke
	}()

	// 1. The SHA is on the base branch: base...sha says "behind" or "identical"
	// when the SHA is an ancestor of the base's tip.
	cmp, cerr := d.cfg.GitHub.Compare(ctx, tok, req.repo, req.policy.PR.Base, req.sha)
	switch {
	case errors.Is(cerr, gh.ErrNotFound):
		v.add("sha_on_base", false, "no such commit "+short(req.sha)+" in "+req.repo.String())
		return nil
	case cerr != nil:
		return fmt.Errorf("deploy: compare: %w", cerr)
	}
	onBase := (cmp.Status == "identical" || cmp.Status == "behind") && cmp.AheadBy == 0
	v.add("sha_on_base", onBase, fmt.Sprintf("%s is not on %s (GitHub compares it as %s, %d commit(s) ahead)",
		short(req.sha), req.policy.PR.Base, oneWord(cmp.Status), cmp.AheadBy))
	if !onBase {
		return nil
	}

	// 2. verify (and the project's extra checks) succeeded on exactly this SHA.
	for _, name := range req.policy.PR.requiredChecks() {
		runs, lerr := d.cfg.GitHub.ListCheckRuns(ctx, tok, req.repo, req.sha, gh.CheckRunQuery{
			CheckName: name, AppID: gh.GitHubActionsAppID, All: true,
		})
		if errors.Is(lerr, gh.ErrListTruncated) {
			v.add(name, false, "more check runs than GitHub listed; result is ambiguous")
			return nil
		}
		if lerr != nil {
			return fmt.Errorf("deploy: read check %s: %w", name, lerr)
		}
		c, stop := judgeCheck(name, gh.GitHubActionsAppID, "GitHub Actions", runs, req.sha)
		v.Checks = append(v.Checks, c)
		if !c.Passed {
			v.Stop = stop
			return nil
		}
		ev.verify = append(ev.verify, fmt.Sprintf("%s: success on %s", name, short(req.sha)))
	}
	return nil
}

func (d *Deploy) revoke(ctx context.Context, tok *gh.Token) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := d.cfg.GitHub.RevokeToken(rctx, tok)
	tok.Wipe()
	return err
}

func (d *Deploy) checkGate(req deployRequest, v *PRVerdict, ev *deployEvidence) {
	g, err := d.cfg.Facts.ReadLoadGate()
	if err != nil {
		addCheck(v, "load_gate", false, "the load gate file: "+err.Error())
		return
	}
	ok, detail := judgeGate(g, d.cfg.Now(), req.policy.GateMaxAge)
	addCheck(v, "load_gate", ok, detail)
	if ok {
		ev.gate = detail
	}
}

func (d *Deploy) checkBackup(req deployRequest, v *PRVerdict, ev *deployEvidence) {
	b, err := d.cfg.Facts.ReadBackup()
	if err != nil {
		addCheck(v, "backup", false, "the last valid backup file: "+err.Error())
		return
	}
	ok, detail := judgeBackup(b, d.cfg.Now(), req.policy.MaxBackupAge)
	if ok && d.cfg.Facts.DumpSize != nil && b.Path != "" {
		switch size, serr := d.cfg.Facts.DumpSize(b.Path); {
		case errors.Is(serr, os.ErrNotExist):
			ok, detail = false, "the dump the last valid backup names is gone"
		case serr == nil && size <= 0:
			ok, detail = false, "the dump the last valid backup names is empty (0 bytes)"
		}
	}
	addCheck(v, "backup", ok, detail)
	if !ok {
		return
	}
	ev.backup = detail
	if backupFileRE.MatchString(b.File) {
		ev.backup += ", " + b.File
	}
	ev.backup += fmt.Sprintf(", %d entries, validated at %s", b.Entries, b.ValidatedAt.UTC().Format(time.RFC3339))
}

func (d *Deploy) checkHealth(ctx context.Context, v *PRVerdict, _ *deployEvidence) {
	st := d.cfg.Health.Check(ctx)
	detail := "ok"
	if !st.OK() {
		detail = "pilot readiness is " + oneWord(st.Status) + ", not ok"
	}
	addCheck(v, "pilot_health", st.OK(), detail)
}

// ---- Execute ---------------------------------------------------------------

// Execute runs after the approval is consumed. It never retries the runbook.
func (d *Deploy) Execute(ctx context.Context, r *Request) (Outcome, error) {
	req, err := d.request(r)
	if err != nil {
		return failedOutcome("the request cannot be read: " + err.Error()), nil
	}
	started := d.cfg.Now()
	res := map[string]any{"sha": req.sha}

	// The pilot must still be healthy: Check ran a moment ago, and a deploy over
	// a pilot that went down in between would hide which change broke it.
	if before := d.cfg.Health.Check(ctx); !before.OK() {
		res["health_before"] = before.Status
		res["error"] = "the pilot is not healthy before the deploy; nothing was started"
		return Outcome{Failed: true, Result: res}, nil
	}

	hr, err := d.cfg.Host.RunDeploy(ctx, HostJob{OpID: r.ID, OpHash: r.OpHash, SHA: req.sha, Caller: r.Caller})
	switch {
	case errors.Is(err, ErrHostNotTaken):
		res["error"] = "the host helper did not take the grant in time; nothing ran"
		return Outcome{Failed: true, Result: res}, nil
	case err != nil:
		res["error"] = clip(err.Error(), 300)
		d.alert(ctx, req, "the host helper may or may not have run it: "+clip(err.Error(), 120))
		return Outcome{Unconfirmed: true, Result: res}, nil
	}
	res["host_outcome"] = hr.Outcome
	res["exit_code"] = hr.ExitCode
	if hr.Code != "" {
		res["host_code"] = hr.Code
	}
	if hr.Output != "" {
		res["output_tail"] = hr.Output
	}

	// From here the runbook ran (or the host said why it did not). The readiness
	// wait must outlive an op context that is close to its limit.
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), d.cfg.PostHealthWait+15*time.Second)
	defer cancel()

	switch hr.Outcome {
	case HostSucceeded:
	case HostRefused:
		res["error"] = "the host helper refused the grant; nothing ran"
		d.alert(hctx, req, "the host helper refused the grant ("+oneWord(hr.Code)+")")
		return Outcome{Failed: true, Result: res}, nil
	case HostTimeout:
		// The runbook was killed part way: what it changed is unknown.
		d.finish(res, started, d.cfg.Health.Check(hctx))
		res["error"] = "the runbook timed out on the host; the pilot's state is unknown"
		d.alert(hctx, req, "the runbook timed out on the host; check the pilot now")
		d.record(hctx, req, r, gh.DeployError, res)
		return Outcome{Unconfirmed: true, Result: res}, nil
	default: // failed
		after := d.cfg.Health.Check(hctx)
		d.finish(res, started, after)
		res["error"] = fmt.Sprintf("the runbook failed with exit code %d", hr.ExitCode)
		d.alert(hctx, req, fmt.Sprintf("the runbook failed (exit %d); pilot readiness is %s", hr.ExitCode, after.Status))
		d.record(hctx, req, r, gh.DeployFailure, res)
		return Outcome{Failed: true, Result: res}, nil
	}

	after := d.waitHealthy(hctx)
	d.finish(res, started, after)
	if !after.OK() {
		res["error"] = "the runbook finished but the pilot is not healthy afterwards"
		d.alert(hctx, req, "the pilot is "+after.Status+" after the deploy; roll back or investigate now")
		d.record(hctx, req, r, gh.DeployFailure, res)
		return Outcome{Failed: true, Result: res}, nil
	}
	return Outcome{ExternalRef: d.record(hctx, req, r, gh.DeploySuccess, res), Result: res}, nil
}

// addCheck records a check whose detail is a note when it passed and the
// reason when it failed (PRVerdict.add drops the note of a passed check).
func addCheck(v *PRVerdict, name string, passed bool, detail string) {
	v.Checks = append(v.Checks, PRCheck{Name: name, Passed: passed, Detail: clip(detail, 300)})
}

func failedOutcome(msg string) Outcome {
	return Outcome{Failed: true, Result: map[string]any{"error": clip(untrusted.Line(msg), 300)}}
}

// finish adds the post-deploy health and the blast-radius times (HH:MM).
func (d *Deploy) finish(res map[string]any, started time.Time, after HealthStatus) {
	end := d.cfg.Now()
	res["health_after"] = after.Status
	res["started_at"] = started.In(d.cfg.Location).Format("15:04")
	res["finished_at"] = end.In(d.cfg.Location).Format("15:04")
	res["blast_radius"] = res["started_at"].(string) + "-" + res["finished_at"].(string)
}

// waitHealthy reads readiness until it says ok or the wait ends.
func (d *Deploy) waitHealthy(ctx context.Context) HealthStatus {
	deadline := time.NewTimer(d.cfg.PostHealthWait)
	defer deadline.Stop()
	tick := time.NewTicker(d.cfg.PostHealthEvery)
	defer tick.Stop()
	for {
		st := d.cfg.Health.Check(ctx)
		if st.OK() {
			return st
		}
		select {
		case <-ctx.Done():
			return st
		case <-deadline.C:
			return d.cfg.Health.Check(ctx)
		case <-tick.C:
		}
	}
}

func (d *Deploy) alert(ctx context.Context, req deployRequest, why string) {
	if d.cfg.Alert == nil {
		return
	}
	d.cfg.Alert.RaiseDeployAlert(ctx, AlertDeployFailed, "Deploy of "+short(req.sha)+": "+why)
}

// record writes the GitHub deployment and its status with the App's own
// deployments token. It returns the deployment's API URL for the op result's
// external_ref ("" when nothing could be recorded). A failure to record adds a
// warning to the result and never changes the op's outcome.
func (d *Deploy) record(ctx context.Context, req deployRequest, r *Request, state string, res map[string]any) (ref string) {
	warn := func(msg string) {
		res["record_warning"] = clip(msg, 200)
	}
	tok, err := d.cfg.Tokens.Mint(ctx, req.repo, gh.PermsDeploy())
	if err != nil {
		warn("the deployment could not be recorded: no GitHub token")
		return ""
	}
	defer func() { _ = d.revoke(ctx, tok) }()
	dep, err := d.cfg.GitHub.CreateDeployment(ctx, tok, req.repo, gh.DeploymentRequest{
		Ref: req.sha, Environment: DeployEnvironment, Description: "Deployed by Chaperone, op " + r.ID,
	})
	if err != nil {
		warn("the deployment could not be recorded: GitHub refused or did not answer")
		return ""
	}
	if _, err := d.cfg.GitHub.CreateDeploymentStatus(ctx, tok, req.repo, dep.ID, gh.DeploymentStatusRequest{
		State: state, Description: "Chaperone op " + r.ID,
	}); err != nil {
		warn("the deployment was created but its status could not be set")
	}
	res["deployment_id"] = dep.ID
	return clip(fmt.Sprintf("https://api.github.com/repos/%s/deployments/%d", req.repo, dep.ID), 300)
}
