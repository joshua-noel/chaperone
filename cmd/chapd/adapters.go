package main

import (
	"context"
	"errors"

	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/gh"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// adapterDeps is what the op adapters are built from.
type adapterDeps struct {
	// github is the App client; nil when chapd has no GitHub App configured
	// (no -github-app-id), in which case no GitHub op has an adapter.
	github *gh.Client
	// minter mints one repository-narrowed installation token per call.
	minter ops.TokenMinter
	policy *policy.Engine
	// ciRun reads chapd's own record of a run, for ci.report. It is set after the run registry exists (the
	// registry's end hook needs the op service, which needs the adapters), so it reads the registry lazily.
	ciRun ops.CIRunFunc
}

// ciRunLookup reads a run from the registry get returns.
func ciRunLookup(get func() *runtoken.Runs) ops.CIRunFunc {
	return func(ctx context.Context, runID string) (ops.CIRun, error) {
		runs := get()
		if runs == nil {
			return ops.CIRun{}, errors.New("run registry is not ready")
		}
		rec, err := runs.Get(ctx, runID)
		if errors.Is(err, runtoken.ErrNotFound) {
			return ops.CIRun{}, ops.ErrCIRunUnknown
		}
		if err != nil {
			return ops.CIRun{}, err
		}
		return ops.CIRun{
			RunID: rec.RunID, Project: rec.Project, Profile: rec.Claims.Profile.Name,
			Repo: rec.Claims.TaskScope.Repo, Head: rec.Claims.TaskScope.Base,
			Ended: rec.State == "ended", Outcome: rec.EndOutcome,
		}, nil
	}
}

func newAdapterDeps(c *gh.Client, pol *policy.Engine) adapterDeps {
	d := adapterDeps{github: c, policy: pol}
	if c != nil {
		d.minter = &ops.InstallationMinter{Client: c}
	}
	return d
}

// adapters returns the op adapters this build installs, by op kind. Each ticket
// adds its lines here and flips its op in internal/policy/data/baseline.yaml
// (the policy PR): L1-11 logs, L1-16 mail.send and drive.share. `deploy` (L1-15)
// is built in deploy.go, only when its flags are set. An op with no adapter is
// refused (OP_DISABLED), whatever the baseline says.
func adapters(d adapterDeps) (map[string]ops.Adapter, error) {
	m := map[string]ops.Adapter{}
	// L1-11. Read-only: one GET of the pilot readiness URL on the loopback.
	pilot, err := ops.NewPilotHealth(ops.PilotHealthConfig{})
	if err != nil {
		return nil, err
	}
	m["health"] = ops.NewHealthAdapter(pilot)
	if d.github != nil {
		// The adapters of the github connector. kit.Bind below refuses to
		// start when a declared operation has no adapter here, or an adapter
		// here has no declaration (internal/connectors/github/githubspec).
		g := map[string]ops.Adapter{}
		// L1-10. The baseline turns both on; a project is mergeable only if its
		// policy file has a `pr:` block (the adapters refuse any other).
		merger, err := ops.NewPRMerger(ops.PRMergerConfig{GitHub: d.github, Tokens: d.minter})
		if err != nil {
			return nil, err
		}
		pol := ops.PRPolicyFromEngine(d.policy)
		g[githubspec.NamePRMerge] = ops.NewPRMergeAdapter(merger, pol)
		g[githubspec.NamePRUpdate] = ops.NewPRUpdateAdapter(merger, pol)

		// L1-09. A run opens a PR from its own branch; the orchestrator may name
		// any head in a project whose policy file has a `pr:` block.
		project := func(name string) (ops.PRProject, bool) {
			eff := d.policy.For(name)
			if eff.Invalid != nil || eff.PR == nil {
				return ops.PRProject{}, false
			}
			return ops.PRProject{Repo: eff.PR.Repo, Base: eff.PR.Base}, true
		}
		opener, err := ops.NewPROpen(ops.PROpenConfig{GitHub: d.github, Tokens: d.minter, Project: project})
		if err != nil {
			return nil, err
		}
		g[githubspec.NamePROpen] = opener

		// ADR-002 amendment 10. On in the baseline; a project is reportable only if its policy file has a
		// `pr.local_ci` block.
		if d.ciRun != nil {
			ci, err := ops.NewCIReportAdapter(ops.CIReportConfig{GitHub: d.github, Tokens: d.minter, Runs: d.ciRun, Policy: pol})
			if err != nil {
				return nil, err
			}
			ciBound, err := kit.Bind(githubspec.CI, map[string]ops.Adapter{githubspec.NameCIReport: ci})
			if err != nil {
				return nil, err
			}
			for op, a := range ciBound {
				m[op] = a
			}
		}

		// The error watcher files issues through the orchestrator
		// token; the repository is the project's `pr.repo`, and every issue
		// must carry the label source:error-watcher.
		for _, op := range []string{ops.OpIssueOpen, ops.OpIssueComment, ops.OpIssueReopen} {
			a, err := ops.NewIssueAdapter(op, ops.IssueConfig{GitHub: d.github, Tokens: d.minter, Project: project})
			if err != nil {
				return nil, err
			}
			g[op] = a
		}

		// ADR-002 amendment 12. Read-only views of a pull request (pr.view, pr.diff, pr.checks, pr.files) for the
		// orchestrator token; the repository is the project's `pr.repo`. Off in the baseline.
		for _, op := range ops.PRReadOps {
			a, err := ops.NewPRReadAdapter(op, ops.PRReadConfig{GitHub: d.github, Tokens: d.minter, Project: project})
			if err != nil {
				return nil, err
			}
			g[op] = a
		}
		bound, err := kit.Bind(githubspec.Connector, g)
		if err != nil {
			return nil, err
		}
		for op, a := range bound {
			m[op] = a
		}
	}
	return m, nil
}
