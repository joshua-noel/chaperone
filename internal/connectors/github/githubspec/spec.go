// Package githubspec declares the GitHub operations once: `pr.open`,
// `pr.update`, `pr.merge`, the four read operations (`pr.view`, `pr.diff`,
// `pr.checks`, `pr.files`) and `issue.open`, `issue.comment`, `issue.reopen`,
// and `ci.report`, which states a finished local CI run's result on GitHub.
//
// It holds the facts that used to be typed by hand in the adapter map, the
// `chap` command table, the API manual, the params schema and the baseline: the
// name, class, reversibility, summary, usage line, rate, target and parameters
// of each operation. It holds no behaviour. The conditions under which an
// operation is allowed, the merge rules, the idempotency of each write and the
// handling of GitHub's text are in the adapters of internal/ops.
//
// `ci.report` is a second connector, `ci`, because its target adapter is
// `runner`: the ref is a run of chapd's own registry, and chapd reads the
// repository and the commit from that record. The act is still on GitHub.
//
// `branch.push` is not declared here. It is reached through the git proxy and
// not through POST /v0/ops, and the kit has no surface other than `op`.
//
// The package imports only the kit, so the `chap` client can use it without
// linking the daemon's code.
package githubspec

import "github.com/joshua-noel/chaperone/internal/connectors/kit"

// Adapter is `target.adapter` of every operation of the github connector.
const Adapter = "github"

// CIAdapter is `target.adapter` of ci.report: the run registry.
const CIAdapter = "runner"

// The op kinds.
const (
	NamePROpen       = "pr.open"
	NamePRUpdate     = "pr.update"
	NamePRMerge      = "pr.merge"
	NamePRView       = "pr.view"
	NamePRDiff       = "pr.diff"
	NamePRChecks     = "pr.checks"
	NamePRFiles      = "pr.files"
	NameIssueOpen    = "issue.open"
	NameIssueComment = "issue.comment"
	NameIssueReopen  = "issue.reopen"
	NameCIReport     = "ci.report"
)

// Limits of what a caller may send. The adapters in internal/ops use the same
// numbers.
const (
	// TitleMax is the longest pull request or issue title.
	TitleMax = 200
	// PRBodyMax and IssueBodyMax are the longest bodies.
	PRBodyMax    = 20000
	IssueBodyMax = 10000
	// IssueLabelsMax is the most labels on a new issue; IssueLabelMax is the
	// longest label.
	IssueLabelsMax = 10
	IssueLabelMax  = 50
	// FilesPerPage is the default page size of pr.files; FilesMaxPerPage is its
	// largest.
	FilesPerPage    = 30
	FilesMaxPerPage = 100
)

// The shapes the schema holds a value to.
const (
	// SHAPattern is a full lowercase sha-1 commit id.
	SHAPattern = `^[0-9a-f]{40}$`
	// HeadSHAPattern is a full lowercase commit id of either length (sha-1 or
	// sha-256). The reads accept both; the command line, as before, only the
	// 40 character one.
	HeadSHAPattern = `^(?:[0-9a-f]{40}|[0-9a-f]{64})$`
	// RunIDPattern is the id of a run, `r-7f3a`.
	RunIDPattern = `^r-[0-9a-z]{4,32}$`
)

// Connector is the declaration of the github connector.
var Connector = kit.Connector{
	Name: "github",
	Ops:  []kit.Op{PROpen, PRUpdate, PRMerge, PRView, PRDiff, PRChecks, PRFiles, IssueOpen, IssueComment, IssueReopen},
}

// CI is the declaration of the connector of ci.report.
var CI = kit.Connector{
	Name: "ci",
	Ops:  []kit.Op{CIReport},
}

// Connectors lists both.
var Connectors = []kit.Connector{Connector, CI}

// repoTarget is a repository: `owner/name`, from --repo or the git remote.
var repoTarget = kit.Target{Adapter: Adapter, Repo: true}

// prTarget is one pull request: `owner/name#N`.
var prTarget = kit.Target{Adapter: Adapter, Repo: true, Positional: "n", Why: "the PR number must be a positive integer"}

// issueTarget is one issue: `owner/name#N`.
var issueTarget = kit.Target{Adapter: Adapter, Repo: true, Positional: "n", Why: "the issue number must be a positive integer"}

// expectedHead is the optional --expected-head of the reads.
var expectedHead = kit.Param{
	Name: "expected_head_sha", Kind: kit.String, Pattern: HeadSHAPattern, CLIPattern: SHAPattern,
	Why: "--expected-head must be a 40-character lowercase hex sha", Flag: "expected-head", Placeholder: "sha",
	Help: "fail if the PR's head is not this sha (40 lowercase hex characters)",
}

// PROpen is pr.open. Its command stays hand-written: `head` is read from the
// current git branch when --branch is left out.
var PROpen = kit.Op{
	Name:          NamePROpen,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Open a pull request from the run's branch.",
	Usage:         "chap pr open --title <t> [--branch <b>] [--base <b>] [--body <b>] [--draft]",
	RatePerMinute: 6,
	Doc:           "Phase 1 shape for `pr.open` (owned by L1-09). `head` must equal the token's `task_scope.branch`, `base` its `task_scope.base`.",
	Target:        repoTarget,
	Params: []kit.Param{
		{Name: "title", Kind: kit.String, Required: true, MinLength: 1, MaxLength: TitleMax},
		{Name: "body", Kind: kit.Text, MaxLength: PRBodyMax},
		{Name: "head", Kind: kit.String, Required: true, Unbounded: true},
		{Name: "base", Kind: kit.String, Required: true, Unbounded: true},
		{Name: "draft", Kind: kit.Bool},
	},
	CLI: kit.CLI{Custom: true},
}

// PRUpdate is pr.update.
var PRUpdate = kit.Op{
	Name:          NamePRUpdate,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Update a PR title or body, or update its branch.",
	Usage:         "chap pr update <n> --expected-head <sha> [--title <t>] [--body <b>]",
	RatePerMinute: 12,
	Doc:           "Phase 1 shape for `pr.update` (owned by L1-10). `expected_head_sha` is required.",
	Target:        prTarget,
	Params: []kit.Param{
		{Name: "number", Kind: kit.Int, Required: true, Min: 1, FromRef: true},
		{Name: "expected_head_sha", Kind: kit.String, Required: true, Pattern: SHAPattern,
			Why: "--expected-head must be a 40-character lowercase hex sha", Flag: "expected-head", Placeholder: "sha",
			Help: "the PR's head sha you last saw (required)"},
		{Name: "title", Kind: kit.String, MinLength: 1, MaxLength: TitleMax, Placeholder: "t", Help: "new title"},
		{Name: "body", Kind: kit.Text, MaxLength: PRBodyMax},
		{Name: "update_branch", Kind: kit.Bool, Flag: "update-branch", Help: "update the PR branch from its base"},
	},
	CLI: kit.CLI{Summary: "update a PR's title or body, or its branch"},
}

// PRMerge is pr.merge. It is the one operation here that changes the
// repository for good, and its command stays hand-written: the merge method is
// fixed by the command, the base defaults to main, and the sha flag is named
// --head. The class is pinned in internal/connectors/declared.
var PRMerge = kit.Op{
	Name:          NamePRMerge,
	Class:         kit.Gated,
	Reversibility: kit.Compensable,
	Summary:       "Merge a PR when verify is green on its exact head.",
	Usage:         "chap pr merge <n> --head <sha> [--dry-run]",
	RatePerMinute: 6,
	Doc:           "Phase 1 shape for `pr.merge` (owned by L1-10; the spec's reference example). Target is `{adapter: github, ref: \"owner/repo#N\"}`.",
	Target:        prTarget,
	Params: []kit.Param{
		{Name: "base", Kind: kit.String, Required: true, Unbounded: true},
		{Name: "head_sha", Kind: kit.String, Required: true, Pattern: SHAPattern},
		{Name: "method", Kind: kit.String, Required: true, Const: "squash"},
	},
	CLI: kit.CLI{Custom: true},
}

// PRView is pr.view.
var PRView = kit.Op{
	Name:          NamePRView,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Read a PR's title, body, state, head, base, mergeability.",
	Usage:         "chap pr view <n> [--repo owner/name]",
	RatePerMinute: 30,
	Doc:           "Phase 1 shape for `pr.view` (ADR-002 amendment 12). Target is `{adapter: github, ref: \"owner/repo#N\"}`; the repository must be the project's. No params. Read-only; only the orchestrator token asks. The result holds number, title, body (cut at 64 KiB, `body_truncated`), state, draft, merged, author, labels, head {ref, sha, repo, fork}, base {ref, sha}, mergeable (null while GitHub computes it), mergeable_state, url and the counts.",
	Target:        prTarget,
	CLI: kit.CLI{
		Summary: "read a PR's title, body, state, head, base, mergeability (orchestrator only)",
		DryRun:  "check the request and the policy only; read nothing from GitHub",
	},
}

// PRDiff is pr.diff.
var PRDiff = kit.Op{
	Name:          NamePRDiff,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Read a PR's unified diff, capped at 256 KiB.",
	Usage:         "chap pr diff <n> [--expected-head <sha>] [--repo owner/name]",
	RatePerMinute: 12,
	Doc:           "Phase 1 shape for `pr.diff` (ADR-002 amendment 12). Target as for `pr.view`. The result holds `diff` (cut at a line end at 256 KiB: `truncated`, `size`, `returned`, `cap`) and the `head_sha` it was read at. With `expected_head_sha` the op fails, and says the new head, if the head moved.",
	Target:        prTarget,
	Params:        []kit.Param{expectedHead},
	CLI: kit.CLI{
		Summary: "read a PR's unified diff, capped at 256 KiB (orchestrator only)",
		DryRun:  "check the request and the policy only; read nothing from GitHub",
	},
}

// PRChecks is pr.checks.
var PRChecks = kit.Op{
	Name:          NamePRChecks,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Read the check runs on a PR's head commit.",
	Usage:         "chap pr checks <n> [--expected-head <sha>] [--repo owner/name]",
	RatePerMinute: 30,
	Doc:           "Phase 1 shape for `pr.checks` (ADR-002 amendment 12). Target as for `pr.view`. The result holds the latest check run of each name on the head commit (id, name, status, conclusion, app_id, url, started_at) and a `summary` of counts (total, passed, failed, pending, other).",
	Target:        prTarget,
	Params:        []kit.Param{expectedHead},
	CLI: kit.CLI{
		Summary: "read the check runs on a PR's head commit (orchestrator only)",
		DryRun:  "check the request and the policy only; read nothing from GitHub",
	},
}

// PRFiles is pr.files.
var PRFiles = kit.Op{
	Name:          NamePRFiles,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "List a PR's changed files, one page at a time.",
	Usage:         "chap pr files <n> [--page <p>] [--per-page <n>] [--expected-head <sha>]",
	RatePerMinute: 30,
	Doc:           "Phase 1 shape for `pr.files` (ADR-002 amendment 12). Target as for `pr.view`. One page of the changed files (no patches; `pr.diff` has them): filename, previous_filename, status, additions, deletions, has_patch. GitHub lists at most 3000 files.",
	Target:        prTarget,
	Params: []kit.Param{
		{Name: "page", Kind: kit.Int, Min: 1, Default: 1, Placeholder: "p", Help: "page of the file list, from 1 (default 1)"},
		{Name: "per_page", Kind: kit.Int, Min: 1, Max: FilesMaxPerPage, Default: FilesPerPage, Flag: "per-page", Placeholder: "n",
			Help: "files per page, 1 to 100 (default 30)"},
		expectedHead,
	},
	CLI: kit.CLI{
		Summary: "list a PR's changed files, one page at a time (orchestrator only)",
		DryRun:  "check the request and the policy only; read nothing from GitHub",
	},
}

// IssueOpen is issue.open. Its command stays hand-written: the usage line
// names the label the error watcher must give, and the flag is a list.
var IssueOpen = kit.Op{
	Name:          NameIssueOpen,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Open an issue labelled source:error-watcher.",
	Usage:         "chap issue open --title <t> --label source:error-watcher [--body <b>]",
	RatePerMinute: 6,
	Doc:           "Phase 1 shape for `issue.open`. Target is `{adapter: github, ref: \"owner/repo\"}`; the repository must be the project's. `labels` must include `source:error-watcher`. Only the orchestrator token asks.",
	Target:        repoTarget,
	Params: []kit.Param{
		{Name: "title", Kind: kit.String, Required: true, MinLength: 1, MaxLength: TitleMax},
		{Name: "body", Kind: kit.Text, MaxLength: IssueBodyMax},
		{Name: "labels", Kind: kit.List, Required: true, MinItems: 1, MaxItems: IssueLabelsMax, MinLength: 1, MaxLength: IssueLabelMax},
	},
	CLI: kit.CLI{Custom: true},
}

// IssueComment is issue.comment.
var IssueComment = kit.Op{
	Name:          NameIssueComment,
	Class:         kit.Routine,
	Reversibility: kit.Compensable,
	Summary:       "Comment on an issue labelled source:error-watcher.",
	Usage:         "chap issue comment <n> --body <b>",
	RatePerMinute: 6,
	Doc:           "Phase 1 shape for `issue.comment`. Target is `{adapter: github, ref: \"owner/repo#N\"}`; issue N must carry `source:error-watcher`.",
	Target:        issueTarget,
	Params: []kit.Param{
		{Name: "body", Kind: kit.Text, Required: true, MinLength: 1, MaxLength: IssueBodyMax},
	},
	CLI: kit.CLI{Summary: "comment on an issue labelled source:error-watcher"},
}

// IssueReopen is issue.reopen.
var IssueReopen = kit.Op{
	Name:          NameIssueReopen,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Reopen an issue labelled source:error-watcher.",
	Usage:         "chap issue reopen <n>",
	RatePerMinute: 6,
	Doc:           "Phase 1 shape for `issue.reopen`. Target is `{adapter: github, ref: \"owner/repo#N\"}`; issue N must carry `source:error-watcher`. No params.",
	Target:        issueTarget,
	CLI:           kit.CLI{Summary: "reopen an issue labelled source:error-watcher"},
}

// CIReport is ci.report.
var CIReport = kit.Op{
	Name:          NameCIReport,
	Class:         kit.Routine,
	Reversibility: kit.Reversible,
	Summary:       "Post a finished local CI run's result as a check run.",
	Usage:         "chap ci report <run-id>",
	RatePerMinute: 6,
	Doc:           "ADR-002 amendment 10. Target is `{adapter: runner, ref: \"<run_id>\"}`, the same run ID as `run_id`. Chaperone reads the repository, the exact commit and the outcome from its own record of the run; the request carries nothing else. Orchestrator only; a `ci` run that has ended.",
	Target: kit.Target{
		Adapter: CIAdapter, Pattern: RunIDPattern, Why: "%q is not a run id like r-7f3a", Positional: "run-id",
	},
	Params: []kit.Param{
		{Name: "run_id", Kind: kit.String, Required: true, Pattern: RunIDPattern, FromRef: true},
	},
	CLI: kit.CLI{
		Summary: "post a finished ci run's result to GitHub as a check run (orchestrator only)",
		DryRun:  "check the run and the policy only; post nothing",
	},
}
