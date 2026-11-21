package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One golden file per case under testdata/golden: the command line, the exit
// code, the request chap sent to the fake chapd (token never shown, only its
// kind) and everything chap printed. Regenerate with `go test ./cmd/chap -update`
// and read the diff: it is the interface.

const (
	sha1   = "0588aa4ee0116267162e895016bcfda9ec3a3e2c"
	origin = "https://github.com/acme/shop.git"
)

var gitOrigin = map[string]string{
	"config --get remote.origin.url": origin,
	"rev-parse --abbrev-ref HEAD":    "agent/r-7f3a",
}

type golden struct {
	name string
	args []string
	env  env     // chapd is filled in from ans
	ans  *answer // nil: chap must not call chapd
}

func ok200(fixture string) *answer { return &answer{status: 200, fixture: fixture} }
func ok202(fixture string) *answer { return &answer{status: 202, fixture: fixture} }
func withStatus(status int, fixture string) *answer {
	return &answer{status: status, fixture: fixture}
}

var goldenCases = []golden{
	// pr
	{name: "pr-open", args: []string{"pr", "open", "--title", "docs: fix typo", "--body-file", "/work/body.md", "--draft"},
		env: env{git: gitOrigin, fs: map[string]string{"/work/body.md": "Fixes the typo.\n"}}, ans: ok200("op-pr-open")},
	{name: "pr-open-json-orchestrator", args: []string{"pr", "open", "--title", "docs: fix typo", "--repo", "acme/shop", "--branch", "agent/r-7f3a", "--base", "develop", "--project", "acme-shop", "--json"},
		env: env{token: "orch"}, ans: ok200("op-pr-open")},
	{name: "pr-open-no-title", args: []string{"pr", "open"}, env: env{git: gitOrigin}},
	{name: "pr-open-no-repo", args: []string{"pr", "open", "--title", "x"}, env: env{}},
	{name: "pr-open-refused-at-release", args: []string{"pr", "open", "--title", "docs: fix typo"},
		env: env{git: gitOrigin}, ans: ok200("op-pr-open-refused")},
	{name: "pr-update", args: []string{"pr", "update", "214", "--expected-head", sha1, "--title", "fix: x", "--repo", "acme/shop", "--update-branch"},
		env: env{}, ans: ok200("op-pr-update")},
	{name: "pr-update-bad-head", args: []string{"pr", "update", "214", "--expected-head", "abc", "--repo", "acme/shop"}},
	// issue (the error watcher)
	{name: "issue-open", args: []string{"issue", "open", "--title", "TypeError in /api/orders", "--label", "source:error-watcher,bug", "--body-file", "/work/body.md", "--repo", "example-org/storefront", "--project", "storefront"},
		env: env{token: "orch", fs: map[string]string{"/work/body.md": "Seen 3 times.\n"}}, ans: ok200("op-issue-open")},
	{name: "issue-open-no-label", args: []string{"issue", "open", "--title", "x", "--repo", "example-org/storefront"}, env: env{token: "orch"}},
	{name: "issue-open-no-title", args: []string{"issue", "open", "--label", "source:error-watcher", "--repo", "example-org/storefront"}, env: env{token: "orch"}},
	{name: "issue-comment", args: []string{"issue", "comment", "301", "--body", "Seen again.", "--repo", "example-org/storefront", "--project", "storefront", "--json"},
		env: env{token: "orch"}, ans: ok200("op-issue-comment")},
	{name: "issue-comment-no-body", args: []string{"issue", "comment", "301", "--repo", "example-org/storefront"}, env: env{token: "orch"}},
	{name: "issue-comment-bad-number", args: []string{"issue", "comment", "x", "--body", "y", "--repo", "example-org/storefront"}, env: env{token: "orch"}},
	{name: "issue-reopen", args: []string{"issue", "reopen", "301", "--repo", "example-org/storefront", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-issue-reopen")},
	{name: "pr-merge", args: []string{"pr", "merge", "214", "--head", sha1},
		env: env{git: gitOrigin}, ans: ok200("op-pr-merge-succeeded")},
	{name: "pr-merge-flags-first", args: []string{"pr", "merge", "--head", sha1, "--repo", "acme/shop", "--reason", "CI green on this head", "214"},
		ans: ok200("op-pr-merge-succeeded")},
	{name: "pr-merge-refused", args: []string{"pr", "merge", "214", "--head", sha1, "--repo", "acme/shop"},
		ans: ok200("op-pr-merge-refused")},
	{name: "pr-merge-dry-run-allow", args: []string{"pr", "merge", "214", "--head", sha1, "--repo", "acme/shop", "--dry-run"},
		ans: ok200("dryrun-allow")},
	{name: "pr-merge-dry-run-approval", args: []string{"pr", "merge", "214", "--head", sha1, "--repo", "acme/shop", "--dry-run"},
		env: env{token: "orch", extra: map[string]string{"CHAP_PROJECT": "acme-shop"}}, ans: ok200("dryrun-approval")},
	{name: "pr-merge-denied-orchestrator", args: []string{"pr", "merge", "214", "--head", sha1, "--repo", "acme/shop", "--project", "acme-shop"},
		env: env{token: "orch"}, ans: withStatus(403, "api:denial-orchestrator-approval-required")},
	{name: "pr-merge-resume-approval", args: []string{"pr", "merge", "214", "--head", sha1, "--repo", "acme/shop", "--approval", "a-8m2q4x", "--wait", "20"},
		ans: ok202("op-pr-merge-approval-pending")},
	// ci report
	{name: "ci-report", args: []string{"ci", "report", "r-9c1d", "--project", "chaperone"},
		env: env{token: "orch"}, ans: ok200("op-ci-report")},
	{name: "ci-report-dry-run", args: []string{"ci", "report", "r-9c1d", "--project", "chaperone", "--dry-run"},
		env: env{token: "orch"}, ans: ok200("dryrun-ci-report")},
	{name: "ci-report-bad-run-id", args: []string{"ci", "report", "214", "--project", "chaperone"}, env: env{token: "orch"}},
	{name: "ci-report-no-run-id", args: []string{"ci", "report", "--project", "chaperone"}, env: env{token: "orch"}},
	// pr view, diff, checks, files (ADR-002 amendment 12): read-only, orchestrator only
	{name: "pr-view", args: []string{"pr", "view", "214", "--repo", "example-org/storefront", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-pr-view")},
	{name: "pr-view-json", args: []string{"pr", "view", "214", "--repo", "example-org/storefront", "--project", "storefront", "--json"},
		env: env{token: "orch"}, ans: ok200("op-pr-view")},
	{name: "pr-view-dry-run", args: []string{"pr", "view", "214", "--repo", "example-org/storefront", "--project", "storefront", "--dry-run"},
		env: env{token: "orch"}, ans: ok200("dryrun-pr-view")},
	{name: "pr-view-disabled", args: []string{"pr", "view", "214", "--repo", "example-org/storefront", "--project", "storefront"},
		env: env{token: "orch"}, ans: withStatus(403, "denial-pr-view-disabled")},
	{name: "pr-view-bad-number", args: []string{"pr", "view", "x", "--repo", "example-org/storefront"}, env: env{token: "orch"}},
	{name: "pr-view-git-remote", args: []string{"pr", "view", "214", "--project", "storefront"},
		env: env{token: "orch", git: gitOrigin}, ans: ok200("op-pr-view")},
	{name: "pr-diff", args: []string{"pr", "diff", "214", "--expected-head", sha1, "--repo", "example-org/storefront", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-pr-diff")},
	{name: "pr-diff-head-moved", args: []string{"pr", "diff", "214", "--expected-head", sha1, "--repo", "example-org/storefront", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-pr-diff-head-moved")},
	{name: "pr-diff-bad-head", args: []string{"pr", "diff", "214", "--expected-head", "main", "--repo", "example-org/storefront"}, env: env{token: "orch"}},
	{name: "pr-checks", args: []string{"pr", "checks", "214", "--repo", "example-org/storefront", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-pr-checks")},
	{name: "pr-files", args: []string{"pr", "files", "214", "--page", "2", "--per-page", "2", "--repo", "example-org/storefront", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-pr-files")},
	{name: "pr-files-bad-page", args: []string{"pr", "files", "214", "--page", "-1", "--repo", "example-org/storefront"}, env: env{token: "orch"}},
	{name: "pr-files-per-page-too-big", args: []string{"pr", "files", "214", "--per-page", "101", "--repo", "example-org/storefront"}, env: env{token: "orch"}},

	{name: "pr-merge-bad-number", args: []string{"pr", "merge", "0", "--head", sha1, "--repo", "acme/shop"}},

	// health, logs, deploy
	{name: "health", args: []string{"health"}, ans: ok200("op-health")},
	{name: "health-json", args: []string{"health", "--json"}, ans: ok200("op-health")},
	{name: "health-rate-limited", args: []string{"health"}, ans: &answer{status: 429, fixture: "api:denial-run-rate-limited", header: map[string]string{"Retry-After": "12"}}},
	{name: "logs", args: []string{"logs", "web", "--lines", "2"}, ans: ok200("op-logs")},
	{name: "logs-bad-source", args: []string{"logs", "syslog"}},
	{name: "deploy-executing", args: []string{"deploy", sha1, "--wait", "5"}, env: env{token: "orch"}, ans: ok202("op-deploy-executing")},
	{name: "deploy-disabled", args: []string{"deploy", sha1}, ans: withStatus(403, "api:denial-run-op-disabled")},
	{name: "deploy-approval-required", args: []string{"deploy", sha1, "--project", "acme-shop", "--reason", "ship the checkout fix"},
		env: env{token: "orch"}, ans: withStatus(403, "api:denial-orchestrator-approval-required")},
	{name: "deploy-unconfirmed", args: []string{"deploy", sha1}, ans: ok200("op-succeeded-unconfirmed")},
	{name: "deploy-bad-sha", args: []string{"deploy", "main"}},

	// mail, drive
	{name: "mail-send", args: []string{"mail", "send", "--from", "operator@example.com", "--to", "a@example.com,b@example.com", "--to", "c@example.com", "--subject", "Launch", "--body-file", "/work/mail.txt", "--project", "acme-shop"},
		env: env{token: "orch", fs: map[string]string{"/work/mail.txt": "We shipped.\n"}}, ans: ok202("op-mail-pending")},
	{name: "mail-send-stdin", args: []string{"mail", "send", "--from", "operator@example.com", "--to", "a@example.com", "--subject", "Launch", "--body-file", "-", "--project", "acme-shop"},
		env: env{token: "orch", stdin: "from stdin\n"}, ans: ok202("op-mail-pending")},
	{name: "mail-send-missing", args: []string{"mail", "send", "--to", "a@example.com"}},
	{name: "mail-send-resend", args: []string{"mail", "send", "--via", "resend", "--from", "alerts@mail.example.com", "--to", "ops@example.com", "--cc", "dev@example.com", "--subject", "Launch", "--body-file", "/work/mail.txt", "--project", "acme-shop"},
		env: env{token: "orch", fs: map[string]string{"/work/mail.txt": "We shipped.\n"}}, ans: ok202("op-mail-pending")},
	{name: "mail-send-bad-via", args: []string{"mail", "send", "--via", "smtp", "--from", "a@example.com", "--to", "b@example.com", "--subject", "x", "--body-file", "-"}, env: env{stdin: "x\n"}},
	{name: "drive-share", args: []string{"drive", "share", "1AbCdEf", "--from", "operator@example.com", "--name", "Q3 plan", "--to", "a@example.com", "--role", "reader", "--project", "acme-shop"},
		env: env{token: "orch"}, ans: ok202("op-drive-pending")},

	// request
	{name: "request-op", args: []string{"request", "op", "deploy", "--reason", "ship the checkout fix", "--params", `{"sha":"` + sha1 + `"}`, "--project", "acme-shop"},
		env: env{token: "orch"}, ans: ok202("op-deploy-pending")},
	{name: "request-op-explicit-target", args: []string{"request", "op", "pr.merge", "--reason", "needed", "--target", "github:acme/shop#214", "--params", `{"base":"main","head_sha":"` + sha1 + `","method":"squash"}`, "--project", "acme-shop"},
		env: env{token: "orch"}, ans: ok202("op-pr-merge-approval-pending")},
	{name: "request-op-json", args: []string{"request", "op", "deploy", "--reason", "x", "--params", `{"sha":"` + sha1 + `"}`, "--json"}, ans: ok202("op-deploy-pending")},
	// intake (the Linear operator board)
	{name: "intake-list", args: []string{"intake", "list", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-intake-list")},
	{name: "intake-list-refresh-team-closed", args: []string{"intake", "list", "--refresh", "--closed", "--team", "SHOP", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-intake-list")},
	{name: "intake-list-json", args: []string{"intake", "list", "--project", "storefront", "--json"}, env: env{token: "orch"}, ans: ok200("op-intake-list")},
	{name: "intake-list-bad-team", args: []string{"intake", "list", "--team", "ops"}, env: env{token: "orch"}},
	{name: "intake-states", args: []string{"intake", "states", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-intake-states")},
	{name: "intake-comment", args: []string{"intake", "comment", "SHOP-12", "--body", "Picked up by the orchestrator: https://github.com/example-org/storefront/issues/401", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-intake-comment")},
	{name: "intake-comment-body-file", args: []string{"intake", "comment", "SHOP-12", "--body-file", "/work/note.md", "--project", "storefront"},
		env: env{token: "orch", fs: map[string]string{"/work/note.md": "Picked up by the orchestrator.\n"}}, ans: ok200("op-intake-comment")},
	{name: "intake-comment-no-body", args: []string{"intake", "comment", "SHOP-12"}, env: env{token: "orch"}},
	{name: "intake-comment-bad-issue", args: []string{"intake", "comment", "ops-12", "--body", "x"}, env: env{token: "orch"}},
	{name: "intake-move", args: []string{"intake", "move", "SHOP-12", "--state", "Handed to engineering", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-intake-move")},
	{name: "intake-move-failed", args: []string{"intake", "move", "SHOP-12", "--state", "Blocked", "--project", "storefront"},
		env: env{token: "orch"}, ans: ok200("op-intake-move-failed")},
	{name: "intake-move-no-state", args: []string{"intake", "move", "SHOP-12"}, env: env{token: "orch"}},
	{name: "intake-move-disabled", args: []string{"intake", "move", "SHOP-12", "--state", "Blocked", "--project", "storefront"},
		env: env{token: "orch"}, ans: withStatus(403, "api:denial-run-op-disabled")},
	// issue ops on Linear : a Linear identifier picks the connector
	{name: "issue-get", args: []string{"issue", "get", "AGT-12", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-issue-get")},
	{name: "issue-get-bad-issue", args: []string{"issue", "get", "301"}, env: env{token: "orch"}},
	{name: "issue-list", args: []string{"issue", "list", "--state", "started", "--label", "bug", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-issue-list")},
	{name: "issue-list-cursor-team-json", args: []string{"issue", "list", "--team", "AGT", "--cursor", "25", "--project", "storefront", "--json"}, env: env{token: "orch"}, ans: ok200("op-issue-list")},
	{name: "issue-list-bad-team", args: []string{"issue", "list", "--team", "agt"}, env: env{token: "orch"}},
	{name: "issue-comment-linear", args: []string{"issue", "comment", "AGT-12", "--body", "Looking at it.", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-issue-comment-linear")},
	{name: "issue-comment-linear-no-body", args: []string{"issue", "comment", "AGT-12"}, env: env{token: "orch"}},
	{name: "issue-label-add", args: []string{"issue", "label", "AGT-12", "--add", "triaged", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-issue-label")},
	{name: "issue-label-neither", args: []string{"issue", "label", "AGT-12"}, env: env{token: "orch"}},
	{name: "issue-label-both", args: []string{"issue", "label", "AGT-12", "--add", "a", "--remove", "b"}, env: env{token: "orch"}},
	{name: "issue-move-linear", args: []string{"issue", "move", "AGT-12", "--state", "In Progress", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-issue-move")},
	{name: "issue-move-no-state", args: []string{"issue", "move", "AGT-12"}, env: env{token: "orch"}},
	{name: "issue-link", args: []string{"issue", "link", "AGT-12", "--url", "https://github.com/example-org/storefront/pull/12", "--title", "The fix", "--project", "storefront"}, env: env{token: "orch"}, ans: ok200("op-issue-link")},
	{name: "issue-link-no-url", args: []string{"issue", "link", "AGT-12"}, env: env{token: "orch"}},
	{name: "request-op-no-reason", args: []string{"request", "op", "deploy"}},
	{name: "request-op-unknown-target", args: []string{"request", "op", "pr.merge", "--reason", "x"}},
	{name: "request-op-bad-params", args: []string{"request", "op", "deploy", "--reason", "x", "--params", "[1]"}},
	{name: "request-net", args: []string{"request", "net", "api.example.com", "--reason", "fetch the API schema"}, ans: withStatus(400, "err-params-net")},
	{name: "request-pkg", args: []string{"request", "pkg", "left-pad-ng@2.0.1", "--reason", "needed"}, ans: withStatus(400, "err-params-net")},
	{name: "request-scope", args: []string{"request", "scope", "--reason", "needs the docs folder"}, ans: withStatus(400, "err-params-net")},
	{name: "request-not-in-token", args: []string{"request", "op", "pr.merge", "--reason", "x", "--target", "github:acme/shop#214"}, ans: withStatus(403, "api:denial-run-op-not-in-token")},
	{name: "request-flag-on-command", args: []string{"pr", "merge", "214", "--head", sha1, "--repo", "acme/shop", "--project", "acme-shop", "--request", "--reason", "CI is green on this head"},
		env: env{token: "orch"}, ans: ok202("op-pr-merge-approval-pending")},
	{name: "request-flag-no-reason", args: []string{"deploy", sha1, "--request"}},
	{name: "request-flag-with-dry-run", args: []string{"pr", "merge", "214", "--head", sha1, "--repo", "acme/shop", "--request", "--reason", "x", "--dry-run"}},
	{name: "wait-out-of-range", args: []string{"health", "--wait", "99"}},

	// op show
	{name: "op-show-executing", args: []string{"op", "show", "q-9z8y7x", "--wait", "30", "--since", "executing"}, ans: ok200("op-deploy-executing")},
	{name: "op-show-succeeded", args: []string{"op", "show", "q-3k9d2m"}, ans: ok200("op-pr-merge-succeeded")},
	{name: "op-show-refused-with-reason", args: []string{"op", "show", "q-wcjx67"}, ans: ok200("op-pr-open-refused")},
	{name: "op-show-refused-no-reason", args: []string{"op", "show", "q-w0ss2r"}, ans: ok200("op-pr-open-refused-no-reason")},
	{name: "op-show-not-found", args: []string{"op", "show", "q-3k9d2m"}, ans: withStatus(404, "err-not-found")},
	{name: "op-show-conflict", args: []string{"op", "show", "q-3k9d2m"}, ans: withStatus(409, "err-conflict")},
	{name: "op-show-bad-id", args: []string{"op", "show", "214"}},

	// approve, ledger, runs, vault
	{name: "approve-list", args: []string{"approve", "list"}, env: env{token: "orch"}, ans: ok200("approvals-page")},
	{name: "approve-list-empty", args: []string{"approve", "list", "--state", "pending", "--limit", "5"}, ans: ok200("approvals-empty")},
	{name: "approve-list-json", args: []string{"approve", "list", "--json"}, ans: ok200("approvals-page")},
	{name: "approve-list-bad-state", args: []string{"approve", "list", "--state", "done"}},
	{name: "ledger-verify", args: []string{"ledger", "verify"}, env: env{token: "orch"}, ans: ok200("ledger-ok")},
	{name: "ledger-verify-broken", args: []string{"ledger", "verify", "--against-export"}, env: env{token: "orch"}, ans: ok200("ledger-broken")},
	{name: "ledger-verify-anchor", args: []string{"ledger", "verify", "--anchor"}, env: env{token: "orch"}, ans: ok200("ledger-anchor-ok")},
	{name: "ledger-verify-anchor-restored-copy", args: []string{"ledger", "verify", "--anchor", "--anchor-file", "/restore/chaperone.main.jsonl", "--anchor-pub", "PUBKEY"},
		env: env{token: "orch", fs: map[string]string{"/restore/chaperone.main.jsonl": "{\"v\":1}\n\n{\"v\":2}\n"}}, ans: ok200("ledger-anchor-rewritten")},
	{name: "ledger-verify-anchor-file-missing", args: []string{"ledger", "verify", "--anchor", "--anchor-file", "/restore/none.jsonl"}, env: env{token: "orch"}},
	{name: "ledger-verify-anchor-file-without-anchor", args: []string{"ledger", "verify", "--anchor-file", "/restore/chaperone.main.jsonl"}, env: env{token: "orch"}},
	{name: "ledger-verify-run-token", args: []string{"ledger", "verify"}, ans: withStatus(403, "api:denial-run-op-not-in-token")},
	{name: "runs-revoke", args: []string{"runs", "revoke", "r-7f3a"}, env: env{token: "orch"}, ans: ok200("run-revoked")},
	{name: "runs-revoke-all", args: []string{"runs", "revoke", "--all"}, env: env{token: "orch"}, ans: ok200("runs-revoked-all")},
	{name: "runs-revoke-none", args: []string{"runs", "revoke"}},
	{name: "runs-revoke-bad-id", args: []string{"runs", "revoke", "7f3a"}},
	{name: "vault-status", args: []string{"vault", "status"}, env: env{token: "orch"}, ans: ok200("vault-status")},
	{name: "vault-status-uninitialized", args: []string{"vault", "status"}, env: env{token: "orch"}, ans: ok200("vault-uninitialized")},

	// dev-token
	{name: "dev-token", args: []string{"dev-token", "--project", "acme-shop", "--repo", "acme/shop", "--branch", "agent/r-9a2b", "--path", "docs/**", "--path", "README.md", "--op", "pr.open", "--op", "health", "--minutes", "90", "--out", "run.token"},
		env: env{token: "orch"}, ans: withStatus(201, "devtoken")},
	{name: "dev-token-json", args: []string{"dev-token", "--project", "acme-shop", "--repo", "acme/shop", "--branch", "agent/r-9a2b", "--path", "docs/**", "--op", "pr.open", "--out", "run.token", "--json"},
		env: env{token: "orch"}, ans: withStatus(201, "devtoken")},
	{name: "dev-token-no-out", args: []string{"dev-token", "--project", "acme-shop", "--repo", "acme/shop", "--branch", "b", "--path", "docs/**", "--op", "pr.open"}},
	{name: "dev-token-run-token", args: []string{"dev-token", "--project", "acme-shop", "--repo", "acme/shop", "--branch", "b", "--path", "docs/**", "--op", "pr.open", "--out", "run.token"},
		ans: withStatus(403, "api:denial-run-op-not-in-token")},

	// git setup
	{name: "git-setup", args: []string{"git", "setup"}},
	{name: "git-setup-global", args: []string{"git", "setup", "--global"}},

	// manual
	{name: "manual-docs", args: []string{"manual", "--profile", "docs"}, ans: ok200("catalog:docs")},
	{name: "manual-code", args: []string{"manual"}, env: env{token: "orch"}, ans: ok200("catalog:code")},
	{name: "manual-json", args: []string{"manual", "--profile", "docs", "--json"}, ans: ok200("catalog:docs")},
	{name: "manual-unknown-profile", args: []string{"manual", "--profile", "ops"}},

	// denials and failures, rendered the same for every command
	{name: "denied-not-in-token", args: []string{"health"}, ans: withStatus(403, "api:denial-run-op-not-in-token")},
	{name: "denied-not-in-token-json", args: []string{"health", "--json"}, ans: withStatus(403, "api:denial-run-op-not-in-token")},
	{name: "denied-thrash", args: []string{"deploy", sha1}, ans: withStatus(403, "denial-thrash")},
	{name: "denied-control-characters", args: []string{"deploy", sha1}, ans: withStatus(403, "denial-injection")},
	{name: "denied-token-revoked", args: []string{"health"}, env: env{token: "orch"}, ans: withStatus(401, "api:denial-orchestrator-token-revoked")},
	{name: "denied-ci-stale", args: []string{"health"}, env: env{token: "orch"}, ans: withStatus(403, "denial-ci-stale")},
	{name: "denied-title-edited", args: []string{"health"}, env: env{token: "orch"}, ans: withStatus(403, "denial-title-edited")},
	{name: "denied-approval-flood", args: []string{"health"}, env: env{token: "orch"}, ans: &answer{status: 429, fixture: "denial-approval-flood", header: map[string]string{"Retry-After": "60"}}},
	{name: "denied-token-expired", args: []string{"health"}, env: env{token: "orch"}, ans: withStatus(401, "denial-token-expired")},
	{name: "denied-token-expired-run", args: []string{"health"}, ans: withStatus(401, "denial-run-token-expired")},
	{name: "denied-token-revoked-run", args: []string{"health"}, ans: withStatus(401, "denial-run-token-revoked")},
	{name: "auth-error", args: []string{"health"}, ans: withStatus(401, "err-auth")},
	{name: "unavailable", args: []string{"health"}, ans: withStatus(503, "err-unavailable")},
	{name: "token-echoed-by-server", args: []string{"deploy", sha1}, ans: withStatus(403, "denial-token-echo")},
	{name: "no-token", args: []string{"health"}, env: env{token: "none"}},
	{name: "chapd-not-loopback", args: []string{"health"}, env: env{extra: map[string]string{"CHAP_URL": "http://example.com:55398"}, notURL: true}},

	// the tree itself
	{name: "help", args: []string{"help"}},
	{name: "logo", args: []string{"logo"}},
	{name: "help-command", args: []string{"pr", "merge", "--help"}},
	{name: "unknown-command", args: []string{"frobnicate"}},
	{name: "unknown-verb", args: []string{"pr", "close"}},
	{name: "flag-no-such", args: []string{"health", "--token", "abc"}},
}

func quoteArgs(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'$") {
			a = fmt.Sprintf("%q", a)
		}
		parts[i] = a
	}
	return strings.Join(parts, " ")
}

func TestGolden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.env
			if tc.ans != nil {
				e.chapd = newFakeChapd(t, *tc.ans)
			}
			ta := newTestApp(t, e)
			exit := ta.run(tc.args)

			var b strings.Builder
			fmt.Fprintf(&b, "$ chap %s\nexit: %d\n", quoteArgs(tc.args), exit)
			if e.chapd != nil {
				if len(e.chapd.reqs) == 0 {
					b.WriteString("--- request\n(none)\n")
				}
				for _, r := range e.chapd.reqs {
					b.WriteString("--- request\n" + r + "\n")
				}
			} else {
				if len(ta.gitCalls) > 0 && strings.HasPrefix(tc.name, "git-setup") {
					b.WriteString("--- git\n" + strings.Join(ta.gitCalls, "\n") + "\n")
				}
				b.WriteString("--- request\n(none)\n")
			}
			for p, data := range ta.files {
				fmt.Fprintf(&b, "--- file\n%s (%d bytes)\n", p, len(data))
			}
			b.WriteString("--- stdout\n" + ta.out.String())
			b.WriteString("--- stderr\n" + ta.errb.String())
			got := b.String()

			// No golden output ever holds a token, and chap must have used
			// the one the case set up.
			for _, secret := range []string{testRunToken, testOrchToken, "c2lnbmF0dXJl", "chap_orch_Zm9v"} {
				if strings.Contains(got, secret) {
					t.Fatalf("output contains a token fragment %q:\n%s", secret, got)
				}
			}
			for _, d := range ta.files {
				if string(d) == "" {
					t.Error("empty file written")
				}
			}

			path := filepath.Join("testdata", "golden", tc.name+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Errorf("golden mismatch for %s\n--- got\n%s\n--- want\n%s", tc.name, got, want)
			}
		})
	}
}

// Every golden file has a case, so a deleted case cannot leave a stale file.
func TestNoOrphanGoldens(t *testing.T) {
	names := map[string]bool{}
	for _, tc := range goldenCases {
		if names[tc.name] {
			t.Errorf("duplicate case %q", tc.name)
		}
		names[tc.name] = true
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "golden", "*.golden"))
	for _, f := range files {
		if n := strings.TrimSuffix(filepath.Base(f), ".golden"); !names[n] {
			t.Errorf("%s has no case", f)
		}
	}
}
