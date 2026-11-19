package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// The commands that ask chapd for an op: POST /v0/ops (or /v0/approvals for
// `chap request`). Each builds {op, target, params} and nothing else; chapd
// computes op_hash, takes the requester from the token and decides.

var (
	shaRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repoRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$`)
	opNameRE  = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)
	targetRE  = regexp.MustCompile(`^([a-z][a-z0-9-]{0,38}):(.{1,300})$`)
	remoteRE  = regexp.MustCompile(`(?:github\.com[:/]|/git/)([A-Za-z0-9_][A-Za-z0-9._-]*)/([A-Za-z0-9_][A-Za-z0-9._-]*?)(?:\.git)?/?$`)
	logSource = map[string]bool{"web": true, "worker": true, "db": true, "tunnel": true}
)

// target is the op's target, as in the contract's Target schema.
type target struct {
	Adapter string `json:"adapter"`
	Ref     string `json:"ref"`
}

// Targets of the ops whose adapters are not written yet. [INFERENCE] The
// contract fixes the shape (adapter, ref) and says ParamsDeploy's target is
// `{adapter: wsl-host, ref: "<target>"}`; the names below are this CLI's
// choice until each adapter ticket (L1-11, L1-15, L1-16) names its own. They
// live in one table so changing one is a one-line edit, and chapd refuses a
// target it does not know as OP_PARAMS_INVALID, which chap prints.
var defaultTargets = map[string]target{
	"health": {"pilot", "health"},
	"logs":   {"wsl-host", "pilot"},
	"deploy": {"wsl-host", "pilot"},
}

// common holds the flags every op command takes.
type common struct {
	json     bool
	project  string
	reason   string
	approval string
	wait     int
	request  bool
}

func (c *common) register(fs *flag.FlagSet, a *app) {
	fs.BoolVar(&c.json, "json", false, "print chapd's JSON reply instead of text")
	fs.StringVar(&c.project, "project", strings.TrimSpace(a.getenv("CHAP_PROJECT")), "project slug (the orchestrator must name one; a run's is its token's) [env CHAP_PROJECT]")
	fs.StringVar(&c.reason, "reason", "", "why (shown on the approval card, never used for authorization)")
	fs.StringVar(&c.approval, "approval", "", "resume under this approval id (a-...)")
	fs.BoolVar(&c.request, "request", false, "create the approval card for this exact op instead of running it (needs --reason)")
	c.wait = -1 // not sent: chapd's default
	fs.Func("wait", "seconds to wait for a final state, 0 to 55 (default: chapd's)", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 55 {
			return errors.New("must be 0 to 55")
		}
		c.wait = n
		return nil
	})
}

func (c *common) check() error {
	if c.approval != "" && !regexp.MustCompile(`^a-[0-9a-z]{6,32}$`).MatchString(c.approval) {
		return errors.New("--approval must look like a-xxxxxx")
	}
	if c.request && c.reason == "" {
		return errors.New("--request needs --reason")
	}
	if c.request && c.approval != "" {
		return errors.New("--request and --approval do not go together")
	}
	return nil
}

// parse parses flags and positionals in any order. It returns done=true when
// the command is finished (help, or a usage error already printed).
func (a *app) parse(c *command, fs *flag.FlagSet, args []string, minPos, maxPos int) (pos []string, code int, done bool) {
	var rest []string
	for i, x := range args {
		if x == "--" {
			args, rest = args[:i], args[i+1:]
			break
		}
	}
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.Usage = func() {}
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				var h bytes.Buffer
				fmt.Fprintf(&h, "usage: %s\n%s\n", c.usage, c.summary)
				fs.SetOutput(&h)
				fs.PrintDefaults()
				a.out(h.String())
				return nil, exitOK, true
			}
			return nil, a.fail(exitUsage, "%s\nusage: %s", strings.TrimSpace(buf.String()), c.usage), true
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	pos = append(pos, rest...)
	if len(pos) < minPos || len(pos) > maxPos {
		return nil, a.fail(exitUsage, "usage: %s", c.usage), true
	}
	return pos, 0, false
}

func (a *app) usageErr(c *command, format string, args ...any) int {
	return a.fail(exitUsage, "%s\nusage: %s", fmt.Sprintf(format, args...), c.usage)
}

// opReq is one op to ask for.
type opReq struct {
	op     string
	target target
	params map[string]any
	dryRun bool
}

// ask is POST /v0/ops.
func (a *app) ask(co *common, r opReq) int {
	if co.request {
		if r.dryRun {
			return a.fail(exitUsage, "--request and --dry-run do not go together")
		}
		return a.approve(co, "op", r)
	}
	body := map[string]any{"op": r.op, "target": r.target, "params": r.params}
	if co.project != "" {
		body["project"] = co.project
	}
	if co.reason != "" {
		body["reason"] = co.reason
	}
	if co.approval != "" {
		body["approval_id"] = co.approval
	}
	if r.dryRun {
		body["dry_run"] = true
	}
	q := url.Values{}
	if co.wait >= 0 {
		q.Set("wait", strconv.Itoa(co.wait))
	}
	return a.do(co.json, "POST", "/v0/ops", q, body, func(rp *reply) rendered {
		var head struct {
			Type string `json:"type"`
		}
		json.Unmarshal(rp.body, &head)
		if head.Type == "dry_run" {
			var v verdict
			if err := json.Unmarshal(rp.body, &v); err != nil {
				return unreadable(err)
			}
			return rendered{human: renderVerdict(r.op, r.target.Ref, &v), code: verdictCode(&v)}
		}
		return renderOpReply(rp, opCode)
	})
}

func unreadable(err error) rendered {
	return rendered{human: "chap: chapd's reply cannot be read: " + err.Error() + "\n", code: exitFail}
}

func renderOpReply(rp *reply, code func(state string) int) rendered {
	var o op
	if err := json.Unmarshal(rp.body, &o); err != nil {
		return unreadable(err)
	}
	return rendered{human: renderOp(&o), code: code(o.State)}
}

// repoArg returns owner/name from --repo, else from the git remote `origin`.
func (a *app) repoArg(flagVal string) (string, error) {
	repo := flagVal
	if repo == "" {
		raw, err := a.git("config", "--get", "remote.origin.url")
		if err != nil || raw == "" {
			return "", errors.New("cannot tell the repository from git; pass --repo owner/name")
		}
		m := remoteRE.FindStringSubmatch(raw)
		if m == nil {
			return "", errors.New("the git remote origin is not a GitHub repository; pass --repo owner/name")
		}
		repo = m[1] + "/" + m[2]
	}
	if !repoRE.MatchString(repo) {
		return "", errors.New("--repo must be owner/name")
	}
	return repo, nil
}

func parsePR(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, errors.New("the PR number must be a positive integer")
	}
	return n, nil
}

// readText reads a --body-file; "-" is stdin.
func (a *app) readText(path string) (string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(a.stdin, maxBody+1))
	} else {
		data, err = a.readFile(path)
	}
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %v", path, err)
	}
	if len(data) > maxBody {
		return "", fmt.Errorf("%s is larger than %d bytes", path, maxBody)
	}
	return string(data), nil
}

// textFlags is --body / --body-file.
type textFlags struct{ body, bodyFile string }

func (t *textFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&t.body, "body", "", "text")
	fs.StringVar(&t.bodyFile, "body-file", "", "read the text from this file (- for stdin)")
}

func (t *textFlags) resolve(a *app) (text string, set bool, err error) {
	if t.body != "" && t.bodyFile != "" {
		return "", false, errors.New("use --body or --body-file, not both")
	}
	if t.bodyFile != "" {
		s, err := a.readText(t.bodyFile)
		return s, true, err
	}
	return t.body, t.body != "", nil
}

// listFlag is a repeatable flag; each use may carry a comma list.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}

func opCommands() []*command {
	return []*command{
		{path: "pr open", usage: "chap pr open --title <t> [--body <b> | --body-file <f>] [--draft] [--branch <b>] [--base <b>] [--repo owner/name]",
			summary: "open a pull request from the run's branch", run: cmdPrOpen},
		{path: "pr update", usage: "chap pr update <n> --expected-head <sha> [--title <t>] [--body <b> | --body-file <f>] [--update-branch] [--repo owner/name]",
			summary: "update a PR's title or body, or its branch", run: cmdPrUpdate},
		{path: "pr merge", usage: "chap pr merge <n> --head <sha> [--base <b>] [--repo owner/name] [--dry-run]",
			summary: "merge a PR when verify is green on its exact head", run: cmdPrMerge},
		{path: "pr view", usage: "chap pr view <n> [--repo owner/name] [--dry-run]",
			summary: "read a PR's title, body, state, head, base, mergeability (orchestrator only)", run: cmdPrView},
		{path: "pr diff", usage: "chap pr diff <n> [--expected-head <sha>] [--repo owner/name] [--dry-run]",
			summary: "read a PR's unified diff, capped at 256 KiB (orchestrator only)", run: cmdPrDiff},
		{path: "pr checks", usage: "chap pr checks <n> [--expected-head <sha>] [--repo owner/name] [--dry-run]",
			summary: "read the check runs on a PR's head commit (orchestrator only)", run: cmdPrChecks},
		{path: "pr files", usage: "chap pr files <n> [--page <p>] [--per-page <n>] [--expected-head <sha>] [--repo owner/name] [--dry-run]",
			summary: "list a PR's changed files, one page at a time (orchestrator only)", run: cmdPrFiles},
		{path: "ci report", usage: "chap ci report <run-id> [--dry-run]",
			summary: "post a finished ci run's result to GitHub as a check run (orchestrator only)", run: cmdCiReport},
		{path: "issue open", usage: "chap issue open --title <t> --label source:error-watcher [--label <l>] [--body <b> | --body-file <f>] [--repo owner/name]",
			summary: "open an issue labelled source:error-watcher", run: cmdIssueOpen},
		{path: "issue comment", usage: "chap issue comment <n> [--body <b> | --body-file <f>] [--repo owner/name]",
			summary: "comment on an issue labelled source:error-watcher", run: cmdIssueComment},
		{path: "issue reopen", usage: "chap issue reopen <n> [--repo owner/name]",
			summary: "reopen an issue labelled source:error-watcher", run: cmdIssueReopen},
		{path: "health", usage: "chap health",
			summary: "read the pilot's readiness status", run: cmdHealth},
		{path: "logs", usage: "chap logs <web|worker|db|tunnel> [--lines <n>]",
			summary: "read recent log lines from a fixed source", run: cmdLogs},
		{path: "deploy", usage: "chap deploy <sha>",
			summary: "deploy a commit to the pilot (needs one approval)", run: cmdDeploy},
		{path: "mail send", usage: "chap mail send --from <account> --to <a> [--to <b>] [--cc <c>] [--bcc <d>] --subject <s> --body-file <f>",
			summary: "send one email to allowlisted recipients (needs approval)", run: cmdMailSend},
		{path: "drive share", usage: "chap drive share <file-id> --from <account> --name <file-name> --to <a> [--to <b>] --role <r>",
			summary: "share one Drive file with allowlisted recipients (needs approval)", run: cmdDriveShare},
		{path: "request op", usage: "chap request op <op> --reason <why> [--params <json>] [--target <adapter>:<ref>]",
			summary: "create the approval card for an op", run: cmdRequestOp},
		{path: "request net", usage: "chap request net <host> --reason <why>",
			summary: "ask for network access (a the runner surface)", run: cmdRequestKind},
		{path: "request pkg", usage: "chap request pkg <name@version> --reason <why>",
			summary: "ask for a package (a the runner surface)", run: cmdRequestKind},
		{path: "request scope", usage: "chap request scope --reason <why>",
			summary: "ask for a wider task scope (a the runner surface)", run: cmdRequestKind},
	}
}

func cmdPrOpen(a *app, c *command, args []string) int {
	var co common
	var tf textFlags
	var title, branch, base, repo string
	var draft bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	tf.register(fs)
	fs.StringVar(&title, "title", "", "PR title, a Conventional Commit line (required)")
	fs.BoolVar(&draft, "draft", false, "open as a draft")
	fs.StringVar(&branch, "branch", "", "head branch (default: the current git branch)")
	fs.StringVar(&base, "base", "main", "base branch")
	fs.StringVar(&repo, "repo", "", "owner/name (default: from the git remote origin)")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	if title == "" {
		return a.usageErr(c, "--title is required")
	}
	text, hasBody, err := tf.resolve(a)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	r, err := a.repoArg(repo)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	if branch == "" {
		branch, err = a.git("rev-parse", "--abbrev-ref", "HEAD")
		if err != nil || branch == "" || branch == "HEAD" {
			return a.usageErr(c, "cannot tell the head branch from git; pass --branch")
		}
	}
	params := map[string]any{"title": title, "head": branch, "base": base}
	if hasBody {
		params["body"] = text
	}
	if draft {
		params["draft"] = true
	}
	return a.ask(&co, opReq{op: "pr.open", target: target{"github", r}, params: params})
}

func cmdPrUpdate(a *app, c *command, args []string) int {
	var co common
	var tf textFlags
	var title, expected, repo string
	var updateBranch bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	tf.register(fs)
	fs.StringVar(&title, "title", "", "new title")
	fs.StringVar(&expected, "expected-head", "", "the PR's head sha you last saw (required)")
	fs.BoolVar(&updateBranch, "update-branch", false, "update the PR branch from its base")
	fs.StringVar(&repo, "repo", "", "owner/name (default: from the git remote origin)")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	n, err := parsePR(pos[0])
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	if !shaRE.MatchString(expected) {
		return a.usageErr(c, "--expected-head must be a 40-character lowercase hex sha")
	}
	text, hasBody, err := tf.resolve(a)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	r, err := a.repoArg(repo)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	params := map[string]any{"number": n, "expected_head_sha": expected}
	if title != "" {
		params["title"] = title
	}
	if hasBody {
		params["body"] = text
	}
	if updateBranch {
		params["update_branch"] = true
	}
	return a.ask(&co, opReq{op: "pr.update", target: target{"github", fmt.Sprintf("%s#%d", r, n)}, params: params})
}

func cmdPrMerge(a *app, c *command, args []string) int {
	var co common
	var head, base, repo string
	var dry bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	fs.StringVar(&head, "head", "", "the PR's head sha the merge is for (required)")
	fs.StringVar(&base, "base", "main", "base branch")
	fs.StringVar(&repo, "repo", "", "owner/name (default: from the git remote origin)")
	fs.BoolVar(&dry, "dry-run", false, "evaluate policy and preconditions only; merge nothing")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	n, err := parsePR(pos[0])
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	if !shaRE.MatchString(head) {
		return a.usageErr(c, "--head must be a 40-character lowercase hex sha")
	}
	r, err := a.repoArg(repo)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	params := map[string]any{"base": base, "head_sha": head, "method": "squash"}
	return a.ask(&co, opReq{op: "pr.merge", target: target{"github", fmt.Sprintf("%s#%d", r, n)}, params: params, dryRun: dry})
}

// cmdCiReport asks chapd to state a finished `ci` run's result on GitHub. The request names the run and nothing else:
// chapd reads the repository, the commit and the outcome from its own record of the run.
func cmdCiReport(a *app, c *command, args []string) int {
	var co common
	var dry bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	fs.BoolVar(&dry, "dry-run", false, "check the run and the policy only; post nothing")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	if !runIDRE.MatchString(pos[0]) {
		return a.usageErr(c, "%q is not a run id like r-7f3a", pos[0])
	}
	return a.ask(&co, opReq{op: "ci.report", target: target{"runner", pos[0]}, params: map[string]any{"run_id": pos[0]}, dryRun: dry})
}

func cmdHealth(a *app, c *command, args []string) int {
	var co common
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	return a.ask(&co, opReq{op: "health", target: defaultTargets["health"], params: map[string]any{}})
}

func cmdLogs(a *app, c *command, args []string) int {
	var co common
	var lines int
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	fs.IntVar(&lines, "lines", 0, "how many recent lines, 1 to 500 (default: chapd's)")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	if !logSource[pos[0]] {
		return a.usageErr(c, "the source must be one of web, worker, db, tunnel")
	}
	params := map[string]any{"source": pos[0]}
	if lines != 0 {
		if lines < 1 || lines > 500 {
			return a.usageErr(c, "--lines must be 1 to 500")
		}
		params["lines"] = lines
	}
	return a.ask(&co, opReq{op: "logs", target: defaultTargets["logs"], params: params})
}

func cmdDeploy(a *app, c *command, args []string) int {
	var co common
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	if !shaRE.MatchString(pos[0]) {
		return a.usageErr(c, "the sha must be 40 lowercase hex characters")
	}
	return a.ask(&co, opReq{op: "deploy", target: defaultTargets["deploy"], params: map[string]any{"sha": pos[0]}})
}

func cmdMailSend(a *app, c *command, args []string) int {
	var co common
	var to, cc, bcc listFlag
	var subject, bodyFile, from string
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	fs.StringVar(&from, "from", "", "the Google account that sends, the address chapd connect google status prints (required)")
	fs.Var(&to, "to", "recipient (repeat, or comma-separated)")
	fs.Var(&cc, "cc", "copy recipient (repeat, or comma-separated)")
	fs.Var(&bcc, "bcc", "blind-copy recipient (repeat, or comma-separated)")
	fs.StringVar(&subject, "subject", "", "subject line (required)")
	fs.StringVar(&bodyFile, "body-file", "", "file with the message text, - for stdin (required)")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	if from == "" || len(to) == 0 || subject == "" || bodyFile == "" {
		return a.usageErr(c, "--from, --to, --subject and --body-file are required")
	}
	text, err := a.readText(bodyFile)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	params := map[string]any{"to": []string(to), "subject": subject, "body": text}
	if len(cc) > 0 {
		params["cc"] = []string(cc)
	}
	if len(bcc) > 0 {
		params["bcc"] = []string(bcc)
	}
	// The target is the sending account: the card shows it, and chapd refuses a
	// request for an account it is not connected as.
	return a.ask(&co, opReq{op: "mail.send", target: target{"google", from}, params: params})
}

func cmdDriveShare(a *app, c *command, args []string) int {
	var co common
	var to listFlag
	var role, from, name string
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	fs.StringVar(&from, "from", "", "the Google account that shares (required)")
	fs.StringVar(&name, "name", "", "the file's name in Drive, exactly (required: the card shows it and chapd checks it)")
	fs.Var(&to, "to", "recipient (repeat, or comma-separated)")
	fs.StringVar(&role, "role", "", "Drive role: reader, commenter or writer (required)")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	if from == "" || name == "" || len(to) == 0 || role == "" {
		return a.usageErr(c, "--from, --name, --to and --role are required")
	}
	// A share is always with named people: chap cannot ask for a link share.
	params := map[string]any{"file_id": pos[0], "file_name": name, "recipients": []string(to), "role": role, "link_visibility": "restricted"}
	return a.ask(&co, opReq{op: "drive.share", target: target{"google", from}, params: params})
}

// approve is POST /v0/approvals: the same body as the op, plus kind.
func (a *app) approve(co *common, kind string, r opReq) int {
	body := map[string]any{"kind": kind, "op": r.op, "target": r.target, "params": r.params, "reason": co.reason}
	if co.project != "" {
		body["project"] = co.project
	}
	return a.do(co.json, "POST", "/v0/approvals", nil, body, func(rp *reply) rendered {
		// The card exists and the op waits for the operator: that is this
		// command's success.
		return renderOpReply(rp, func(state string) int {
			if state == "pending_approval" {
				return exitOK
			}
			return opCode(state)
		})
	})
}

func cmdRequestOp(a *app, c *command, args []string) int {
	var co common
	var tgt, params string
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	fs.StringVar(&tgt, "target", "", "the op's target as adapter:ref (default: the op's usual target)")
	fs.StringVar(&params, "params", "{}", "the op's params as one JSON object, exactly as they will run")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	name := pos[0]
	if !opNameRE.MatchString(name) || len(name) > 64 {
		return a.usageErr(c, "%q is not an op name like pr.merge", name)
	}
	if co.reason == "" {
		return a.usageErr(c, "--reason is required")
	}
	var t target
	if tgt != "" {
		m := targetRE.FindStringSubmatch(tgt)
		if m == nil {
			return a.usageErr(c, "--target must be adapter:ref")
		}
		t = target{m[1], m[2]}
	} else if d, ok := defaultTargets[name]; ok {
		t = d
	} else {
		return a.usageErr(c, "%s has no usual target; pass --target adapter:ref", name)
	}
	dec := json.NewDecoder(strings.NewReader(params))
	dec.UseNumber()
	var p map[string]any
	if err := dec.Decode(&p); err != nil || p == nil || dec.More() {
		return a.usageErr(c, "--params must be one JSON object")
	}
	return a.approve(&co, "op", opReq{op: name, target: t, params: p})
}

// cmdRequestKind sends the spec's net, pkg and scope requests. The contract
// says chapd answers any kind but `op` with 400 OP_PARAMS_INVALID in Phase 1
// (they belong to the runner's surfaces); chap sends them anyway so that the
// answer is chapd's, and starts working when chapd takes them.
func cmdRequestKind(a *app, c *command, args []string) int {
	var co common
	kind := strings.TrimPrefix(c.path, "request ")
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	want := 1
	if kind == "scope" {
		want = 0
	}
	pos, code, done := a.parse(c, fs, args, want, want)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	if co.reason == "" {
		return a.usageErr(c, "--reason is required")
	}
	ref := "task_scope"
	params := map[string]any{}
	switch kind {
	case "net":
		ref, params = pos[0], map[string]any{"host": pos[0]}
	case "pkg":
		ref, params = pos[0], map[string]any{"package": pos[0]}
	}
	return a.approve(&co, kind, opReq{op: kind, target: target{"runner", ref}, params: params})
}
