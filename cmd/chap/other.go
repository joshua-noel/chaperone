package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/joshua-noel/chaperone/internal/localtime"
)

// The commands that are not "ask for an op": reads, operator calls, and the
// two that make no call to chapd (`git setup`, none other).

var (
	opIDRE  = regexp.MustCompile(`^q-[0-9a-z]{6,32}$`)
	runIDRE = regexp.MustCompile(`^r-[0-9a-z]{4,32}$`)
	slugRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}$`)
)

var profiles = map[string]bool{"code": true, "docs": true, "research": true, "review": true, "deploy-watch": true, "data-op": true, "ci": true, "host-interim": true}

func otherCommands() []*command {
	return []*command{
		{path: "approve list", usage: "chap approve list [--state pending|approved|denied|expired|cancelled|consumed] [--limit <n>] [--cursor <c>]",
			summary: "list your own approval requests (approving is done in the console)", run: cmdApproveList},
		{path: "op show", usage: "chap op show <q-id> [--wait <s>] [--since <state>]",
			summary: "show one op, optionally waiting for it to change", run: cmdOpShow},
		{path: "ledger verify", usage: "chap ledger verify [--against-export] [--anchor [--anchor-file <f>]... [--anchor-pub <k>]...]",
			summary: "walk the ledger hash chain, optionally against the signed anchor copies (orchestrator only)", run: cmdLedgerVerify},
		{path: "runs revoke", usage: "chap runs revoke <r-id> | --all",
			summary: "revoke one run, or every active run (orchestrator only)", run: cmdRunsRevoke},
		{path: "dev-token", usage: "chap dev-token --project <p> --repo <owner/name> --branch <b> --path <glob> --op <op> --out <file> [--base <b>] [--minutes <n>]",
			summary: "mint an interim run token into a file (orchestrator only)", run: cmdDevToken},
		{path: "git setup", usage: "chap git setup [--global]",
			summary: "route git's GitHub traffic through chapd's git proxy", run: cmdGitSetup},
		{path: "vault status", usage: "chap vault status",
			summary: "vault state: names and counts, never a value (orchestrator only)", run: cmdVaultStatus},
		{path: "doctor", usage: "chap doctor [--json]",
			summary: "check the server's Chaperone install (from a normal, not elevated, terminal)", run: cmdDoctor},
		{path: "manual", usage: "chap manual [--profile <p>] [--all] [--project <p>]",
			summary: "what this caller may ask for, with usage", run: cmdManual},
	}
}

// jsonOnly registers --json alone.
func jsonOnly(fs *flag.FlagSet) *bool {
	var j bool
	fs.BoolVar(&j, "json", false, "print chapd's JSON reply instead of text")
	return &j
}

func cmdApproveList(a *app, c *command, args []string) int {
	var state, cursor string
	var limit int
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.StringVar(&state, "state", "", "only approvals in this state")
	fs.IntVar(&limit, "limit", 0, "page size, 1 to 200")
	fs.StringVar(&cursor, "cursor", "", "the next_cursor of the previous page")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	switch state {
	case "", "pending", "approved", "denied", "expired", "cancelled", "consumed":
	default:
		return a.usageErr(c, "--state must be pending, approved, denied, expired, cancelled or consumed")
	}
	if limit < 0 || limit > 200 {
		return a.usageErr(c, "--limit must be 1 to 200")
	}
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	return a.do(*asJSON, "GET", "/v0/approvals", q, nil, func(r *reply) rendered {
		var page struct {
			Items      []approvalSummary `json:"items"`
			NextCursor *string           `json:"next_cursor"`
		}
		if err := json.Unmarshal(r.body, &page); err != nil {
			return unreadable(err)
		}
		if len(page.Items) == 0 {
			return rendered{human: "no approvals\n"}
		}
		rows := make([][]string, len(page.Items))
		for i, it := range page.Items {
			class := it.Class
			if it.Critical && it.Class != "critical" {
				class += " CRITICAL"
			}
			rows[i] = []string{it.ID, it.Op, it.State, class, it.RequestID, localtime.FromRFC3339(it.ExpiresAt)}
		}
		out := table([]string{"APPROVAL", "OP", "STATE", "CLASS", "REQUEST", "EXPIRES(-04)"}, rows)
		if page.NextCursor != nil {
			out += "more: chap approve list --cursor " + clean(*page.NextCursor) + "\n"
		}
		return rendered{human: out}
	})
}

func cmdOpShow(a *app, c *command, args []string) int {
	var wait int
	var since string
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.IntVar(&wait, "wait", 0, "seconds to hold for a state change, 0 to 55")
	fs.StringVar(&since, "since", "", "the state you last saw; wait until it differs")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if !opIDRE.MatchString(pos[0]) {
		return a.usageErr(c, "the op id must look like q-xxxxxx")
	}
	if wait < 0 || wait > 55 {
		return a.usageErr(c, "--wait must be 0 to 55")
	}
	q := url.Values{}
	if wait > 0 {
		q.Set("wait", strconv.Itoa(wait))
	}
	if since != "" {
		q.Set("since_state", since)
	}
	return a.do(*asJSON, "GET", "/v0/ops/"+pos[0], q, nil, func(r *reply) rendered { return renderOpReply(r, opCode) })
}

const maxAnchorLines = 2000 // chapd's own limit (ops.MaxAnchorRecords)

// anchorLines reads the record lines of an --anchor-file: one signed anchor per
// line, as chapd keeps them in anchors\<chain>.jsonl and as the backup copy holds
// them. Blank lines are skipped.
func (a *app) anchorLines(path string) ([]string, error) {
	data, err := a.readFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read --anchor-file %s: %w", path, err)
	}
	if len(data) > maxBody {
		return nil, fmt.Errorf("--anchor-file %s is larger than %d bytes", path, maxBody)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func cmdLedgerVerify(a *app, c *command, args []string) int {
	var against, anchor bool
	var files, keys listFlag
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.BoolVar(&against, "against-export", false, "also compare the chain with the daily JSONL export")
	fs.BoolVar(&anchor, "anchor", false, "also compare the chain with the signed anchor records (the copies chapd made on the phone and in the backup set)")
	fs.Var(&files, "anchor-file", "with --anchor: a copy of the records file kept somewhere chapd cannot edit (restored from the Drive backup); repeatable")
	fs.Var(&keys, "anchor-pub", "with --anchor: an extra trusted ledger public key (after a key rotation); repeatable")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	if !anchor && (len(files) > 0 || len(keys) > 0) {
		return a.usageErr(c, "--anchor-file and --anchor-pub need --anchor")
	}
	body := map[string]any{"against_export": against}
	if anchor {
		lines := []string{}
		for _, f := range files {
			ls, err := a.anchorLines(f)
			if err != nil {
				return a.fail(exitUsage, "%v", err)
			}
			lines = append(lines, ls...)
		}
		if len(lines) > maxAnchorLines {
			return a.usageErr(c, "at most %d anchor records", maxAnchorLines)
		}
		body["anchor"] = true
		body["anchor_records"] = lines
		body["anchor_keys"] = []string(keys)
	}
	return a.do(*asJSON, "POST", "/v0/ledger/verify", nil, body, func(r *reply) rendered {
		var v struct {
			OK             bool     `json:"ok"`
			Chain          string   `json:"chain"`
			HeadSeq        int64    `json:"head_seq"`
			HeadHash       string   `json:"head_hash"`
			CheckedExport  bool     `json:"checked_export"`
			Problems       []string `json:"problems"`
			AnchorsChecked *int     `json:"anchors_checked"`
			NewestAnchor   *struct {
				AnchorSeq int64  `json:"anchor_seq"`
				HeadSeq   int64  `json:"head_seq"`
				HeadHash  string `json:"head_hash"`
				Time      string `json:"time"`
			} `json:"newest_anchor"`
		}
		if err := json.Unmarshal(r.body, &v); err != nil {
			return unreadable(err)
		}
		var b strings.Builder
		word, code := "ok", exitOK
		if !v.OK {
			word, code = "NOT OK", exitNotOK
		}
		fmt.Fprintf(&b, "ledger %s: chain %s, head seq %d, hash %s\n", word, clean(v.Chain), v.HeadSeq, clean(v.HeadHash))
		if v.CheckedExport {
			b.WriteString("compared with the daily export\n")
		} else if against {
			b.WriteString("the export was not compared\n")
		}
		if v.AnchorsChecked != nil {
			fmt.Fprintf(&b, "compared with %d signed anchor record(s)\n", *v.AnchorsChecked)
		}
		if n := v.NewestAnchor; n != nil {
			fmt.Fprintf(&b, "newest anchor: head seq %d, hash %s, at %s (the phone has the same two values)\n", n.HeadSeq, clean(n.HeadHash), clean(n.Time))
		}
		for _, p := range v.Problems {
			fmt.Fprintf(&b, "problem: %s\n", clean(p))
		}
		return rendered{human: b.String(), code: code}
	})
}

func cmdRunsRevoke(a *app, c *command, args []string) int {
	var all bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.BoolVar(&all, "all", false, "revoke every active run")
	pos, code, done := a.parse(c, fs, args, 0, 1)
	if done {
		return code
	}
	if all == (len(pos) == 1) {
		return a.usageErr(c, "give one run id or --all")
	}
	if all {
		return a.do(*asJSON, "POST", "/v0/runs/revoke-all", nil, nil, func(r *reply) rendered {
			var v struct {
				Revoked  int    `json:"revoked"`
				StopCode string `json:"stop_code"`
			}
			if err := json.Unmarshal(r.body, &v); err != nil {
				return unreadable(err)
			}
			return rendered{human: fmt.Sprintf("revoked %d active runs (%s)\n", v.Revoked, clean(v.StopCode))}
		})
	}
	if !runIDRE.MatchString(pos[0]) {
		return a.usageErr(c, "the run id must look like r-xxxx")
	}
	return a.do(*asJSON, "POST", "/v0/runs/"+pos[0]+"/revoke", nil, nil, func(r *reply) rendered {
		var v struct {
			RunID     string `json:"run_id"`
			Project   string `json:"project"`
			Profile   string `json:"profile"`
			State     string `json:"state"`
			EndReason string `json:"end_reason"`
		}
		if err := json.Unmarshal(r.body, &v); err != nil {
			return unreadable(err)
		}
		out := fmt.Sprintf("run %s (%s, %s): %s\n", clean(v.RunID), clean(v.Project), clean(v.Profile), clean(v.State))
		if v.EndReason != "" {
			out += "reason: " + clean(v.EndReason) + "\n"
		}
		return rendered{human: out}
	})
}

// cmdDevToken mints an interim run token. The token is the one thing chapd
// returns that is a secret, and chap never prints a secret: it goes to a file
// only the user can read (created exclusively, never overwritten), and chap
// prints where, the run id, the expiry and the token's fingerprint.
func cmdDevToken(a *app, c *command, args []string) int {
	var project, repo, base, branch, out string
	var paths, ops listFlag
	var minutes int
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.StringVar(&project, "project", strings.TrimSpace(a.getenv("CHAP_PROJECT")), "project slug (required) [env CHAP_PROJECT]")
	fs.StringVar(&repo, "repo", "", "owner/name the run may push to (required)")
	fs.StringVar(&base, "base", "main", "base branch")
	fs.StringVar(&branch, "branch", "", "the one branch the run may push (required)")
	fs.Var(&paths, "path", "path glob the run may change (repeat, required)")
	fs.Var(&ops, "op", "op the token may ask for (repeat, required)")
	fs.IntVar(&minutes, "minutes", 60, "lifetime in minutes, 1 to 120")
	fs.StringVar(&out, "out", "", "file to write the token to; private to you (mode 0600, or an access list for you alone on Windows), never overwritten (required)")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	switch {
	case !slugRE.MatchString(project):
		return a.usageErr(c, "--project must be a project slug")
	case !repoRE.MatchString(repo):
		return a.usageErr(c, "--repo must be owner/name")
	case branch == "" || len(paths) == 0 || len(ops) == 0:
		return a.usageErr(c, "--branch, --path and --op are required")
	case out == "":
		return a.usageErr(c, "--out is required: chap never prints a token, it writes it to a file")
	case minutes < 1 || minutes > 120:
		return a.usageErr(c, "--minutes must be 1 to 120")
	}
	for _, o := range ops {
		if !opNameRE.MatchString(o) {
			return a.usageErr(c, "%q is not an op name like pr.open", o)
		}
	}
	body := map[string]any{
		"project": project, "profile": "host-interim", "repo": repo, "base": base,
		"branch": branch, "paths": []string(paths), "ops": []string(ops), "minutes": minutes,
	}
	return a.do(*asJSON, "POST", "/v0/dev-tokens", nil, body, func(r *reply) rendered {
		var v struct {
			Token     string `json:"token"`
			RunID     string `json:"run_id"`
			JTI       string `json:"jti"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal(r.body, &v); err != nil || v.Token == "" {
			return rendered{human: "chap: chapd's dev-token reply has no token\n", code: exitFail}
		}
		a.secrets = append(a.secrets, v.Token)
		if err := a.createFile(out, []byte(v.Token+"\n")); err != nil {
			// The token exists on chapd's side and is lost here; say so.
			return rendered{human: fmt.Sprintf("chap: cannot write %s: %v\nthe run %s exists and its token is lost; revoke it: chap runs revoke %s\n",
				out, err, clean(v.RunID), clean(v.RunID)), code: exitFail}
		}
		sum := sha256.Sum256([]byte(v.Token))
		fp := hex.EncodeToString(sum[:4])
		j, _ := json.Marshal(map[string]string{
			"run_id": v.RunID, "jti": v.JTI, "expires_at": v.ExpiresAt, "token_file": out, "fingerprint": fp,
		})
		return rendered{
			human: fmt.Sprintf("run %s token written to %s (fingerprint %s), expires %s\nhand it to the run as CHAP_RUN_TOKEN, read from that file\n",
				clean(v.RunID), out, fp, clean(localtime.FromRFC3339(v.ExpiresAt))),
			json: j,
		}
	})
}

func cmdVaultStatus(a *app, c *command, args []string) int {
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	return a.do(*asJSON, "GET", "/v0/vault/status", nil, nil, func(r *reply) rendered {
		var v struct {
			Initialized bool     `json:"initialized"`
			SecretCount int      `json:"secret_count"`
			Names       []string `json:"names"`
		}
		if err := json.Unmarshal(r.body, &v); err != nil {
			return unreadable(err)
		}
		if !v.Initialized {
			return rendered{human: "vault: not initialized\n"}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "vault: initialized, %d secrets\n", v.SecretCount)
		for _, n := range v.Names {
			fmt.Fprintf(&b, "  %s\n", clean(n))
		}
		return rendered{human: b.String()}
	})
}

func cmdManual(a *app, c *command, args []string) int {
	var profile, project string
	var all bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.StringVar(&profile, "profile", "", "show what this profile may use (code, docs, research, review, deploy-watch, data-op, ci, host-interim)")
	fs.BoolVar(&all, "all", false, "also list disabled ops (orchestrator only)")
	fs.StringVar(&project, "project", "", "project slug (orchestrator only)")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	if profile != "" && !profiles[profile] {
		return a.usageErr(c, "unknown profile %q", profile)
	}
	if project != "" && !slugRE.MatchString(project) {
		return a.usageErr(c, "--project must be a project slug")
	}
	q := url.Values{}
	if profile != "" {
		q.Set("profile", profile)
	}
	if all {
		q.Set("all", "true")
	}
	if project != "" {
		q.Set("project", project)
	}
	return a.do(*asJSON, "GET", "/v0/catalog", q, nil, func(r *reply) rendered {
		var cat struct {
			PolicyVersion string `json:"policy_version"`
			Project       string `json:"project"`
			Profile       string `json:"profile"`
			Ops           []struct {
				Op      string `json:"op"`
				Class   string `json:"class"`
				Enabled bool   `json:"enabled"`
				Summary string `json:"summary"`
				Usage   string `json:"usage"`
			} `json:"ops"`
		}
		if err := json.Unmarshal(r.body, &cat); err != nil {
			return unreadable(err)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "manual: project %s", clean(cat.Project))
		if cat.Profile != "" {
			fmt.Fprintf(&b, ", profile %s", clean(cat.Profile))
		}
		fmt.Fprintf(&b, ", policy %s\n", clean(cat.PolicyVersion))
		for _, o := range cat.Ops {
			state := o.Class
			if !o.Enabled {
				state += ", disabled"
			}
			fmt.Fprintf(&b, "%s [%s] %s\n  %s\n", clean(o.Op), clean(state), clean(o.Summary), clean(o.Usage))
		}
		if len(cat.Ops) == 0 {
			b.WriteString("no ops are enabled\n")
		}
		return rendered{human: b.String()}
	})
}

// cmdGitSetup points git at chapd's proxy. It makes no call to chapd and
// writes no secret: the credential helper it installs reads CHAP_RUN_TOKEN
// from the environment when git asks, so the token is never in a config file
// or a URL.
func cmdGitSetup(a *app, c *command, args []string) int {
	var global bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	fs.BoolVar(&global, "global", false, "write the user's git config instead of this repository's")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	base, err := a.baseURL()
	if err != nil {
		return a.report(err)
	}
	scope := "--local"
	if global {
		scope = "--global"
	}
	proxy := base + "/git/"
	// An empty first helper resets any helper inherited for this URL.
	helper := `!f() { echo username=chap; echo "password=$CHAP_RUN_TOKEN"; }; f`
	steps := [][]string{
		{"config", scope, "--replace-all", "url." + proxy + ".insteadOf", "https://github.com/"},
		{"config", scope, "--replace-all", "credential." + proxy + ".helper", ""},
		{"config", scope, "--add", "credential." + proxy + ".helper", helper},
	}
	for _, s := range steps {
		if _, err := a.git(s...); err != nil {
			return a.fail(exitFail, "git %s failed: %v (inside a repository, or use --global)", strings.Join(s[:3], " "), err)
		}
	}
	a.out(fmt.Sprintf("git now sends https://github.com/ traffic to %s (%s)\npush authenticates with CHAP_RUN_TOKEN from the environment; no token is stored\n",
		proxy, strings.TrimPrefix(scope, "--")))
	return exitOK
}
