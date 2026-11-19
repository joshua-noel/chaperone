package main

import "flag"

// `chap issue open|comment|reopen`: the error watcher files and
// follows issues through chapd with its orchestrator token. chapd takes the
// repository from the project and refuses any issue that lacks the label
// source:error-watcher; these commands only build the request. `issue comment`
// and `issue reopen` are built from their declarations (cmd/chap/kitcmd.go);
// `issue open` stays here because its usage line names the label the watcher
// must give.

func cmdIssueOpen(a *app, c *command, args []string) int {
	var co common
	var tf textFlags
	var title, repo string
	var labels listFlag
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	tf.register(fs)
	fs.StringVar(&title, "title", "", "issue title, one line (required)")
	fs.Var(&labels, "label", "label to put on the issue; repeat or comma-separate (source:error-watcher is required)")
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
	if len(labels) == 0 {
		return a.usageErr(c, "--label is required (chapd refuses an issue without source:error-watcher)")
	}
	text, hasBody, err := tf.resolve(a)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	r, err := a.repoArg(repo)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	params := map[string]any{"title": title, "labels": []string(labels)}
	if hasBody {
		params["body"] = text
	}
	return a.ask(&co, opReq{op: "issue.open", target: target{"github", r}, params: params})
}
