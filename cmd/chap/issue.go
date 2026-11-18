package main

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
)

// `chap issue open|comment|reopen`: the error watcher files and
// follows issues through chapd with its orchestrator token. chapd takes the
// repository from the project and refuses any issue that lacks the label
// source:error-watcher; these commands only build the request.

func parseIssue(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, errors.New("the issue number must be a positive integer")
	}
	return n, nil
}

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

func cmdIssueComment(a *app, c *command, args []string) int {
	var co common
	var tf textFlags
	var repo string
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	tf.register(fs)
	fs.StringVar(&repo, "repo", "", "owner/name (default: from the git remote origin)")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	n, err := parseIssue(pos[0])
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	text, hasBody, err := tf.resolve(a)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	if !hasBody {
		return a.usageErr(c, "--body or --body-file is required")
	}
	r, err := a.repoArg(repo)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	return a.ask(&co, opReq{op: "issue.comment", target: target{"github", fmt.Sprintf("%s#%d", r, n)}, params: map[string]any{"body": text}})
}

func cmdIssueReopen(a *app, c *command, args []string) int {
	var co common
	var repo string
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	fs.StringVar(&repo, "repo", "", "owner/name (default: from the git remote origin)")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}
	n, err := parseIssue(pos[0])
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	r, err := a.repoArg(repo)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	return a.ask(&co, opReq{op: "issue.reopen", target: target{"github", fmt.Sprintf("%s#%d", r, n)}, params: map[string]any{}})
}
