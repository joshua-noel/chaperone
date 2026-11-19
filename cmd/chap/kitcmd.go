package main

import (
	"flag"
	"regexp"
	"strings"

	"github.com/joshua-noel/chaperone/internal/connectors/declared"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
)

// The commands of the operations that connectors declare with the kit
// (internal/connectors/kit). A declaration carries what a simple command needs:
// the words of the command, the ref and how it is given, the params and their
// flags, the usage line and the summary. This file turns one into a command
// that does what every hand-written op command here does: parse the flags,
// check the shapes, send {op, target, params} and print the answer. The shapes
// are checked here only to give a usage error early. chapd checks everything
// again and is the guard.
//
// An operation that needs more than this (a computed ref, a param that is read
// from git, a flag that depends on another) sets CLI.Custom in its declaration
// and keeps a hand-written command in opCommands; a test checks that each
// declared operation has exactly one of the two.

// declaredOps is the list of declared operations. A test replaces it.
var declaredOps = declared.Ops

// kitCommands builds the generic command of every declared operation that does
// not ask for a custom one.
func kitCommands(ops []kit.Op) []*command {
	var out []*command
	for _, o := range ops {
		if o.CLI.Custom {
			continue
		}
		out = append(out, &command{
			path:    o.CLIPath(),
			usage:   o.CLIUsage(),
			summary: o.CLISummary(),
			run:     func(a *app, c *command, args []string) int { return runDeclared(o, a, c, args) },
		})
	}
	return out
}

func runDeclared(o kit.Op, a *app, c *command, args []string) int {
	var co common
	var tf textFlags
	var teamFlag string
	bools := map[string]*bool{}
	strs := map[string]*string{}
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	co.register(fs, a)
	for _, p := range o.Params {
		switch p.Kind {
		case kit.Bool:
			bools[p.Name] = fs.Bool(p.FlagName(), false, p.Help)
		case kit.String:
			strs[p.Name] = fs.String(p.FlagName(), "", p.Help)
		case kit.Text:
			tf.register(fs)
		}
	}
	positionals := 0
	if o.Target.Positional != "" {
		positionals = 1
	} else {
		fs.StringVar(&teamFlag, o.Target.Flag, "", o.Target.Help)
	}
	pos, code, done := a.parse(c, fs, args, positionals, positionals)
	if done {
		return code
	}
	if err := co.check(); err != nil {
		return a.usageErr(c, "%v", err)
	}

	// The ref is the positional argument, or the flag's value, or the
	// declared default when the flag is left out. A given ref must have the
	// declared shape; the default is a fixed word the adapter understands.
	ref, given := o.Target.Default, false
	if positionals == 1 {
		ref, given = pos[0], true
	} else if teamFlag != "" {
		ref, given = teamFlag, true
	}
	if given && !regexp.MustCompile(o.Target.Pattern).MatchString(ref) {
		return a.usageErr(c, "%s", o.Target.Why)
	}

	params := map[string]any{}
	for _, p := range o.Params {
		switch p.Kind {
		case kit.Bool:
			if *bools[p.Name] {
				params[p.Name] = true
			}
		case kit.String:
			v := *strs[p.Name]
			if p.Required && strings.TrimSpace(v) == "" {
				return a.usageErr(c, "--%s is required", p.FlagName())
			}
			if v != "" {
				params[p.Name] = v
			}
		case kit.Text:
			text, has, err := tf.resolve(a)
			if err != nil {
				return a.usageErr(c, "%v", err)
			}
			if !has && p.Required {
				return a.usageErr(c, "--body or --body-file is required")
			}
			if has {
				params[p.Name] = text
			}
		}
	}
	return a.ask(&co, opReq{op: o.Name, target: target{o.Target.Adapter, ref}, params: params})
}
