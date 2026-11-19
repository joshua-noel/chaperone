package main

import (
	"flag"
	"fmt"
	"regexp"
	"strconv"
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
// An operation that needs more than this (a param that is read from git, a
// default that differs from the schema's, a flag that depends on another, a
// fixed flag in the usage line) sets CLI.Custom in its declaration and keeps a
// hand-written command in opCommands; a test checks that each declared
// operation has exactly one of the two.

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

// declaredFlags holds the values of the flags of one generated command.
type declaredFlags struct {
	co       common
	tf       textFlags
	teamFlag string
	repo     string
	dry      bool
	bools    map[string]*bool
	strs     map[string]*string
	ints     map[string]*int
	lists    map[string]*listFlag
}

// registerDeclared defines every flag of the generated command of o: the
// common ones, the params', the ref's and --repo and --dry-run. The flag
// package panics when a flag is defined twice, so a clash between a declared
// flag and a common one fails TestGeneratedCommandsHaveNoFlagClash instead of
// surprising a user.
func registerDeclared(o kit.Op, fs *flag.FlagSet, a *app) *declaredFlags {
	d := &declaredFlags{bools: map[string]*bool{}, strs: map[string]*string{}, ints: map[string]*int{}, lists: map[string]*listFlag{}}
	d.co.register(fs, a)
	for _, p := range o.Params {
		if p.FromRef || p.Const != "" {
			continue
		}
		switch p.Kind {
		case kit.Bool:
			d.bools[p.Name] = fs.Bool(p.FlagName(), false, p.Help)
		case kit.String:
			d.strs[p.Name] = fs.String(p.FlagName(), "", p.Help)
		case kit.Int:
			d.ints[p.Name] = fs.Int(p.FlagName(), 0, p.Help)
		case kit.List:
			l := &listFlag{}
			d.lists[p.Name] = l
			fs.Var(l, p.FlagName(), p.Help)
		case kit.Text:
			d.tf.register(fs)
		}
	}
	if o.Target.Flag != "" {
		fs.StringVar(&d.teamFlag, o.Target.Flag, "", o.Target.Help)
	}
	if o.Target.Repo {
		fs.StringVar(&d.repo, "repo", "", "owner/name (default: from the git remote origin)")
	}
	if o.CLI.DryRun != "" {
		fs.BoolVar(&d.dry, "dry-run", false, o.CLI.DryRun)
	}
	return d
}

func runDeclared(o kit.Op, a *app, c *command, args []string) int {
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	d := registerDeclared(o, fs, a)
	co, tf := &d.co, &d.tf
	positionals := 0
	if o.Target.Positional != "" {
		positionals = 1
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
	// For a repository target the positional argument is the number, and the
	// repository is read last, as the hand-written commands did.
	ref, given, number := o.Target.Default, false, 0
	switch {
	case o.Target.Repo && positionals == 1:
		n, err := strconv.Atoi(pos[0])
		if err != nil || n < 1 {
			return a.usageErr(c, "%s", o.Target.Why)
		}
		number = n
	case positionals == 1:
		ref, given = pos[0], true
	case d.teamFlag != "":
		ref, given = d.teamFlag, true
	}
	if given && !regexp.MustCompile(o.Target.Pattern).MatchString(ref) {
		why := o.Target.Why
		if strings.Contains(why, "%q") {
			why = fmt.Sprintf(why, ref)
		}
		return a.usageErr(c, "%s", why)
	}

	params := map[string]any{}
	for _, p := range o.Params {
		switch {
		case p.FromRef && p.Kind == kit.Int:
			params[p.Name] = number
			continue
		case p.FromRef:
			params[p.Name] = ref
			continue
		case p.Const != "":
			params[p.Name] = p.Const
			continue
		}
		switch p.Kind {
		case kit.Bool:
			if *d.bools[p.Name] {
				params[p.Name] = true
			}
		case kit.String:
			v := *d.strs[p.Name]
			if p.Pattern != "" {
				pat := p.CLIPattern
				if pat == "" {
					pat = p.Pattern
				}
				if (p.Required || v != "") && !regexp.MustCompile(pat).MatchString(v) {
					return a.usageErr(c, "%s", p.Why)
				}
			} else if p.Required && strings.TrimSpace(v) == "" {
				return a.usageErr(c, "--%s is required", p.FlagName())
			}
			if v != "" {
				params[p.Name] = v
			}
		case kit.Int:
			// 0 is a flag left out: nothing is sent and the adapter applies
			// the schema's default.
			v := *d.ints[p.Name]
			if v == 0 {
				if p.Required {
					return a.usageErr(c, "--%s is required", p.FlagName())
				}
				continue
			}
			if v < p.Min || p.Max > 0 && v > p.Max {
				if p.Max > 0 {
					return a.usageErr(c, "--%s must be %d to %d", p.FlagName(), p.Min, p.Max)
				}
				return a.usageErr(c, "--%s must be %d or more", p.FlagName(), p.Min)
			}
			params[p.Name] = v
		case kit.List:
			l := *d.lists[p.Name]
			if len(l) == 0 {
				if p.Required {
					return a.usageErr(c, "--%s is required", p.FlagName())
				}
				continue
			}
			params[p.Name] = []string(l)
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
	if o.Target.Repo {
		repo, err := a.repoArg(d.repo)
		if err != nil {
			return a.usageErr(c, "%v", err)
		}
		ref = repo
		if positionals == 1 {
			ref = fmt.Sprintf("%s#%d", repo, number)
		}
	}
	return a.ask(co, opReq{op: o.Name, target: target{o.Target.Adapter, ref}, params: params, dryRun: d.dry})
}
