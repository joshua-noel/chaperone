package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joshua-noel/chaperone/internal/grant"
)

// A runbook is a fixed program shape: which script (a file named in the
// config, hash-checked against the grant), which launcher, which arguments in
// which order. Nothing about it comes from a grant except the validated
// argument values. The set of names is grant.Names(); a config or grant that
// names anything else is refused.
//
// The pilot distro has Windows drives and interop switched off, so a script
// cannot be run from a Windows path. Every runbook therefore gets its
// verified copy on standard input of a fixed stub that stores it in the
// distro, runs it with the validated arguments and removes it.

const (
	pilotDistro = "sm-pilot"
	pilotUser   = "pilot"

	// wslStage is the only shell text in this program. It is a constant with no
	// placeholder: the script arrives on stdin, the arguments arrive as separate
	// argv entries ($@: a fixed verb, then values the grant schema already
	// restricted to 40 lowercase hex or a fixed word list). stdin of the script
	// is /dev/null so nothing it runs can eat the rest of its own source.
	wslStage = `set -eu; f=$(mktemp); trap 'rm -f $f' EXIT; cat >$f; bash $f $@ </dev/null`
)

// Runbook is the launch description of one allowlisted runbook.
type Runbook struct {
	// Source is the script on disk, from the config. Empty means not configured.
	Source  string
	Timeout time.Duration
	// Argv builds the command line from the grant's validated arguments in
	// schema order. argv[0] is an absolute program path.
	Argv func(args []string) []string
	// Env is extra environment for the child, on top of the fixed minimal set.
	Env []string
}

// builtinRunbooks returns the production table: one entry per allowlisted name
// (grant.Names), with sources from the config.
func builtinRunbooks(sources map[string]string) map[string]Runbook {
	table := map[string]Runbook{
		"deploy":     {Timeout: 45 * time.Minute, Argv: wslArgv(pilotDistro, pilotUser, "deploy")},
		"logs.pilot": {Timeout: 2 * time.Minute, Argv: wslArgv(pilotDistro, pilotUser, "logs")},
	}
	for name, src := range sources {
		rb, ok := table[name]
		if !ok {
			continue // config validation rejects this before we get here
		}
		rb.Source = src
		table[name] = rb
	}
	return table
}

func wslArgv(distro, user, verb string) func(args []string) []string {
	return func(args []string) []string {
		argv := []string{
			systemExe("wsl.exe"), "-d", distro, "-u", user, "--exec",
			"bash", "-lc", wslStage, "chap-host", verb,
		}
		return append(argv, args...)
	}
}

// systemExe is the absolute path of a System32 program. It never searches PATH.
func systemExe(name string) string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", name)
}

// checkRunbooks reports a table that does not match the allowlist exactly.
func checkRunbooks(table map[string]Runbook) error {
	for name := range table {
		if _, ok := grant.Lookup(name); !ok {
			return fmt.Errorf("runbook %q is not in the grant allowlist", name)
		}
	}
	for _, name := range grant.Names() {
		rb, ok := table[name]
		if !ok {
			return fmt.Errorf("allowlisted runbook %q has no launch description", name)
		}
		if rb.Argv == nil || rb.Timeout <= 0 {
			return fmt.Errorf("runbook %q is incomplete", name)
		}
	}
	return nil
}
