package grant

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
)

// ArgKind is the value shape of one runbook argument.
type ArgKind int

const (
	// ArgGitSHA is a full git commit id: 40 lowercase hex characters.
	ArgGitSHA ArgKind = iota + 1
	// ArgEnum is one of a fixed list of values.
	ArgEnum
)

// ArgSpec describes one argument. Every argument is required.
type ArgSpec struct {
	Name   string
	Kind   ArgKind
	Values []string // for ArgEnum
}

// RunbookSpec is the fixed schema of one runbook: the op it serves and its
// ordered arguments. A grant for anything else, or with an extra, missing or
// malformed argument, is invalid.
type RunbookSpec struct {
	Op   string
	Args []ArgSpec
}

// runbooks is the closed list of runbook names a grant may name (ticket
// L1-14). `host.scripts.refresh` joins it in the PR that enables that op.
var runbooks = map[string]RunbookSpec{
	"deploy": {
		Op:   "deploy",
		Args: []ArgSpec{{Name: "sha", Kind: ArgGitSHA}},
	},
	"logs.pilot": {
		Op: "logs",
		// The fixed set of log sources (ticket L1-11): one pilot unit each.
		Args: []ArgSpec{{Name: "source", Kind: ArgEnum, Values: []string{"web", "worker", "db", "tunnel"}}},
	},
}

var gitSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Lookup returns the schema of the named runbook.
func Lookup(name string) (RunbookSpec, bool) {
	s, ok := runbooks[name]
	return s, ok
}

// Names lists the allowlisted runbook names, sorted.
func Names() []string {
	names := make([]string, 0, len(runbooks))
	for n := range runbooks {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (s RunbookSpec) checkArgs(args map[string]string) error {
	if len(args) != len(s.Args) {
		return fmt.Errorf("want %d args, got %d", len(s.Args), len(args))
	}
	for _, a := range s.Args {
		v, ok := args[a.Name]
		if !ok {
			return fmt.Errorf("arg %q is missing", a.Name)
		}
		switch a.Kind {
		case ArgGitSHA:
			if !gitSHARe.MatchString(v) {
				return fmt.Errorf("arg %q is not 40 lowercase hex", a.Name)
			}
		case ArgEnum:
			if !slices.Contains(a.Values, v) {
				return fmt.Errorf("arg %q is not one of the allowed values", a.Name)
			}
		default:
			return fmt.Errorf("arg %q has an unknown kind", a.Name)
		}
	}
	return nil
}

// Ordered returns the argument values of a validated grant in schema order.
// Call it only on a grant that passed Validate.
func (s RunbookSpec) Ordered(args map[string]string) []string {
	out := make([]string, len(s.Args))
	for i, a := range s.Args {
		out[i] = args[a.Name]
	}
	return out
}
