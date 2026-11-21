package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/declared"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
)

// A command path is in the table once. A declared op has a generated command,
// or says Custom and has a hand-written one; never both and never neither.
func TestEveryDeclaredOpHasExactlyOneCommand(t *testing.T) {
	counts := map[string]int{}
	for _, c := range commands() {
		counts[c.path]++
	}
	for path, n := range counts {
		if n != 1 {
			t.Errorf("command %q is in the table %d times", path, n)
		}
	}
	generated := map[string]bool{}
	for _, c := range kitCommands(declared.Ops()) {
		generated[c.path] = true
	}
	hand := map[string]bool{}
	for _, c := range opCommands() {
		hand[c.path] = true
	}
	for _, o := range declared.Ops() {
		switch path := o.CLIPath(); {
		case o.CLI.Custom && !hand[path]:
			t.Errorf("%s says its command is custom, and opCommands has no %q", o.Name, path)
		case o.CLI.Custom && generated[path]:
			t.Errorf("%s says its command is custom, and one was generated", o.Name)
		case !o.CLI.Custom && hand[path]:
			t.Errorf("%s has a generated command and a hand-written one: delete one", o.Name)
		case !o.CLI.Custom && !generated[path]:
			t.Errorf("%s has no generated command", o.Name)
		}
	}
}

// A tiny read-only operation that is not in the shipped catalog. It stands for
// a fifth Linear operation: declared once, and `chap intake show` exists, with
// its help, its usage errors and its request, without a line of command code.
func TestAFifthOperationGetsItsCommandFromItsDeclaration(t *testing.T) {
	show := kit.Op{
		Name:          "intake.show",
		Class:         kit.Routine,
		Reversibility: kit.Reversible,
		Summary:       "Show one labelled board item.",
		Usage:         "chap intake show <SHOP-12> [--full]",
		RatePerMinute: 12,
		Doc:           "Target is the issue. `full` adds the comments.",
		Target:        kit.Target{Adapter: linearspec.Adapter, Pattern: linearspec.IssueRefPattern, Why: "the issue must be an identifier such as SHOP-12", Positional: "SHOP-12"},
		Params:        []kit.Param{{Name: "full", Kind: kit.Bool, Help: "also show the comments"}},
	}
	if err := show.Validate(); err != nil {
		t.Fatal(err)
	}
	prev := declaredOps
	declaredOps = func() []kit.Op { return append(prev(), show) }
	t.Cleanup(func() { declaredOps = prev })

	t.Run("help lists it", func(t *testing.T) {
		ta := newTestApp(t, env{})
		if code := ta.run([]string{"help"}); code != 0 || !strings.Contains(ta.out.String(), fmt.Sprintf("  %-18s %s\n", "intake show", "show one labelled board item")) {
			t.Errorf("exit %d, help:\n%s", code, ta.out)
		}
	})
	t.Run("help of the command", func(t *testing.T) {
		ta := newTestApp(t, env{})
		if code := ta.run([]string{"intake", "show", "-h"}); code != 0 {
			t.Fatalf("exit %d: %s", code, ta.errb)
		}
		out := ta.out.String()
		if !strings.HasPrefix(out, "usage: chap intake show <SHOP-12> [--full]\nshow one labelled board item\n") || !strings.Contains(out, "-full") {
			t.Errorf("help:\n%s", out)
		}
	})
	t.Run("sends the request", func(t *testing.T) {
		chapd := newFakeChapd(t, *ok200("op-intake-states"))
		ta := newTestApp(t, env{chapd: chapd, token: "orch"})
		if code := ta.run([]string{"intake", "show", "SHOP-12", "--full", "--project", "storefront"}); code != 0 {
			t.Fatalf("exit %d: %s", code, ta.errb)
		}
		want := `{"op":"intake.show","params":{"full":true},"project":"storefront","target":{"adapter":"linear","ref":"SHOP-12"}}`
		if len(chapd.reqs) != 1 || !strings.HasSuffix(chapd.reqs[0], "\n"+want) {
			t.Errorf("requests = %q, want a body %s", chapd.reqs, want)
		}
	})
	t.Run("refuses a bad ref before it asks", func(t *testing.T) {
		chapd := newFakeChapd(t, *ok200("op-intake-states"))
		ta := newTestApp(t, env{chapd: chapd, token: "orch"})
		code := ta.run([]string{"intake", "show", "ops-1"})
		if code != exitUsage || len(chapd.reqs) != 0 || !strings.Contains(ta.errb.String(), "the issue must be an identifier such as SHOP-12\nusage: chap intake show <SHOP-12> [--full]") {
			t.Errorf("exit %d, requests %q, stderr %q", code, chapd.reqs, ta.errb)
		}
	})
}

// The flag package panics when a flag is defined twice. Building the flag set of
// every generated command therefore fails here, in a test, when a declared flag
// has the name of a common one, and not when a person runs the command.
func TestGeneratedCommandsHaveNoFlagClash(t *testing.T) {
	build := func(o kit.Op) (err any) {
		defer func() { err = recover() }()
		registerDeclared(o, flag.NewFlagSet(o.Name, flag.ContinueOnError), newTestApp(t, env{}).app)
		return nil
	}
	for _, o := range declared.Ops() {
		if o.CLI.Custom {
			continue
		}
		if err := build(o); err != nil {
			t.Errorf("%s: building its flags panics: %v", o.Name, err)
		}
	}
	// The check is not blind: a clash does panic.
	clash := declared.Ops()[0]
	clash.Params = append([]kit.Param{{Name: "json", Kind: kit.Bool, Help: "x"}}, clash.Params...)
	if build(clash) == nil {
		t.Error("a declared flag named like a common one must make the flag set panic")
	}
}

// kit refuses a clash with the common flags without building a flag set, from
// its own list. That list must be the list chap registers.
func TestKitKnowsTheCommonFlags(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	var co common
	co.register(fs, newTestApp(t, env{}).app)
	var got []string
	fs.VisitAll(func(f *flag.Flag) { got = append(got, f.Name) })
	slices.Sort(got)
	want := slices.Sorted(slices.Values(kit.CommonFlags))
	if !slices.Equal(got, want) {
		t.Errorf("common flags registered by chap %v, kit.CommonFlags %v", got, want)
	}
}
