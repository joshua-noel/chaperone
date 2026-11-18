package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/spec"
)

const repoRoot = "../.."

var (
	buildOnce sync.Once
	chapBin   string
	buildErr  error
	buildDir  string
)

// builtChap builds ./cmd/chap once for the whole package.
func builtChap(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "manualgen-test-")
		if buildErr == nil {
			chapBin, buildErr = buildChap(repoRoot, buildDir)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return chapBin
}

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

func generated(t *testing.T) string {
	t.Helper()
	doc, err := generate(builtChap(t))
	if err != nil {
		t.Fatal(err)
	}
	return string(doc)
}

// The manual on disk is what the generator writes now.
func TestManualIsCurrent(t *testing.T) {
	want := generated(t)
	got, err := os.ReadFile(filepath.Join("..", "manual.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
		t.Fatal("docs/manual.md is out of date: run `go run ./docs/manualgen` from the repository root and commit the result")
	}
}

var never = regexp.MustCompile(`(?i)\bnever\b`)

// Every absolute promise in the manual is covered by a rule, and every rule's
// phrases are really in the manual (so a rule cannot outlive its sentence).
func TestEveryNeverIsAnEnforcedRule(t *testing.T) {
	doc := generated(t)
	for _, line := range strings.Split(doc, "\n") {
		if !never.MatchString(line) {
			continue
		}
		covered := false
		for _, r := range rules {
			for _, c := range r.Covers {
				if strings.Contains(line, c) {
					covered = true
				}
			}
		}
		if !covered {
			t.Errorf("the manual makes a promise no rule covers (add a rule with a test, or reword): %q", line)
		}
	}
	for _, r := range rules {
		for _, c := range r.Covers {
			if !strings.Contains(doc, c) {
				t.Errorf("rule %q covers %q, which is no longer in the manual", r.Text, c)
			}
		}
	}
}

// Every test a rule names exists.
func TestRuleTestsExist(t *testing.T) {
	for _, r := range rules {
		if len(r.Tests) == 0 {
			t.Errorf("rule without a test: %q", r.Text)
		}
		for _, ref := range r.Tests {
			files, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(ref.Pkg), "*_test.go"))
			if err != nil || len(files) == 0 {
				t.Errorf("%s: no test files in %s", ref.Name, ref.Pkg)
				continue
			}
			found := false
			for _, f := range files {
				b, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(b), "\nfunc "+ref.Name+"(t *testing.T)") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s is not a test function in %s", ref.Name, ref.Pkg)
			}
		}
	}
}

var credentialish = regexp.MustCompile(`(?i)token|secret|password|passwd|credential|key`)

// No `chap` flag is named for a credential: nothing a person types on a command
// line can carry a token or a secret into a process list or a shell history.
func TestNoFlagNamesACredential(t *testing.T) {
	help, err := runChap(builtChap(t), "help")
	if err != nil {
		t.Fatal(err)
	}
	cmds, _, err := parseHelp(help)
	if err != nil {
		t.Fatal(err)
	}
	flags := 0
	for _, c := range cmds {
		if c.path == "version" || c.path == "logo" {
			continue
		}
		h, err := runChap(builtChap(t), append(strings.Fields(c.path), "-h")...)
		if err != nil {
			t.Fatal(err)
		}
		if err := parseFlags(&c, h); err != nil {
			t.Fatal(err)
		}
		for _, f := range c.flags {
			flags++
			if credentialish.MatchString(f.name) {
				t.Errorf("chap %s has a flag named --%s", c.path, f.name)
			}
		}
	}
	if flags < 20 {
		t.Fatalf("parsed only %d flags: the parser is broken", flags)
	}
}

// `chap` has one command in the approve group, and it only lists.
func TestChapHasNoApproveVerb(t *testing.T) {
	help, err := runChap(builtChap(t), "help")
	if err != nil {
		t.Fatal(err)
	}
	cmds, _, err := parseHelp(help)
	if err != nil {
		t.Fatal(err)
	}
	var approve []string
	for _, c := range cmds {
		if strings.Contains(c.path, "approve") || strings.Contains(c.path, "decide") || strings.Contains(c.path, "deny") {
			approve = append(approve, c.path)
		}
	}
	if len(approve) != 1 || approve[0] != "approve list" {
		t.Fatalf("approval-related commands: %v, want only [approve list]", approve)
	}
}

// The op hash an approval binds to does not cover the reason.
func TestReasonIsNotPartOfTheOpHash(t *testing.T) {
	req := func(reason string, param string) spec.Request {
		return spec.Request{
			SpecVersion: spec.SpecVersion, Type: "op.request", RequestID: "q-1a2b3c4d5e",
			Requester: spec.Requester{Kind: "orchestrator", ID: "main"},
			Project:   "acme-shop", Op: "deploy", Target: spec.Target{Adapter: "wsl-host", Ref: "pilot"},
			Params: map[string]any{"sha": param}, Reason: reason,
			RequestedAt: "2026-10-24T12:00:00Z", ExpiresAt: "2026-10-24T12:30:00Z",
		}
	}
	sha := strings.Repeat("a", 40)
	h1, err := spec.OpHash(req("ship the fix", sha))
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := spec.OpHash(req("something quite different", sha))
	if h1 != h2 {
		t.Error("the reason changes the op hash")
	}
	if h3, _ := spec.OpHash(req("ship the fix", strings.Repeat("b", 40))); h3 == h1 {
		t.Error("control failed: a different param gives the same op hash")
	}
}

// No policy rule and no adapter reads the request's reason: it is data for the
// card and the record, not an input to a decision.
func TestNoAdapterOrPolicyReadsTheReason(t *testing.T) {
	var files []string
	for _, pat := range []string{
		"internal/policy/*.go", "internal/ops/pr_*.go", "internal/ops/deploy*.go",
		"internal/ops/health*.go", "internal/ops/git_gate*.go", "adapters/*/*.go",
	} {
		m, err := filepath.Glob(filepath.Join(repoRoot, filepath.FromSlash(pat)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	read := regexp.MustCompile(`\.Reason\b`)
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if read.Match(b) {
			t.Errorf("%s reads a .Reason field: check that it is not an input to a decision, then narrow this test", f)
		}
	}
	if checked < 10 {
		t.Fatalf("scanned %d files: the glob is wrong", checked)
	}
}

var usageFlag = regexp.MustCompile(`--([a-z][a-z-]*)`)

// Every command line the catalog shows is a line `chap` accepts: the command
// exists and each flag in the usage is one of its flags.
func TestCatalogUsageMatchesChap(t *testing.T) {
	bin := builtChap(t)
	help, err := runChap(bin, "help")
	if err != nil {
		t.Fatal(err)
	}
	cmds, _, err := parseHelp(help)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]map[string]bool{}
	for _, c := range cmds {
		if c.path == "version" || c.path == "logo" {
			continue
		}
		h, err := runChap(bin, append(strings.Fields(c.path), "-h")...)
		if err != nil {
			t.Fatal(err)
		}
		if err := parseFlags(&c, h); err != nil {
			t.Fatal(err)
		}
		byPath[c.path] = map[string]bool{}
		for _, f := range c.flags {
			byPath[c.path][f.name] = true
		}
	}
	cat, err := policy.DefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range cat.Ops() {
		e, _ := cat.Lookup(op)
		stmt, _, _ := strings.Cut(e.Usage, ";")
		words := strings.Fields(stmt)
		if len(words) < 2 || words[0] != "chap" {
			t.Errorf("%s: usage %q does not start with chap", op, e.Usage)
			continue
		}
		var flags map[string]bool
		for _, n := range []int{2, 1} {
			if len(words) > n {
				if f, ok := byPath[strings.Join(words[1:1+n], " ")]; ok {
					flags = f
					break
				}
			}
		}
		if flags == nil {
			t.Errorf("%s: no chap command matches %q", op, stmt)
			continue
		}
		for _, m := range usageFlag.FindAllStringSubmatch(stmt, -1) {
			if !flags[m[1]] {
				t.Errorf("%s: usage %q names --%s, which that chap command does not have", op, stmt, m[1])
			}
		}
	}
}
