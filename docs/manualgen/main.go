// Command manualgen writes docs/manual.md, the generated `chap` manual.
// The text comes from the `chap` binary itself (`chap help`, and
// `chap <command> -h` for each command's flags) and from the op catalog in
// api/manual.yaml, plus the prose in intro.md and the rules table in rules.go.
//
//	go run ./docs/manualgen            # rewrite docs/manual.md (run from the repository root)
//	go run ./docs/manualgen -chap PATH  # use a chap binary that is already built
//
// The test in this package builds chap, regenerates the manual and fails when
// docs/manual.md differs, so the manual cannot drift from the binary.
package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/joshua-noel/chaperone/internal/policy"
)

//go:embed intro.md
var intro string

func main() {
	chapBin := flag.String("chap", "", "path of a built chap binary (default: build ./cmd/chap)")
	out := flag.String("out", filepath.Join("docs", "manual.md"), "file to write")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: go run ./docs/manualgen [-chap PATH] [-out FILE]")
		os.Exit(2)
	}
	bin := *chapBin
	if bin == "" {
		dir, err := os.MkdirTemp("", "manualgen-")
		if err != nil {
			fatal(err)
		}
		defer os.RemoveAll(dir)
		if bin, err = buildChap(".", dir); err != nil {
			fatal(err)
		}
	}
	doc, err := generate(bin)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, doc, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", *out, len(doc))
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "manualgen: %v\n", err)
	os.Exit(1)
}

// buildChap builds ./cmd/chap of the module rooted at repo into dir.
func buildChap(repo, dir string) (string, error) {
	name := "chap"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(dir, name)
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	cmd := exec.Command(goBin, "build", "-trimpath", "-o", out, "./cmd/chap")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build ./cmd/chap: %v\n%s", err, b)
	}
	return out, nil
}

// runChap runs the binary with args and returns stdout. A -h run must exit 0.
func runChap(bin string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	// Nothing may reach a real chapd, and no credential is in scope.
	cmd.Env = []string{"CHAP_URL=http://127.0.0.1:1"}
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("chap %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.ReplaceAll(stdout.String(), "\r\n", "\n"), nil
}

// command is one leaf of chap's command tree, as `chap help` and `-h` show it.
type command struct {
	path, summary, usage string
	flags                []flagDoc
}

type flagDoc struct{ name, typ, desc string }

var helpLine = regexp.MustCompile(`^  (\S+(?: \S+)?)\s{2,}(\S.*)$`)

// parseHelp reads `chap help`: the command lines and the footer lines.
func parseHelp(help string) (cmds []command, footer []string, err error) {
	inCmds := false
	for _, line := range strings.Split(help, "\n") {
		switch {
		case line == "commands:":
			inCmds = true
		case inCmds && line == "":
			inCmds = false
		case inCmds:
			if m := helpLine.FindStringSubmatch(line); m != nil {
				cmds = append(cmds, command{path: m[1], summary: m[2]})
			} else if name := strings.TrimSpace(line); name != "" {
				cmds = append(cmds, command{path: name}) // "version" has no summary
			}
		case !inCmds && line != "" && !strings.HasPrefix(line, "usage:"):
			footer = append(footer, line)
		}
	}
	if len(cmds) == 0 {
		return nil, nil, errors.New("chap help lists no commands")
	}
	return cmds, footer, nil
}

// parseFlags reads `chap <command> -h`: "usage: ...", the summary, then the
// flag package's PrintDefaults layout ("  -name type", tab-indented text).
func parseFlags(c *command, h string) error {
	lines := strings.Split(strings.TrimRight(h, "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "usage: ") {
		return fmt.Errorf("chap %s -h: unexpected output %q", c.path, h)
	}
	c.usage = strings.TrimPrefix(lines[0], "usage: ")
	c.summary = lines[1]
	for _, l := range lines[2:] {
		switch {
		case strings.HasPrefix(l, "  -"):
			f := strings.Fields(l)
			fd := flagDoc{name: strings.TrimPrefix(f[0], "-")}
			if len(f) > 1 {
				fd.typ = f[1]
			}
			c.flags = append(c.flags, fd)
		case strings.HasPrefix(l, "    \t") && len(c.flags) > 0:
			last := &c.flags[len(c.flags)-1]
			if last.desc != "" {
				last.desc += " "
			}
			last.desc += strings.TrimSpace(l)
		default:
			return fmt.Errorf("chap %s -h: unexpected line %q", c.path, l)
		}
	}
	return nil
}

func esc(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// generate builds the manual from the chap binary at bin.
func generate(bin string) ([]byte, error) {
	help, err := runChap(bin, "help")
	if err != nil {
		return nil, err
	}
	cmds, footer, err := parseHelp(help)
	if err != nil {
		return nil, err
	}
	var leaves []command
	for _, c := range cmds {
		if c.path == "version" || c.path == "logo" || c.path == "mcp" {
			continue
		}
		out, err := runChap(bin, append(strings.Fields(c.path), "-h")...)
		if err != nil {
			return nil, err
		}
		if err := parseFlags(&c, out); err != nil {
			return nil, err
		}
		leaves = append(leaves, c)
	}

	var b strings.Builder
	b.WriteString(intro)

	cat, err := policy.DefaultCatalog()
	if err != nil {
		return nil, err
	}
	b.WriteString("\n## What you can ask for\n\nThe op catalog (`api/manual.yaml`). Whether an op is switched on is policy, per project: `chap manual` lists what is on for you, `chap manual --all` (orchestrator) also what is off.\n\n")
	b.WriteString("| Op | Class | Reversibility | Surface | What it does | How |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, op := range cat.Ops() {
		e, _ := cat.Lookup(op)
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | `%s` |\n", op, e.Class, e.Reversibility, e.Surface, esc(e.Summary), esc(e.Usage))
	}
	b.WriteString("\nSurface `op` is `POST /v0/ops`; surface `git` is the git proxy (`chap git setup`, then `git push`).\n")

	b.WriteString("\n## Commands\n\n| Command | What it does |\n| --- | --- |\n")
	b.WriteString("| `chap logo` | show the CHAPERONE banner |\n| `chap mcp` | serve the ops as MCP tools over stdio (Claude Code, Codex, Cursor) |\n| `chap version` | print the build identity |\n")
	for _, c := range leaves {
		fmt.Fprintf(&b, "| `chap %s` | %s |\n", c.path, esc(c.summary))
	}
	for _, c := range leaves {
		fmt.Fprintf(&b, "\n### `chap %s`\n\n%s\n\n```\n%s\n```\n", c.path, c.summary, c.usage)
		if len(c.flags) == 0 {
			continue
		}
		b.WriteString("\n| Flag | Meaning |\n| --- | --- |\n")
		for _, f := range c.flags {
			name := "--" + f.name
			if f.typ != "" {
				name += " <" + f.typ + ">"
			}
			fmt.Fprintf(&b, "| `%s` | %s |\n", name, esc(f.desc))
		}
	}

	b.WriteString("\n## Exit codes\n\nScripts and agents branch on these. New codes are added; an existing code keeps its meaning (`TestExitCodes`).\n\n| Code | Meaning |\n| --- | --- |\n")
	codes, err := exitCodes(footer)
	if err != nil {
		return nil, err
	}
	for _, c := range codes {
		fmt.Fprintf(&b, "| %s | %s |\n", c[0], c[1])
	}

	b.WriteString("\n## Rules this manual states, and where the code enforces them\n\n")
	b.WriteString("Every rule below has a test that fails if the code stops enforcing it. `go test ./docs/manualgen` also checks that each of these tests exists, and that every absolute promise in this manual is one of these rules.\n\n")
	b.WriteString("| Rule | Enforced in | Test |\n| --- | --- | --- |\n")
	for _, r := range rules {
		tests := make([]string, len(r.Tests))
		for i, t := range r.Tests {
			tests[i] = "`" + t.Name + "` (" + t.Pkg + ")"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", esc(r.Text), esc(r.Where), strings.Join(tests, ", "))
	}
	return []byte(b.String()), nil
}

var exitLine = regexp.MustCompile(`^exit: (.*)\.$`)

// exitCodes reads the "exit: 0 ok, 2 usage, ..." footer line of `chap help`.
func exitCodes(footer []string) ([][2]string, error) {
	for _, l := range footer {
		m := exitLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		var out [][2]string
		for _, part := range strings.Split(m[1], ", ") {
			code, meaning, ok := strings.Cut(part, " ")
			if !ok {
				return nil, fmt.Errorf("exit footer: bad entry %q", part)
			}
			out = append(out, [2]string{code, meaning})
		}
		return out, nil
	}
	return nil, errors.New("chap help has no exit-code line")
}
