// Command allowcheck fails when go.mod requires a module that is not listed in
// docs/dependencies.allow (ADR-001: "Adding a module needs a line in an ADR
// addendum"). It uses only the standard library on purpose.
//
// Usage, from the repository root:
//
//	go run ./scripts/allowcheck [-gomod go.mod] [-allow docs/dependencies.allow]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func main() {
	gomod := flag.String("gomod", "go.mod", "path to go.mod")
	allow := flag.String("allow", "docs/dependencies.allow", "path to the allowlist")
	flag.Parse()
	os.Exit(run(*gomod, *allow, os.Stdout, os.Stderr))
}

func run(gomodPath, allowPath string, stdout, stderr io.Writer) int {
	gm, err := os.Open(gomodPath)
	if err != nil {
		fmt.Fprintf(stderr, "allowcheck: %v\n", err)
		return 2
	}
	defer gm.Close()
	al, err := os.Open(allowPath)
	if err != nil {
		fmt.Fprintf(stderr, "allowcheck: %v\n", err)
		return 2
	}
	defer al.Close()

	required, err := requiredModules(gm)
	if err != nil {
		fmt.Fprintf(stderr, "allowcheck: %s: %v\n", gomodPath, err)
		return 2
	}
	allowed, err := allowedModules(al)
	if err != nil {
		fmt.Fprintf(stderr, "allowcheck: %s: %v\n", allowPath, err)
		return 2
	}

	var missing []string
	for _, m := range required {
		if !allowed[m] {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		fmt.Fprintf(stderr, "allowcheck: %d module(s) in %s are not in %s:\n", len(missing), gomodPath, allowPath)
		for _, m := range missing {
			fmt.Fprintf(stderr, "  %s\n", m)
		}
		fmt.Fprintln(stderr, "A new third-party module needs an allowlist line and an ADR-001 addendum (docs/adr/001-language-runtime.md).")
		return 1
	}
	fmt.Fprintf(stdout, "allowcheck: %d module(s) in %s, all allowlisted\n", len(required), gomodPath)
	return 0
}

// requiredModules returns every module path named in a require directive of
// go.mod, direct or indirect. Go 1.17+ lists every module needed to build the
// main module's packages, so this is the full set.
func requiredModules(r io.Reader) ([]string, error) {
	var out []string
	inBlock := false
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := stripComment(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch {
		case inBlock && line == ")":
			inBlock = false
		case inBlock:
			out = append(out, fields[0])
		case fields[0] == "require" && len(fields) == 2 && fields[1] == "(":
			inBlock = true
		case fields[0] == "require" && len(fields) >= 3:
			out = append(out, fields[1])
		}
	}
	return out, sc.Err()
}

// allowedModules reads one module path per line; `#` starts a comment.
func allowedModules(r io.Reader) (map[string]bool, error) {
	out := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(stripHashComment(sc.Text()))
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, " \t") {
			return nil, fmt.Errorf("line %q: want one module path per line", line)
		}
		out[line] = true
	}
	return out, sc.Err()
}

func stripComment(s string) string {
	if i := strings.Index(s, "//"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func stripHashComment(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	return s
}
