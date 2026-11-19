// Command scaffold writes the skeleton of a new connector:
//
//	go run ./internal/connectors/scaffold -root . <name>
//
// It creates internal/connectors/<name>/ with a declaration that has one example
// read-only operation, an adapter whose Check and Execute refuse until they are
// written, a small HTTP client, a fake service, and a test that already calls the
// conformance suite (internal/connectors/conformance).
//
// It is a command under internal/connectors and not a `chap` subcommand on
// purpose. `chap` is the client an agent runs: it is small, it links the kit
// and nothing of the daemon, and it must not have a verb that writes Go source
// into a checkout. Writing a connector is a developer's act, done in a clone of
// the repository, and a `go run` tool is exactly that.
//
// It registers nothing. The connector list, the catalog, the baseline policy and
// chapd's wiring are changed by hand, deliberately, and the tool prints which.
package main

import (
	"bufio"
	"embed"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

//go:embed templates/*.tmpl
var templates embed.FS

// nameRE is a connector name: a lower-case Go package name, short, with no
// dash (the connector's packages are named from it).
var nameRE = regexp.MustCompile(`^[a-z][a-z0-9]{1,19}$`)

// A file the tool writes: its path under the repository root and its content.
type file struct {
	Path    string
	Content []byte
}

// plan lists the files of a connector called name: the path under the
// repository root and the template each is made from.
func plan(name string) []struct{ out, tmpl string } {
	dir := "internal/connectors/" + name
	return []struct{ out, tmpl string }{
		{dir + "/doc.go", "doc.go.tmpl"},
		{dir + "/adapter.go", "adapter.go.tmpl"},
		{dir + "/client.go", "client.go.tmpl"},
		{dir + "/conformance_test.go", "conformance_test.go.tmpl"},
		{dir + "/" + name + "spec/spec.go", "spec.go.tmpl"},
		{dir + "/" + name + "test/server.go", "server.go.tmpl"},
	}
}

// checkName refuses a name that cannot be a connector, and one that is taken.
func checkName(root, name string) error {
	switch {
	case !nameRE.MatchString(name):
		return fmt.Errorf("%q is not a connector name: use 2 to 20 lower-case letters and digits, starting with a letter (the packages are named from it)", name)
	case name == "main":
		return fmt.Errorf("%q cannot name a package of a connector (it is the name of a program, and a connector is a library package)", name)
	case token.IsKeyword(name):
		return fmt.Errorf("%q is a Go keyword", name)
	}
	if _, err := os.Stat(filepath.Join(root, "internal", "connectors", name)); err == nil {
		return fmt.Errorf("internal/connectors/%s exists already; the tool never overwrites", name)
	}
	return nil
}

// modulePath reads the module path from go.mod under root.
func modulePath(root string) (string, error) {
	f, err := os.Open(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("%s is not the repository root: %w", root, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(m), `"`), nil
		}
	}
	return "", errors.New("go.mod has no module line")
}

// Render makes the files of a connector called name for the module. It writes
// nothing. Every Go file is formatted, so the output is gofmt-clean.
func Render(module, name string) ([]file, error) {
	data := struct{ Name, Module string }{Name: name, Module: module}
	var out []file
	for _, p := range plan(name) {
		src, err := fs.ReadFile(templates, "templates/"+p.tmpl)
		if err != nil {
			return nil, err
		}
		t, err := template.New(p.tmpl).Delims("@{", "}@").Option("missingkey=error").Parse(string(src))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.tmpl, err)
		}
		var b strings.Builder
		if err := t.Execute(&b, data); err != nil {
			return nil, fmt.Errorf("%s: %w", p.tmpl, err)
		}
		formatted, err := format.Source([]byte(b.String()))
		if err != nil {
			return nil, fmt.Errorf("%s does not make Go source: %w", p.tmpl, err)
		}
		out = append(out, file{Path: p.out, Content: formatted})
	}
	return out, nil
}

// write creates the files under root. When one fails, the connector's folder,
// which did not exist before, is removed again.
func write(root, name string, files []file) error {
	dir := filepath.Join(root, "internal", "connectors", name)
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			_ = os.RemoveAll(dir)
			return err
		}
		if err := os.WriteFile(p, f.Content, 0o644); err != nil {
			_ = os.RemoveAll(dir)
			return err
		}
	}
	return nil
}

// handSteps is what the tool prints after it wrote the files. Each is a step
// that stays deliberate.
func handSteps(name string) string {
	return strings.NewReplacer("{name}", name).Replace(`
Nothing is registered and nothing is turned on. These steps stay by hand, in this order:

  1. Declare your operations in internal/connectors/{name}/{name}spec/spec.go (replace the example),
     and write Check and Execute of each in internal/connectors/{name}/adapter.go.
  2. Make the suite pass:  go test ./internal/connectors/{name}/...
  3. Pin the classes: add each operation to internal/connectors/pintable/pintable.go, then in
     internal/connectors/{name}/conformance_test.go replace the local pins with pintable.Pins.
  4. Register the declaration: add {name}spec.Connector to Connectors() in
     internal/connectors/declared/declared.go, then run
       go generate ./internal/connectors/...
       go run ./docs/manualgen
       go test ./cmd/chap -update
  5. Wire the adapters into chapd: build the client and call {name}.Adapters, as
     installLinear in cmd/chapd/linear.go does.
  6. Add the baseline rule, off, to internal/policy/data/baseline.yaml. The rate must equal the declared one:
       <op name>: { enabled: false, rate_per_minute: <rate> }
     Turning an operation on is a separate, reviewed policy change.

The whole walkthrough is docs/write-a-connector.md.
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scaffold", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "the repository root")
	dry := flags.Bool("dry-run", false, "list the files and write nothing")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: go run ./internal/connectors/scaffold [-root <dir>] [-dry-run] <name>")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return 2
	}
	name := flags.Arg(0)
	fail := func(err error) int {
		fmt.Fprintln(stderr, "scaffold:", err)
		return 1
	}
	module, err := modulePath(*root)
	if err != nil {
		return fail(err)
	}
	if err := checkName(*root, name); err != nil {
		return fail(err)
	}
	files, err := Render(module, name)
	if err != nil {
		return fail(err)
	}
	if !*dry {
		if err := write(*root, name, files); err != nil {
			return fail(err)
		}
	}
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = path.Clean(f.Path)
	}
	sort.Strings(paths)
	verb := "wrote"
	if *dry {
		verb = "would write"
	}
	for _, p := range paths {
		fmt.Fprintf(stdout, "scaffold: %s %s\n", verb, p)
	}
	fmt.Fprint(stdout, handSteps(name))
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
