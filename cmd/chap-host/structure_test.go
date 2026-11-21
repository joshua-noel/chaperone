package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func parseDir(t *testing.T, dir string) map[string]*ast.File {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no files in %s: %v", dir, err)
	}
	out := map[string]*ast.File{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(f)] = parsed
	}
	return out
}

// A fault in the helper must not reach the vault: it imports neither the
// vault, the store, nor the redaction registry (which holds secret values).
// internal/logrot is allowed: it is a stdlib-only rotating log file. So is internal/privfile: it makes a new file
// that only the current user can open and never follows a link (it imports the standard library and x/sys/windows).
func TestHelperCannotReachVault(t *testing.T) {
	for _, dir := range []string{".", "../../internal/grant"} {
		for name, f := range parseDir(t, dir) {
			for _, imp := range f.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(path, "github.com/joshua-noel/chaperone/") &&
					path != "github.com/joshua-noel/chaperone/internal/grant" &&
					path != "github.com/joshua-noel/chaperone/internal/logrot" &&
					path != "github.com/joshua-noel/chaperone/internal/privfile" &&
					path != "github.com/joshua-noel/chaperone/internal/version" {
					t.Errorf("%s/%s imports %s", dir, name, path)
				}
				if strings.Contains(path, "sqlite") || path == "net/http/httputil" {
					t.Errorf("%s/%s imports %s", dir, name, path)
				}
			}
		}
	}
}

// No free-form command: processes start in exactly two places (the runner,
// the toast), a listener never exists, and the runner's argv comes from the
// fixed table, not from a parameter of the runner.
func TestNoFreeFormCommand(t *testing.T) {
	allowedExec := map[string]bool{"runner.go": true, "toast.go": true}
	for name, f := range parseDir(t, ".") {
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok {
						switch {
						case id.Name == "exec" && strings.HasPrefix(sel.Sel.Name, "Command") && !allowedExec[name]:
							t.Errorf("%s starts a process", name)
						case id.Name == "net" && strings.HasPrefix(sel.Sel.Name, "Listen"):
							t.Errorf("%s opens a listener", name)
						case id.Name == "http" && (strings.HasPrefix(sel.Sel.Name, "ListenAndServe") || sel.Sel.Name == "Serve"):
							t.Errorf("%s serves HTTP", name)
						}
					}
				}
			}
			return true
		})
	}

	// Runner.Run takes the grant string and an output writer: no command,
	// argument or path parameter.
	for _, decl := range parseDir(t, ".")["runner.go"].Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Run" {
			var types []string
			for _, p := range fn.Type.Params.List {
				types = append(types, types2s(p.Type))
			}
			if strings.Join(types, ",") != "context.Context,string,io.Writer" {
				t.Errorf("Runner.Run parameters: %v", types)
			}
		}
	}

	// The command line accepts no subcommand but version and run, and run has
	// one path flag (-config) and one log folder flag (-log-dir).
	for _, args := range [][]string{{"exec"}, {"sh"}, {"shell"}, {"cmd"}, {"powershell"}, {"run-script"}, {"runbook"}} {
		var out, errb strings.Builder
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	for _, args := range [][]string{{"run", "-exec", "id"}, {"run", "-c", "id"}, {"run", "id"}, {"run", "-config"}} {
		var out, errb strings.Builder
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func types2s(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return types2s(x.X) + "." + x.Sel.Name
	}
	return "?"
}
