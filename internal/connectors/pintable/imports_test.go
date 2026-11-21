package pintable

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The pin table is the second, deliberate copy of a class. Production code
// that read it would make the two copies drift together, so only tests may
// import it. Go enforces that for a _test.go file's own symbols, not for a
// package, so this test does: no non-test file of the module imports it.
func TestOnlyTestsImportThePinTable(t *testing.T) {
	const self = "github.com/joshua-noel/chaperone/internal/connectors/pintable"
	root := "../../.."
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return nil // a file that does not parse is another test's business
		}
		checked++
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == self {
				t.Errorf("%s imports the pin table; only _test.go files may", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 100 {
		t.Fatalf("only %d non-test files were looked at: the walk is wrong", checked)
	}
}
