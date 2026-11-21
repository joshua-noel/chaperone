package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const repoRoot = "../../.."

func TestNamesAreChecked(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"", "a", "Notes", "my-notes", "9lives", "go", "func", "waytoolongaconnectornameyes", "no_te", "main"} {
		if err := checkName(root, name); err == nil {
			t.Errorf("%q was accepted", name)
		}
	}
	for _, name := range []string{"notes", "crm2", "ab"} {
		if err := checkName(root, name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	// A name that is taken is refused, in the real tree: the tool never overwrites.
	if err := checkName(repoRoot, "linear"); err == nil {
		t.Error("an existing connector's name was accepted")
	}
}

func TestRenderedGoIsFormattedAndParses(t *testing.T) {
	files, err := Render("example.test/mod", "notes")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/connectors/notes/adapter.go",
		"internal/connectors/notes/client.go",
		"internal/connectors/notes/conformance_test.go",
		"internal/connectors/notes/doc.go",
		"internal/connectors/notes/notesspec/spec.go",
		"internal/connectors/notes/notestest/server.go",
	}
	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
		formatted, err := format.Source(f.Content)
		if err != nil || !bytes.Equal(formatted, f.Content) {
			t.Errorf("%s is not gofmt-clean (%v)", f.Path, err)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), f.Path, f.Content, parser.AllErrors); err != nil {
			t.Errorf("%s: %v", f.Path, err)
		}
		if strings.Contains(string(f.Content), "@{") || strings.Contains(string(f.Content), "}@") {
			t.Errorf("%s has a template mark left", f.Path)
		}
		if !strings.Contains(string(f.Content), "example.test/mod") && strings.HasSuffix(f.Path, "adapter.go") {
			t.Errorf("%s does not use the module path", f.Path)
		}
	}
	for _, p := range want {
		if !got[p] {
			t.Errorf("%s is not generated", p)
		}
	}
	if len(files) != len(want) {
		t.Errorf("%d files, want %d", len(files), len(want))
	}
}

// The tool registers nothing: it writes inside its own folder and touches no
// shared file, and it prints the steps that stay by hand.
func TestRunWritesOnlyItsOwnFolderAndSaysWhatIsLeft(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test/mod\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"-root", root, "notes"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var written []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			written = append(written, filepath.ToSlash(rel))
		}
		return nil
	})
	for _, p := range written {
		if p != "go.mod" && !strings.HasPrefix(p, "internal/connectors/notes/") {
			t.Errorf("the tool wrote %s, outside its own folder", p)
		}
	}
	for _, step := range []string{"declared.go", "baseline.yaml", "pintable.go", "cmd/chapd/linear.go", "go generate", "Nothing is registered"} {
		if !strings.Contains(out.String(), step) {
			t.Errorf("the hand steps do not mention %q:\n%s", step, out.String())
		}
	}
	// A second run does not overwrite.
	out.Reset()
	errb.Reset()
	if code := run([]string{"-root", root, "notes"}, &out, &errb); code == 0 || !strings.Contains(errb.String(), "exists already") {
		t.Errorf("a second run did not refuse: exit %d %s", code, errb.String())
	}
	// A dry run writes nothing.
	other := t.TempDir()
	_ = os.WriteFile(filepath.Join(other, "go.mod"), []byte("module example.test/mod\n"), 0o644)
	if code := run([]string{"-root", other, "-dry-run", "notes"}, &out, &errb); code != 0 {
		t.Fatalf("dry run exit %d: %s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(other, "internal")); err == nil {
		t.Error("a dry run wrote files")
	}
}

// ---- build and run the generated connector in the real module ----------------
//
// The generated code imports packages of this module that are internal, so it
// has to be compiled inside the module. The test does that without touching
// the working tree: it maps the generated files into the module with the go
// command's -overlay, builds and tests them, and writes nothing under the
// repository.

func goTool(t *testing.T) string {
	t.Helper()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	p := filepath.Join(runtime.GOROOT(), "bin", "go"+exe)
	if _, err := os.Stat(p); err != nil {
		var lerr error
		if p, lerr = exec.LookPath("go"); lerr != nil {
			t.Skip("no go command to build the generated connector with")
		}
	}
	return p
}

// makeDirs creates the folders of the generated packages, empty, and removes
// them when the test ends. The go command runs vet and the test binary inside
// each package's folder, so they must exist; the files themselves come from
// the overlay. The test never writes a file under the repository.
func makeDirs(t *testing.T, files []file) {
	t.Helper()
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	clearLeftovers(t, root)
	top := filepath.Join(root, filepath.FromSlash(strings.Join(strings.SplitN(files[0].Path, "/", 4)[:3], "/")))
	if _, err := os.Stat(top); err == nil {
		t.Fatalf("%s exists: the test would delete it", top)
	}
	t.Cleanup(func() { _ = os.RemoveAll(top) })
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, filepath.FromSlash(f.Path))), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// goWithOverlay maps files (path under the root -> content) into the module and
// runs the go command with them. Call makeDirs first.
func goWithOverlay(t *testing.T, files []file, content map[string][]byte, args ...string) (string, error) {
	t.Helper()
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	replace := map[string]string{}
	for i, f := range files {
		body := f.Content
		if c, ok := content[f.Path]; ok {
			body = c
		}
		tmp := filepath.Join(dir, strings.ReplaceAll(filepath.Base(f.Path), ".", "_")+"_"+string(rune('a'+i))+".go")
		if err := os.WriteFile(tmp, body, 0o644); err != nil {
			t.Fatal(err)
		}
		replace[filepath.Join(root, filepath.FromSlash(f.Path))] = tmp
	}
	ov, _ := json.Marshal(map[string]any{"Replace": replace})
	ovPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(ovPath, ov, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goTool(t), append([]string{args[0], "-overlay=" + ovPath}, args[1:]...)...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestGeneratedConnectorBuildsAndItsSuiteSaysWhatIsNotWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the generated connector")
	}
	name := uniqueName()
	files, err := Render("github.com/joshua-noel/chaperone", name)
	if err != nil {
		t.Fatal(err)
	}
	makeDirs(t, files)
	pkgs := "./internal/connectors/" + name + "/..."

	if out, err := goWithOverlay(t, files, nil, "vet", pkgs); err != nil {
		t.Fatalf("go vet of the generated connector: %v\n%s", err, out)
	}

	// As generated, the suite runs and fails where the stubs refuse, and only there.
	out, err := goWithOverlay(t, files, nil, "test", "-count=1", "-v", pkgs)
	if err == nil {
		t.Fatalf("the generated test passes with the stubs; it must fail until Check and Execute are written:\n%s", out)
	}
	var failing, passing []string
	failLine := regexp.MustCompile(`--- (FAIL|PASS): TestConformance/\S+/(\w+) `)
	for _, m := range failLine.FindAllStringSubmatch(out, -1) {
		if m[1] == "FAIL" {
			failing = append(failing, m[2])
		} else {
			passing = append(passing, m[2])
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "conformance.go:") && !strings.Contains(line, "is not implemented yet") {
			t.Errorf("a failure that is not about the stubs: %s", strings.TrimSpace(line))
		}
	}
	if len(failing) == 0 {
		t.Fatalf("no check failed:\n%s", out)
	}
	for _, id := range []string{"refusals_have_a_known_code", "class_matches_pin"} {
		if !contains(passing, id) {
			t.Errorf("check %s should pass with the stubs (it tests what is already written); passing: %v\n%s", id, passing, out)
		}
	}
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// The walkthrough of docs/write-a-connector.md gives the code of the two
// methods. Applied to the generated adapter, the suite passes: the guide is
// followed here, not just read.
func TestTheGuidesImplementationPassesTheSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the generated connector")
	}
	name := uniqueName()
	files, err := Render("github.com/joshua-noel/chaperone", name)
	if err != nil {
		t.Fatal(err)
	}
	guide, err := os.ReadFile(filepath.Join(repoRoot, "docs", "write-a-connector.md"))
	if err != nil {
		t.Fatal(err)
	}
	impl := guideBlock(t, string(guide), "// guide:show-implementation")
	adapterPath := "internal/connectors/" + name + "/adapter.go"
	var adapter []byte
	for _, f := range files {
		if f.Path == adapterPath {
			adapter = f.Content
		}
	}
	cut := bytes.Index(adapter, []byte("// ---- written by hand from here"))
	if cut < 0 {
		t.Fatal("the generated adapter has no marker line for the part written by hand")
	}
	implemented, err := format.Source(append(append([]byte(nil), adapter[:cut]...), []byte(impl)...))
	if err != nil {
		t.Fatalf("the guide's code does not make Go source: %v", err)
	}
	makeDirs(t, files)
	pkgs := "./internal/connectors/" + name + "/..."
	out, err := goWithOverlay(t, files, map[string][]byte{adapterPath: implemented}, "test", "-count=1", "-v", pkgs)
	if err != nil {
		t.Fatalf("the generated connector with the guide's code fails the suite: %v\n%s", err, out)
	}
	for _, id := range []string{"check_has_no_side_effects", "execute_acts_once", "no_secret_in_output", "refusals_have_a_known_code", "params_and_limits_are_enforced", "service_text_is_untrusted", "class_matches_pin"} {
		if !strings.Contains(out, "--- PASS: TestConformance/"+name+".show/"+id) {
			t.Errorf("check %s did not run and pass:\n%s", id, out)
		}
	}
}

// guideBlock returns the fenced Go block of the guide that holds marker.
func guideBlock(t *testing.T, doc, marker string) string {
	t.Helper()
	parts := strings.Split(doc, "```")
	for i := 1; i < len(parts); i += 2 {
		body, ok := strings.CutPrefix(parts[i], "go\n")
		if ok && strings.Contains(body, marker) {
			return body
		}
	}
	t.Fatalf("docs/write-a-connector.md has no Go block with the line %q", marker)
	return ""
}

// uniqueName is a connector name that no run has used before, so a run that
// was killed and left its folder cannot block the next one.
func uniqueName() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "zz" + hex.EncodeToString(b)
}

// clearLeftovers removes folders of earlier runs of these tests that were
// killed: a folder named zz<hex> under internal/connectors that holds no file.
func clearLeftovers(t *testing.T, root string) {
	t.Helper()
	old, _ := filepath.Glob(filepath.Join(root, "internal", "connectors", "zz*"))
	for _, dir := range old {
		empty := true
		_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				empty = false
			}
			return nil
		})
		if empty {
			_ = os.RemoveAll(dir)
		}
	}
}
