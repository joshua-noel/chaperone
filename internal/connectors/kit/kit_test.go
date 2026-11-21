package kit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// good is a small valid operation the cases below break one rule at a time.
func good() Op {
	return Op{
		Name:          "notes.show",
		Class:         Routine,
		Reversibility: Reversible,
		Summary:       "Show one note.",
		Usage:         "chap notes show <N-1>",
		RatePerMinute: 6,
		Doc:           "Target is `{adapter: notes, ref: \"<id>\"}`. No params.",
		Target: Target{
			Adapter:    "notes",
			Pattern:    `^N-[0-9]{1,6}$`,
			Why:        "the note must be an identifier such as N-1",
			Positional: "N-1",
		},
	}
}

func TestValidAndInvalidDeclarations(t *testing.T) {
	if err := good().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(o *Op){
		"name without a group":         func(o *Op) { o.Name = "show" },
		"name in capitals":             func(o *Op) { o.Name = "Notes.show" },
		"unknown class":                func(o *Op) { o.Class = "low" },
		"unknown reversibility":        func(o *Op) { o.Reversibility = "undoable" },
		"irreversible but routine":     func(o *Op) { o.Reversibility = Irreversible },
		"irreversible but gated":       func(o *Op) { o.Reversibility = Irreversible; o.Class = Gated },
		"summary too long":             func(o *Op) { o.Summary = strings.Repeat("x", 61) },
		"usage too long":               func(o *Op) { o.Usage = "chap notes show " + strings.Repeat("x", 100) },
		"no rate":                      func(o *Op) { o.RatePerMinute = 0 },
		"no doc":                       func(o *Op) { o.Doc = " " },
		"control character in the doc": func(o *Op) { o.Doc = "a\x00b" },
		"newline in the summary":       func(o *Op) { o.Summary = "a\nb" },
		"target with both ref kinds": func(o *Op) {
			o.Target.Flag, o.Target.Placeholder, o.Target.Default, o.Target.Help = "id", "n", "x", "h"
		},
		"target with neither":      func(o *Op) { o.Target.Positional = "" },
		"target without Why":       func(o *Op) { o.Target.Why = "" },
		"unanchored pattern":       func(o *Op) { o.Target.Pattern = `N-[0-9]+` },
		"broken pattern":           func(o *Op) { o.Target.Pattern = `^N-(` + "$" },
		"bad adapter":              func(o *Op) { o.Target.Adapter = "Notes" },
		"usage names no such flag": func(o *Op) { o.Usage = "chap notes show <N-1> --colour" },
		"usage of another command": func(o *Op) { o.Usage = "chap notes list" },
		"bool that is required":    func(o *Op) { o.Params = []Param{{Name: "all", Kind: Bool, Required: true, Help: "h"}} },
		"bool without help":        func(o *Op) { o.Params = []Param{{Name: "all", Kind: Bool}} },
		"string without a bound":   func(o *Op) { o.Params = []Param{{Name: "q", Kind: String, Placeholder: "q", Help: "h"}} },
		"text not named body":      func(o *Op) { o.Params = []Param{{Name: "note", Kind: Text, MaxLength: 10}} },
		"a param twice": func(o *Op) {
			o.Params = []Param{{Name: "all", Kind: Bool, Help: "h"}, {Name: "all", Kind: Bool, Help: "h"}}
		},
		"flag of a common one": func(o *Op) {
			o.Params = []Param{{Name: "json", Kind: Bool, Help: "h"}}
		},
		"unknown kind": func(o *Op) { o.Params = []Param{{Name: "all", Kind: 9}} },
	}
	for name, mutate := range cases {
		o := good()
		mutate(&o)
		if err := o.Validate(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// A custom command is not held to the generic command's usage, target or
	// flag rules: its ref may be computed, and its flags are its own.
	o := good()
	o.CLI.Custom = true
	o.Usage = "chap notes display <id> --colour"
	o.Target = Target{Adapter: "notes"} // the ref comes from git, say
	o.Params = []Param{
		{Name: "note", Kind: Text, MaxLength: 10},  // not named body
		{Name: "json", Kind: String, MaxLength: 5}, // no placeholder, and a common flag's name
		{Name: "all", Kind: Bool, Required: true},  // no help
	}
	if err := o.Validate(); err != nil {
		t.Errorf("custom command: %v", err)
	}
	// What the params schema needs is still checked.
	for name, mutate := range map[string]func(o *Op){
		"bad adapter":                        func(o *Op) { o.Target.Adapter = "Notes" },
		"unknown kind":                       func(o *Op) { o.Params[0].Kind = 9 },
		"no bound":                           func(o *Op) { o.Params[0].MaxLength = 0 },
		"bad param name":                     func(o *Op) { o.Params[0].Name = "No-Good" },
		"duplicate param":                    func(o *Op) { o.Params[1].Name = "note" },
		"still not irreversible and routine": func(o *Op) { o.Reversibility = Irreversible },
	} {
		c := o
		c.Params = append([]Param(nil), o.Params...)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("custom, %s: want an error", name)
		}
	}
}

func TestConnectorValidate(t *testing.T) {
	a, b := good(), good()
	b.Name = "notes.list"
	b.Usage = "chap notes list"
	if err := (Connector{Name: "notes", Ops: []Op{a, b}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Connector{
		"no ops":         {Name: "notes"},
		"bad name":       {Name: "Notes", Ops: []Op{a}},
		"duplicate op":   {Name: "notes", Ops: []Op{a, a}},
		"two adapters":   {Name: "notes", Ops: []Op{a, func() Op { o := b; o.Target.Adapter = "other"; return o }()}},
		"an invalid one": {Name: "notes", Ops: []Op{a, func() Op { o := b; o.Class = "x"; return o }()}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestBindIsOneToOne(t *testing.T) {
	a, b := good(), good()
	b.Name = "notes.list"
	b.Usage = "chap notes list"
	c := Connector{Name: "notes", Ops: []Op{a, b}}
	got, err := Bind(c, map[string]int{"notes.show": 1, "notes.list": 2})
	if err != nil || len(got) != 2 || got["notes.list"] != 2 {
		t.Fatalf("Bind = %v, %v", got, err)
	}
	if _, err := Bind(c, map[string]int{"notes.show": 1}); err == nil || !strings.Contains(err.Error(), "notes.list") {
		t.Errorf("a declared op without an adapter must be refused: %v", err)
	}
	if _, err := Bind(c, map[string]int{"notes.show": 1, "notes.list": 2, "notes.drop": 3}); err == nil || !strings.Contains(err.Error(), "notes.drop") {
		t.Errorf("an adapter without a declaration must be refused: %v", err)
	}
	bad := a
	bad.Class = "nope"
	if _, err := Bind(Connector{Name: "notes", Ops: []Op{bad}}, map[string]int{"notes.show": 1}); err == nil {
		t.Error("Bind must refuse an invalid declaration")
	}
}

func TestDiffPins(t *testing.T) {
	c := Connector{Name: "notes", Ops: []Op{good()}}
	if d := DiffPins(c, map[string]Pin{"notes.show": {Routine, Reversible}}); len(d) != 0 {
		t.Errorf("unexpected differences: %v", d)
	}
	for name, pins := range map[string]map[string]Pin{
		"class loosened":          {"notes.show": {High, Reversible}},
		"reversibility changed":   {"notes.show": {Routine, Compensable}},
		"no pin for a new op":     {},
		"a pin with no operation": {"notes.show": {Routine, Reversible}, "notes.drop": {High, Irreversible}},
	} {
		if d := DiffPins(c, pins); len(d) == 0 {
			t.Errorf("%s: want a difference", name)
		}
	}
}

func TestDerivedCommandLine(t *testing.T) {
	o := good()
	o.Params = []Param{
		{Name: "all", Kind: Bool, Help: "h"},
		{Name: "tag", Kind: String, Placeholder: "name", Help: "h"},
		{Name: "body", Kind: Text, MaxLength: 10},
	}
	o.Target = Target{Adapter: "notes", Pattern: `^[a-z]+$`, Why: "w", Flag: "book", Placeholder: "key", Default: "main", Help: "h"}
	o.Usage = "chap notes show"
	if got, want := o.CLIUsage(), "chap notes show [--all] [--tag <name>] [--body <b> | --body-file <f>] [--book <key>]"; got != want {
		t.Errorf("usage = %q, want %q", got, want)
	}
	if got := o.CLISummary(); got != "show one note" {
		t.Errorf("summary = %q", got)
	}
	o.CLI.Summary = "write what I say"
	if got := o.CLISummary(); got != "write what I say" {
		t.Errorf("summary = %q", got)
	}
	if got := good().ParamsSchemaName(); got != "ParamsNotesShow" {
		t.Errorf("schema name = %q", got)
	}
}

func TestYAMLScalars(t *testing.T) {
	for _, s := range []string{
		"Open a pull request from the run's branch.", "chap intake list [--refresh] [--closed]", "plain words, with: a colon",
		"yes", "true", "12", "1e3", "a # comment", "ends with space ", `a "quote" and a \ slash`, "chap x: y", "- dash", "[flow]", "*star",
	} {
		doc := "k: " + yamlScalar(s) + "\n"
		var out map[string]any
		if err := yaml.Unmarshal([]byte(doc), &out); err != nil || out["k"] != s {
			t.Errorf("%q written as %q reads back as %#v (%v)", s, doc, out["k"], err)
		}
	}
	if got := yamlQuoted(`a"b\c`); got != `"a\"b\\c"` {
		t.Errorf("yamlQuoted = %s", got)
	}
}

const manualText = `version: 1
ops:
  health:
    class: routine
    reversibility: reversible
    surface: op
    summary: Read the status.
    usage: chap health
`

const openapiText = `openapi: 3.1.0
components:
  schemas:
    ParamsHealth:
      type: object
      additionalProperties: false
    ParamsDeploy:
      type: object
`

func conn() Connector {
	o := good()
	o.Params = []Param{
		{Name: "all", Kind: Bool, Help: "h"},
		{Name: "tag", Kind: String, Required: true, MinLength: 1, MaxLength: 20, Placeholder: "name", Help: "h"},
	}
	o.Usage = "chap notes show <N-1> --tag <name>"
	return Connector{Name: "notes", Ops: []Op{o}}
}

func TestSpliceAddsThenRewritesThenIsStable(t *testing.T) {
	c := conn()
	m1, err := Splice(Manual, []byte(manualText), []Connector{c})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(m1), manualText) || !strings.Contains(string(m1), "# BEGIN generated: connector notes (") || !strings.HasSuffix(string(m1), "# END generated: connector notes\n") {
		t.Fatalf("a first region goes at the end of the manual:\n%s", m1)
	}
	var doc struct {
		Ops map[string]map[string]string `yaml:"ops"`
	}
	if err := yaml.Unmarshal(m1, &doc); err != nil {
		t.Fatal(err)
	}
	e := doc.Ops["notes.show"]
	if e["class"] != "routine" || e["surface"] != "op" || e["usage"] != c.Ops[0].Usage || e["summary"] != c.Ops[0].Summary {
		t.Errorf("entry = %v", e)
	}

	o1, err := Splice(OpenAPI, []byte(openapiText), []Connector{c})
	if err != nil {
		t.Fatal(err)
	}
	if i, j := strings.Index(string(o1), "# BEGIN"), strings.Index(string(o1), "    ParamsHealth:"); i < 0 || j < i {
		t.Errorf("a first region goes before the first Params schema:\n%s", o1)
	}
	var api struct {
		Components struct {
			Schemas map[string]map[string]any `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(o1, &api); err != nil {
		t.Fatal(err)
	}
	s := api.Components.Schemas["ParamsNotesShow"]
	if s["additionalProperties"] != false || s["type"] != "object" || len(s["required"].([]any)) != 1 || s["required"].([]any)[0] != "tag" {
		t.Errorf("schema = %v", s)
	}
	if len(api.Components.Schemas) != 3 {
		t.Errorf("the generated schema must sit beside the others: %v", api.Components.Schemas)
	}

	// Stable: splicing again changes nothing. A hand edit inside the region is undone.
	for f, tc := range map[File]struct {
		text     []byte
		from, to string
	}{
		Manual:  {m1, "summary: Show one note.", "summary: Show a lie."},
		OpenAPI: {o1, "additionalProperties: false\n    # END", "additionalProperties: true\n    # END"},
	} {
		again, err := Splice(f, tc.text, []Connector{c})
		if err != nil || string(again) != string(tc.text) {
			t.Errorf("splice of file %d is not stable: %v", f, err)
		}
		tampered := strings.Replace(string(tc.text), tc.from, tc.to, 1)
		if tampered == string(tc.text) {
			t.Fatalf("file %d: the test's edit found nothing to change", f)
		}
		fixed, err := Splice(f, []byte(tampered), []Connector{c})
		if err != nil || string(fixed) != string(tc.text) {
			t.Errorf("a hand edit inside a region must be rewritten (file %d): %v", f, err)
		}
	}
}

func TestSpliceNeverTouchesHandWrittenEntries(t *testing.T) {
	c := conn()
	m1, _ := Splice(Manual, []byte(manualText), []Connector{c})
	c2 := conn()
	c2.Ops[0].Summary = "Show a note, changed."
	m2, err := Splice(Manual, m1, []Connector{c2})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(m2), manualText) {
		t.Errorf("the hand-written part changed:\n%s", m2)
	}
	if !strings.Contains(string(m2), "Show a note, changed.") || strings.Contains(string(m2), "Show one note.") {
		t.Errorf("the region was not rewritten:\n%s", m2)
	}
}

func TestSpliceRefusesBadRegions(t *testing.T) {
	c := conn()
	m1, _ := Splice(Manual, []byte(manualText), []Connector{c})
	text := string(m1)
	for name, in := range map[string]string{
		"begin without end":   strings.Replace(text, "  # END generated: connector notes", "", 1),
		"end without begin":   strings.Replace(text, "# BEGIN generated: connector notes", "# something", 1),
		"two regions":         text + "\n  # BEGIN generated: connector notes (x)\n  # END generated: connector notes\n",
		"two end markers":     text + "  hand_written:\n    class: routine\n  # END generated: connector notes\n",
		"a removed connector": text,
	} {
		conns := []Connector{c}
		if name == "a removed connector" {
			conns = []Connector{{Name: "other", Ops: c.Ops}}
		}
		if _, err := Splice(Manual, []byte(in), conns); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := Splice(OpenAPI, []byte("components:\n  schemas:\n    Other:\n      type: object\n"), []Connector{c}); err == nil {
		t.Error("an OpenAPI file with no Params schema and no marker has no place for a first region")
	}
}

func TestSyncFileReportsAndWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manual.yaml")
	if err := os.WriteFile(path, []byte(manualText), 0o644); err != nil {
		t.Fatal(err)
	}
	c := conn()
	changed, err := SyncFile(path, Manual, []Connector{c}, false)
	if err != nil || !changed {
		t.Fatalf("check on a stale file = %v, %v", changed, err)
	}
	if b, _ := os.ReadFile(path); string(b) != manualText {
		t.Error("check mode wrote the file")
	}
	if changed, err = SyncFile(path, Manual, []Connector{c}, true); err != nil || !changed {
		t.Fatalf("write = %v, %v", changed, err)
	}
	if changed, err = SyncFile(path, Manual, []Connector{c}, false); err != nil || changed {
		t.Fatalf("check after write = %v, %v", changed, err)
	}
	bad := conn()
	bad.Ops[0].Class = "nope"
	if _, err := SyncFile(path, Manual, []Connector{bad}, true); err == nil {
		t.Error("an invalid declaration must not be written")
	}
	if err := os.WriteFile(path, []byte("ops:\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SyncFile(path, Manual, []Connector{c}, true); err == nil {
		t.Error("a CRLF file must be refused")
	}
}

// A second connector gets its own region, beside the first and never inside it.
func TestSpliceTwoConnectors(t *testing.T) {
	a := conn()
	b := conn()
	b.Name = "tasks"
	b.Ops[0].Name = "tasks.show"
	b.Ops[0].Usage = "chap tasks show <N-1> --tag <name>"
	for f, text := range map[File]string{Manual: manualText, OpenAPI: openapiText} {
		one, err := Splice(f, []byte(text), []Connector{a})
		if err != nil {
			t.Fatal(err)
		}
		two, err := Splice(f, one, []Connector{a, b})
		if err != nil {
			t.Fatal(err)
		}
		again, err := Splice(f, two, []Connector{a, b})
		if err != nil || string(again) != string(two) {
			t.Errorf("file %d: two regions are not stable: %v", f, err)
		}
		// Regions are in order and do not nest.
		ba, ea := strings.Index(string(two), "# BEGIN generated: connector notes"), strings.Index(string(two), "# END generated: connector notes")
		bb, eb := strings.Index(string(two), "# BEGIN generated: connector tasks"), strings.Index(string(two), "# END generated: connector tasks")
		if ba < 0 || ea < ba || bb < 0 || eb < bb || (bb < ea && bb > ba) || (ba < eb && ba > bb) {
			t.Errorf("file %d: the regions nest or are missing:\n%s", f, two)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(two, &doc); err != nil {
			t.Errorf("file %d: %v", f, err)
		}
	}
}
