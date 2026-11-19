package kit

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// repoOp is a valid operation on a repository with a number, the shape of the
// GitHub reads.
func repoOp() Op {
	o := good()
	o.Name = "pulls.show"
	o.Usage = "chap pulls show <n> [--repo owner/name]"
	o.Target = Target{Adapter: "notes", Repo: true, Positional: "n", Why: "the number must be a positive integer"}
	return o
}

func TestRepoTargetAndNewKindsValidate(t *testing.T) {
	ok := repoOp()
	ok.CLI.DryRun = "check only"
	ok.Params = []Param{
		{Name: "number", Kind: Int, Required: true, Min: 1, FromRef: true},
		{Name: "page", Kind: Int, Min: 1, Max: 100, Default: 30, Placeholder: "p", Help: "h"},
		{Name: "sha", Kind: String, Pattern: `^[0-9a-f]{40}$`, Why: "w", Placeholder: "sha", Help: "h"},
		{Name: "labels", Kind: List, MinItems: 1, MaxItems: 5, MinLength: 1, MaxLength: 20, Placeholder: "l", Help: "h"},
		{Name: "method", Kind: String, Required: true, Const: "squash"},
		{Name: "base", Kind: String, Unbounded: true, Placeholder: "b", Help: "h"},
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(o *Op){
		"repo target with a pattern":    func(o *Op) { o.Target.Pattern = `^x$` },
		"repo target with a flag":       func(o *Op) { o.Target.Flag = "r" },
		"repo number without Why":       func(o *Op) { o.Target.Why = "" },
		"repo with no number and a Why": func(o *Op) { o.Target.Positional = ""; o.Usage = "chap pulls show" },
		"repo flag used twice":          func(o *Op) { o.Params = []Param{{Name: "repo", Kind: Bool, Help: "h"}} },
		"dry-run flag used twice": func(o *Op) {
			o.CLI.DryRun = "h"
			o.Params = []Param{{Name: "dry_run", Flag: "dry-run", Kind: Bool, Help: "h"}}
		},
		"int below one":     func(o *Op) { o.Params = []Param{{Name: "n", Kind: Int, Min: 0, Placeholder: "n", Help: "h"}} },
		"int max below min": func(o *Op) { o.Params = []Param{{Name: "n", Kind: Int, Min: 5, Max: 2, Placeholder: "n", Help: "h"}} },
		"int default above max": func(o *Op) {
			o.Params = []Param{{Name: "n", Kind: Int, Min: 1, Max: 5, Default: 9, Placeholder: "n", Help: "h"}}
		},
		"int with a length": func(o *Op) {
			o.Params = []Param{{Name: "n", Kind: Int, Min: 1, MaxLength: 3, Placeholder: "n", Help: "h"}}
		},
		"int without help":         func(o *Op) { o.Params = []Param{{Name: "n", Kind: Int, Min: 1, Placeholder: "n"}} },
		"list without items bound": func(o *Op) { o.Params = []Param{{Name: "l", Kind: List, MaxItems: 3, Placeholder: "l", Help: "h"}} },
		"list without a maximum":   func(o *Op) { o.Params = []Param{{Name: "l", Kind: List, MaxLength: 3, Placeholder: "l", Help: "h"}} },
		"list with a pattern": func(o *Op) {
			o.Params = []Param{{Name: "l", Kind: List, MaxItems: 3, MaxLength: 3, Pattern: `^a$`, Placeholder: "l", Help: "h"}}
		},
		"pattern without Why": func(o *Op) {
			o.Params = []Param{{Name: "s", Kind: String, Pattern: `^a$`, Placeholder: "s", Help: "h"}}
		},
		"Why without a pattern": func(o *Op) {
			o.Params = []Param{{Name: "s", Kind: String, MaxLength: 3, Why: "w", Placeholder: "s", Help: "h"}}
		},
		"unanchored param pattern": func(o *Op) {
			o.Params = []Param{{Name: "s", Kind: String, Pattern: `a+`, Why: "w", Placeholder: "s", Help: "h"}}
		},
		"CLIPattern without a pattern": func(o *Op) {
			o.Params = []Param{{Name: "s", Kind: String, MaxLength: 3, CLIPattern: `^a$`, Placeholder: "s", Help: "h"}}
		},
		"unbounded with a length": func(o *Op) {
			o.Params = []Param{{Name: "s", Kind: String, Unbounded: true, MaxLength: 3, Placeholder: "s", Help: "h"}}
		},
		"unbounded with a pattern": func(o *Op) {
			o.Params = []Param{{Name: "s", Kind: String, Unbounded: true, Pattern: `^a$`, Why: "w", Placeholder: "s", Help: "h"}}
		},
		"string with nothing to bound it": func(o *Op) { o.Params = []Param{{Name: "s", Kind: String, Placeholder: "s", Help: "h"}} },
		"const that is not required":      func(o *Op) { o.Params = []Param{{Name: "m", Kind: String, Const: "squash"}} },
		"const with a length": func(o *Op) {
			o.Params = []Param{{Name: "m", Kind: String, Const: "squash", Required: true, MaxLength: 9}}
		},
		"const that is not a plain word": func(o *Op) { o.Params = []Param{{Name: "m", Kind: String, Const: "a b: c", Required: true}} },
		"const with a flag":              func(o *Op) { o.Params = []Param{{Name: "m", Kind: String, Const: "squash", Required: true, Flag: "m"}} },
		"from ref that is not required":  func(o *Op) { o.Params = []Param{{Name: "n", Kind: Int, Min: 1, FromRef: true}} },
		"from ref with a flag": func(o *Op) {
			o.Params = []Param{{Name: "n", Kind: Int, Min: 1, Required: true, FromRef: true, Flag: "n"}}
		},
		"int from ref but no number in the ref": func(o *Op) {
			o.Target.Positional = ""
			o.Target.Why = ""
			o.Usage = "chap pulls show"
			o.Params = []Param{{Name: "n", Kind: Int, Min: 1, Required: true, FromRef: true}}
		},
		"string from ref on a repository": func(o *Op) {
			o.Params = []Param{{Name: "r", Kind: String, Pattern: `^a$`, Required: true, FromRef: true}}
		},
		"text with a pattern":                       func(o *Op) { o.Params = []Param{{Name: "body", Kind: Text, MaxLength: 3, Pattern: `^a$`}} },
		"bool with a bound":                         func(o *Op) { o.Params = []Param{{Name: "b", Kind: Bool, Help: "h", Min: 1}} },
		"Why with a stray percent":                  func(o *Op) { o.Target = good().Target; o.Target.Why = "100% %q" },
		"Why with two %q":                           func(o *Op) { o.Target = good().Target; o.Target.Why = "%q and %q" },
		"dry-run help with a control character":     func(o *Op) { o.CLI.DryRun = "a\nb" },
		"usage names a flag the command lacks":      func(o *Op) { o.Usage = "chap pulls show <n> [--dry-run]" },
		"usage names a flag the repo command lacks": func(o *Op) { o.Usage = "chap pulls show <n> [--branch <b>]" },
	} {
		o := repoOp()
		mutate(&o)
		if err := o.Validate(); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// A Why with one %q is fine for a ref given as a plain positional.
	g := good()
	g.Target.Why = "%q is not a note"
	if err := g.Validate(); err != nil {
		t.Errorf("Why with one %%q: %v", err)
	}
	// A custom command may name any flag, and a computed ref.
	c := repoOp()
	c.CLI.Custom = true
	c.Usage = "chap pulls show <n> --anything"
	c.Target = Target{Adapter: "notes", Repo: true}
	if err := c.Validate(); err != nil {
		t.Errorf("custom: %v", err)
	}
	// What the params schema is written from is still checked.
	c.Params = []Param{{Name: "n", Kind: Int}}
	if err := c.Validate(); err == nil {
		t.Error("custom int with no Min: want an error")
	}
}

func TestSchemaOfNewKinds(t *testing.T) {
	cases := []struct {
		p    Param
		want string
	}{
		{Param{Kind: Bool}, "{ type: boolean }"},
		{Param{Kind: Int, Min: 1}, "{ type: integer, minimum: 1 }"},
		{Param{Kind: Int, Min: 1, Default: 1}, "{ type: integer, minimum: 1, default: 1 }"},
		{Param{Kind: Int, Min: 1, Max: 100, Default: 30}, "{ type: integer, minimum: 1, maximum: 100, default: 30 }"},
		{Param{Kind: String, Unbounded: true}, "{ type: string }"},
		{Param{Kind: String, MaxLength: 8}, "{ type: string, maxLength: 8 }"},
		{Param{Kind: String, MinLength: 1, MaxLength: 8}, "{ type: string, minLength: 1, maxLength: 8 }"},
		{Param{Kind: String, Pattern: `^[0-9a-f]{40}$`}, `{ type: string, pattern: "^[0-9a-f]{40}$" }`},
		{Param{Kind: String, Const: "squash"}, "{ const: squash }"},
		{Param{Kind: Text, MaxLength: 20000}, "{ type: string, maxLength: 20000 }"},
		{Param{Kind: List, MinItems: 1, MaxItems: 10, MinLength: 1, MaxLength: 50}, "{ type: array, minItems: 1, maxItems: 10, items: { type: string, minLength: 1, maxLength: 50 } }"},
		{Param{Kind: List, MaxItems: 3, MaxLength: 5}, "{ type: array, maxItems: 3, items: { type: string, maxLength: 5 } }"},
	}
	for _, c := range cases {
		if got := c.p.schema(); got != c.want {
			t.Errorf("schema = %s, want %s", got, c.want)
		}
		// The text is flow-style YAML that reads back.
		var out map[string]any
		if err := yaml.Unmarshal([]byte("k: "+c.p.schema()+"\n"), &out); err != nil {
			t.Errorf("%s does not read back: %v", c.want, err)
		}
	}
	// The whole params block reads back, with the pattern's backslashes intact.
	o := repoOp()
	o.Params = []Param{
		{Name: "number", Kind: Int, Required: true, Min: 1, FromRef: true},
		{Name: "sha", Kind: String, Pattern: `^\d{3}$`},
	}
	var b strings.Builder
	o.writeParams(&b)
	var doc map[string]map[string]any
	if err := yaml.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatalf("%v\n%s", err, b.String())
	}
	props := doc["ParamsPullsShow"]["properties"].(map[string]any)
	if props["sha"].(map[string]any)["pattern"] != `^\d{3}$` {
		t.Errorf("pattern reads back as %v", props["sha"])
	}
	if req := doc["ParamsPullsShow"]["required"].([]any); len(req) != 1 || req[0] != "number" {
		t.Errorf("required = %v", req)
	}
}

func TestDerivedCommandLineOfNewKinds(t *testing.T) {
	o := repoOp()
	o.CLI.DryRun = "check only"
	o.Params = []Param{
		{Name: "number", Kind: Int, Required: true, Min: 1, FromRef: true},
		{Name: "method", Kind: String, Required: true, Const: "squash"},
		{Name: "per_page", Kind: Int, Min: 1, Flag: "per-page", Placeholder: "n", Help: "h"},
		{Name: "labels", Kind: List, MaxItems: 3, MaxLength: 5, Placeholder: "l", Help: "h"},
		{Name: "must", Kind: List, Required: true, MaxItems: 3, MaxLength: 5, Placeholder: "m", Help: "h"},
		{Name: "sha", Kind: String, Required: true, Pattern: `^a$`, Why: "w", Placeholder: "sha", Help: "h"},
	}
	want := "chap pulls show <n> [--per-page <n>] [--labels <l>] --must <m> [--must <m>] --sha <sha> [--repo owner/name] [--dry-run]"
	if got := o.CLIUsage(); got != want {
		t.Errorf("usage = %q, want %q", got, want)
	}
	// A repository with no number has no positional argument.
	r := good()
	r.Target = Target{Adapter: "notes", Repo: true}
	if got := r.CLIUsage(); got != "chap notes show [--repo owner/name]" {
		t.Errorf("usage = %q", got)
	}
}

// A colon is plain inside a word and quoted before a space; a long description
// is quoted; both read back as written.
func TestPlainColonAndLongDocs(t *testing.T) {
	for s, want := range map[string]string{
		"Open an issue labelled source:error-watcher.": "Open an issue labelled source:error-watcher.",
		"a: b":                          `"a: b"`,
		"ends with a colon:":            `"ends with a colon:"`,
		"Target is `{adapter: github}`": `"Target is ` + "`{adapter: github}`" + `"`,
	} {
		if got := yamlScalar(s); got != want {
			t.Errorf("yamlScalar(%q) = %s, want %s", s, got, want)
		}
		var out map[string]any
		if err := yaml.Unmarshal([]byte("k: "+yamlScalar(s)+"\n"), &out); err != nil || out["k"] != s {
			t.Errorf("%q does not read back: %#v %v", s, out["k"], err)
		}
	}
	short := "Phase 1 shape for `x` (owned by here). `a` is required."
	if got := docScalar(short); got != short {
		t.Errorf("a short plain description is plain: %s", got)
	}
	long := short + strings.Repeat(" more words", 20)
	if got := docScalar(long); !strings.HasPrefix(got, `"`) {
		t.Errorf("a long description is quoted: %s", got)
	}
}
