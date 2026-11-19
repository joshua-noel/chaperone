package conformance

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// mutant is a request that breaks the declaration in one way. The adapter must
// refuse it as OP_PARAMS_INVALID, in Check and in Execute.
type mutant struct {
	name  string
	apply func(req *ops.Request)
}

// maxProbe is the longest value the suite builds. A declared maximum past it is
// not probed.
const maxProbe = 1 << 20

// mutants derives the broken requests from the declaration of the operation:
// an undeclared param, and for each declared param a missing value, a value of
// the wrong kind, and a value past each declared bound. They are applied to the
// first valid sample.
func (h *harness) mutants() []mutant {
	set := func(key string, v any) func(*ops.Request) {
		return func(r *ops.Request) {
			if r.Params == nil {
				r.Params = map[string]any{}
			}
			r.Params[key] = v
		}
	}
	var out []mutant
	add := func(name string, f func(*ops.Request)) { out = append(out, mutant{name: name, apply: f}) }

	add("undeclared param", set("zz_undeclared_param", true))
	for _, p := range h.decl.Params {
		who := func(what string) string { return fmt.Sprintf("param %s: %s", p.Name, what) }
		if p.Required && !p.FromRef {
			add(who("required value left out"), func(r *ops.Request) { delete(r.Params, p.Name) })
		}
		switch p.Kind {
		case kit.Bool:
			add(who("text where a bool belongs"), set(p.Name, "yes"))
		case kit.String, kit.Text:
			add(who("number where text belongs"), set(p.Name, 12345.0))
			if p.Const != "" {
				add(who("not the one allowed value"), set(p.Name, "not-"+p.Const))
				continue
			}
			if p.MinLength >= 1 {
				add(who("empty"), set(p.Name, ""))
			}
			if p.MaxLength > 0 && p.MaxLength < maxProbe && !p.Unbounded {
				add(who(fmt.Sprintf("one byte over the maximum of %d", p.MaxLength)), set(p.Name, strings.Repeat("a", p.MaxLength+1)))
			}
			if p.Pattern != "" {
				if re, err := regexp.Compile(p.Pattern); err == nil && !re.MatchString("!") {
					add(who("does not match the pattern"), set(p.Name, "!"))
				}
			}
		case kit.Int:
			add(who("text where a number belongs"), set(p.Name, "seven"))
			add(who("zero"), set(p.Name, 0.0))
			add(who("negative"), set(p.Name, -1.0))
			if p.Max > 0 {
				add(who(fmt.Sprintf("over the maximum of %d", p.Max)), set(p.Name, float64(p.Max+1)))
			}
		case kit.List:
			add(who("text where a list belongs"), set(p.Name, "a-string"))
			if p.MinItems >= 1 {
				add(who("empty list"), set(p.Name, []any{}))
			}
			if p.MaxItems > 0 && p.MaxItems < 4096 {
				items := make([]any, p.MaxItems+1)
				for i := range items {
					items[i] = "a"
				}
				add(who(fmt.Sprintf("over the maximum of %d items", p.MaxItems)), set(p.Name, items))
			}
			if p.MaxLength > 0 && p.MaxLength < maxProbe {
				add(who(fmt.Sprintf("an item over the maximum of %d bytes", p.MaxLength)), set(p.Name, []any{strings.Repeat("a", p.MaxLength+1)}))
			}
		}
	}
	return out
}
