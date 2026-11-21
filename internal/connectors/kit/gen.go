package kit

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// File is a hand-maintained file that holds generated regions.
type File int

const (
	// Manual is api/manual.yaml: one catalog entry per op, under `ops:`.
	Manual File = iota + 1
	// OpenAPI is api/openapi.yaml: one Params<Op> schema per op, under
	// `components.schemas`.
	OpenAPI
)

// A region is a run of lines between two comment lines:
//
//	# BEGIN generated: connector linear (...)
//	...
//	# END generated: connector linear
//
// The generator rewrites what is between the markers and nothing else, so a
// hand-written entry next to a region is never touched, and an entry cannot be
// both. The markers sit at the indent of the entries.
const (
	beginPrefix = "# BEGIN generated: connector "
	endPrefix   = "# END generated: connector "
)

// Regenerate is the command that rewrites the regions.
const Regenerate = "go generate ./internal/connectors/..."

func beginLine(indent, conn string) string {
	return indent + beginPrefix + conn + " (do not edit by hand; run `" + Regenerate + "`)"
}

func endLine(indent, conn string) string { return indent + endPrefix + conn }

func (f File) indent() string {
	if f == Manual {
		return "  "
	}
	return "    "
}

func (f File) name() string {
	if f == Manual {
		return "api/manual.yaml"
	}
	return "api/openapi.yaml"
}

// Body returns the text of the connector's region in file f, without the
// markers.
func (c Connector) Body(f File) string {
	var b strings.Builder
	for _, o := range c.Ops {
		if f == Manual {
			o.writeManual(&b)
		} else {
			o.writeParams(&b)
		}
	}
	return b.String()
}

// writeManual writes the op's entry of api/manual.yaml. Every op a connector
// declares is reached through POST /v0/ops, so its surface is always `op`.
func (o Op) writeManual(b *strings.Builder) {
	fmt.Fprintf(b, "  %s:\n", o.Name)
	fmt.Fprintf(b, "    class: %s\n", o.Class)
	fmt.Fprintf(b, "    reversibility: %s\n", o.Reversibility)
	b.WriteString("    surface: op\n")
	fmt.Fprintf(b, "    summary: %s\n", yamlScalar(o.Summary))
	fmt.Fprintf(b, "    usage: %s\n", yamlScalar(o.Usage))
}

// writeParams writes the op's Params<Op> schema of api/openapi.yaml. The
// schema refuses unknown properties: that is the contract, and it is what the
// MCP tool schema is built from.
func (o Op) writeParams(b *strings.Builder) {
	fmt.Fprintf(b, "    %s:\n", o.ParamsSchemaName())
	fmt.Fprintf(b, "      description: %s\n", docScalar(o.Doc))
	b.WriteString("      type: object\n")
	if len(o.Params) > 0 {
		b.WriteString("      properties:\n")
		for _, p := range o.Params {
			fmt.Fprintf(b, "        %s: %s\n", p.Name, p.schema())
		}
	}
	var req []string
	for _, p := range o.Params {
		if p.Required {
			req = append(req, p.Name)
		}
	}
	if len(req) > 0 {
		fmt.Fprintf(b, "      required: [%s]\n", strings.Join(req, ", "))
	}
	b.WriteString("      additionalProperties: false\n")
}

// schema is the flow-style schema of one param: `{ type: string, maxLength: 80 }`.
func (p Param) schema() string {
	var f []string
	add := func(format string, a ...any) { f = append(f, fmt.Sprintf(format, a...)) }
	length := func() {
		if p.MinLength > 0 {
			add("minLength: %d", p.MinLength)
		}
		if p.MaxLength > 0 {
			add("maxLength: %d", p.MaxLength)
		}
	}
	switch p.Kind {
	case Bool:
		add("type: boolean")
	case Int:
		add("type: integer")
		add("minimum: %d", p.Min)
		if p.Max > 0 {
			add("maximum: %d", p.Max)
		}
		if p.Default > 0 {
			add("default: %d", p.Default)
		}
	case List:
		add("type: array")
		if p.MinItems > 0 {
			add("minItems: %d", p.MinItems)
		}
		add("maxItems: %d", p.MaxItems)
		item := Param{Kind: String, MinLength: p.MinLength, MaxLength: p.MaxLength}
		add("items: %s", item.schema())
	default:
		if p.Const != "" {
			add("const: %s", yamlScalar(p.Const))
			break
		}
		add("type: string")
		if p.Pattern != "" {
			add("pattern: %s", yamlQuoted(p.Pattern))
		}
		length()
	}
	return "{ " + strings.Join(f, ", ") + " }"
}

// A colon is allowed inside a plain scalar when no space follows it (`source:error-watcher`).
var plainRE = regexp.MustCompile("^[A-Za-z][A-Za-z0-9 .,;:()\\[\\]<>/'|=+*@~$%^&!?_`-]*$")

// yamlScalar writes s as a plain scalar when that reads back as the same
// string, and as a double-quoted one when it does not.
func yamlScalar(s string) string {
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off", "null", "y", "n":
		return yamlQuoted(s)
	}
	if !plainRE.MatchString(s) || strings.HasSuffix(s, " ") || strings.Contains(s, " #") || strings.Contains(s, ": ") || strings.HasSuffix(s, ":") {
		return yamlQuoted(s)
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return yamlQuoted(s)
	}
	return s
}

// yamlQuoted writes s as a YAML double-quoted scalar. Control characters are
// refused by Validate, so only the backslash and the quote need escaping.
func yamlQuoted(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// Splice puts the connectors' regions into the file's text and returns the new
// text. A region that exists is rewritten in place. A connector with no region
// yet gets one: at the end of api/manual.yaml, and in api/openapi.yaml just
// before the first Params schema. A region of a connector that is not in conns
// is an error (a connector was removed and its region left behind).
func Splice(f File, text []byte, conns []Connector) ([]byte, error) {
	lines := strings.Split(string(text), "\n")
	known := map[string]bool{}
	for _, c := range conns {
		known[c.Name] = true
	}
	for _, l := range lines {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, beginPrefix) {
			name, _, _ := strings.Cut(strings.TrimPrefix(t, beginPrefix), " ")
			if !known[name] {
				return nil, fmt.Errorf("%s has a generated region for connector %q, which is not declared; delete the region or declare the connector", f.name(), name)
			}
		}
	}
	for _, c := range conns {
		var err error
		if lines, err = f.spliceOne(lines, c); err != nil {
			return nil, err
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}

func (f File) spliceOne(lines []string, c Connector) ([]string, error) {
	indent := f.indent()
	region := []string{beginLine(indent, c.Name)}
	region = append(region, strings.Split(strings.TrimSuffix(c.Body(f), "\n"), "\n")...)
	region = append(region, endLine(indent, c.Name))

	begin, end := -1, -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, beginPrefix+c.Name+" "):
			if begin >= 0 {
				return nil, fmt.Errorf("%s has two generated regions for connector %s", f.name(), c.Name)
			}
			begin = i
		case t == strings.TrimSpace(endLine(indent, c.Name)):
			if end >= 0 {
				return nil, fmt.Errorf("%s has two end markers for connector %s; entries between them would be deleted by a regeneration", f.name(), c.Name)
			}
			end = i
		}
	}
	switch {
	case begin >= 0 && end > begin:
		out := append([]string(nil), lines[:begin]...)
		out = append(out, region...)
		return append(out, lines[end+1:]...), nil
	case begin >= 0 || end >= 0:
		return nil, fmt.Errorf("%s: the generated region of connector %s has a begin or an end marker but not both, in order", f.name(), c.Name)
	}
	at := len(lines)
	if f == Manual {
		for at > 0 && lines[at-1] == "" {
			at--
		}
	} else {
		// Before the first Params schema, or before the first generated
		// region if that comes first: never inside a region.
		at = -1
		for i, l := range lines {
			if paramsKeyRE.MatchString(l) || strings.HasPrefix(strings.TrimSpace(l), beginPrefix) {
				at = i
				break
			}
		}
		if at < 0 {
			return nil, fmt.Errorf("%s has no Params schema to put the region of connector %s before; add the two marker lines inside components.schemas", f.name(), c.Name)
		}
	}
	out := append([]string(nil), lines[:at]...)
	out = append(out, region...)
	return append(out, lines[at:]...), nil
}

var paramsKeyRE = regexp.MustCompile(`^    Params[A-Za-z0-9]+:\s*$`)

// SyncFile makes the regions of the file at path agree with the declarations.
// With write false it only reports: changed is true when the file is out of
// date. With write true it rewrites the file.
func SyncFile(path string, f File, conns []Connector, write bool) (changed bool, err error) {
	for _, c := range conns {
		if err := c.Validate(); err != nil {
			return false, err
		}
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if bytes.Contains(old, []byte("\r\n")) {
		return false, fmt.Errorf("%s has CRLF line endings; the repository stores LF", path)
	}
	got, err := Splice(f, old, conns)
	if err != nil {
		return false, err
	}
	if bytes.Equal(old, got) {
		return false, nil
	}
	if write {
		return true, os.WriteFile(path, got, 0o644)
	}
	return true, nil
}

// SyncAll runs [SyncFile] for api/manual.yaml and api/openapi.yaml under root,
// the repository root.
func SyncAll(root string, conns []Connector, write bool) (changed []string, err error) {
	for _, f := range []File{Manual, OpenAPI} {
		path := root + "/" + f.name()
		c, err := SyncFile(path, f, conns, write)
		if err != nil {
			return changed, fmt.Errorf("%s: %w", f.name(), err)
		}
		if c {
			changed = append(changed, f.name())
		}
	}
	return changed, nil
}

// longDoc is the length from which a description is always quoted: a long
// prose line is easier to read, and to diff, in one quoted string.
const longDoc = 160

// docScalar writes the prose of a params schema: short and plain it stays
// plain, anything else is quoted.
func docScalar(s string) string {
	if len(s) > longDoc {
		return yamlQuoted(s)
	}
	return yamlScalar(s)
}
