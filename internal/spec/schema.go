package spec

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

//go:embed specdata/schemas/*.schema.json specdata/VERSION
var embedded embed.FS

// Schema names: the document types Chaperone validates.
const (
	SchemaRequest   = "operation-request"
	SchemaApproval  = "operation-approval"
	SchemaRunToken  = "run-token"
	SchemaEvent     = "ledger-event"
	SchemaDenial    = "denial"
	SchemaProfile   = "profile"
	SchemaStopTable = "stop-table"
)

// Version returns the version of the contract in specdata (specdata/VERSION).
func Version() string {
	b, _ := embedded.ReadFile("specdata/VERSION")
	return strings.TrimSpace(string(b))
}

const idPrefix = "https://factory-spec.invalid/v0/"

// Issue is one leaf failure of a schema validation.
type Issue struct {
	Path    string // JSON Pointer into the document; "" is the root
	Keyword string // the failed keyword: required, additionalProperties, pattern, enum ...
	Message string
}

// ValidationError lists why a document does not match its schema.
type ValidationError struct {
	Schema string
	Issues []Issue
}

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		parts[i] = fmt.Sprintf("%s: %s [%s]", is.Path, is.Message, is.Keyword)
	}
	return fmt.Sprintf("%s: %s", e.Schema, strings.Join(parts, "; "))
}

// Validator holds every embedded schema, compiled. It is safe for concurrent use.
type Validator struct {
	compiler *jsonschema.Compiler
	mu       sync.Mutex
	compiled map[string]*jsonschema.Schema
}

var (
	defaultOnce sync.Once
	defaultV    *Validator
	defaultErr  error
)

// Default returns the shared Validator, built on first use.
func Default() (*Validator, error) {
	defaultOnce.Do(func() { defaultV, defaultErr = NewValidator() })
	return defaultV, defaultErr
}

// NewValidator compiles the embedded schemas as JSON Schema 2020-12. Patterns
// run on an ECMAScript-style engine (the schemas use lookahead, which Go's
// regexp lacks), and formats are annotations only, as the spec requires.
func NewValidator() (*Validator, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseRegexpEngine(compilePattern)
	entries, err := embedded.ReadDir("specdata/schemas")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		b, err := embedded.ReadFile("specdata/schemas/" + e.Name())
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err := c.AddResource(idPrefix+e.Name(), doc); err != nil {
			return nil, err
		}
	}
	return &Validator{compiler: c, compiled: map[string]*jsonschema.Schema{}}, nil
}

// schema compiles (once) the named document schema, or its #/$defs/<via> part.
func (v *Validator) schema(name, via string) (*jsonschema.Schema, error) {
	loc := idPrefix + name + ".schema.json"
	if via != "" {
		loc += "#/$defs/" + via
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if s, ok := v.compiled[loc]; ok {
		return s, nil
	}
	s, err := v.compiler.Compile(loc)
	if err != nil {
		return nil, fmt.Errorf("schema %s: %w", name, err)
	}
	v.compiled[loc] = s
	return s, nil
}

// Validate checks a document tree (ParseStrict output) against the named
// schema. A failure is a *ValidationError; unknown members are errors, and
// ledger event attributes are closed per event_name.
func (v *Validator) Validate(name string, tree any) error {
	return v.validate(name, "", tree)
}

func (v *Validator) validate(name, via string, tree any) error {
	s, err := v.schema(name, via)
	if err != nil {
		return err
	}
	err = s.Validate(tree)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return err
	}
	out := &ValidationError{Schema: name}
	collect(ve, message.NewPrinter(language.English), &out.Issues)
	sort.SliceStable(out.Issues, func(i, j int) bool { return out.Issues[i].Path < out.Issues[j].Path })
	return out
}

// keywordOf names the keyword an error kind reports, using the spelling of the
// reference validator (Ajv) where the Go library has no keyword path.
func keywordOf(k jsonschema.ErrorKind) string {
	switch k.(type) {
	case *kind.FalseSchema:
		return "false schema"
	case *kind.Not:
		return "not"
	}
	if path := k.KeywordPath(); len(path) > 0 {
		return path[len(path)-1]
	}
	return ""
}

// collect flattens an error tree into leaf issues. A oneOf, anyOf or allOf node
// that has causes is kept too, so callers can tell which combinator failed.
func collect(e *jsonschema.ValidationError, p *message.Printer, out *[]Issue) {
	kw := keywordOf(e.ErrorKind)
	if len(e.Causes) == 0 || kw != "" {
		ptr := ""
		for _, seg := range e.InstanceLocation {
			ptr += "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(seg)
		}
		*out = append(*out, Issue{Path: ptr, Keyword: kw, Message: e.ErrorKind.LocalizedString(p)})
	}
	for _, c := range e.Causes {
		collect(c, p, out)
	}
}

// Validate checks tree against the named schema with the shared Validator.
func Validate(name string, tree any) error {
	v, err := Default()
	if err != nil {
		return err
	}
	return v.Validate(name, tree)
}

// LoadTree is the one way to accept a document: strict I-JSON parse, then
// schema validation. The tree is what OpHash, EventHash and the others hash.
func LoadTree(name string, data []byte) (any, error) {
	tree, err := ParseStrict(data)
	if err != nil {
		return nil, err
	}
	if err := Validate(name, tree); err != nil {
		return nil, err
	}
	return tree, nil
}

// Load accepts a document as LoadTree does and decodes it into T (Request,
// Approval, RunTokenClaims, Event, Denial ...). Members T does not declare are
// an error, never ignored.
func Load[T any](name string, data []byte) (T, error) {
	var out T
	if _, err := LoadTree(name, data); err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// pattern compiles a schema "pattern" with ECMAScript search semantics.
type pattern struct{ re *regexp2.Regexp }

func (p pattern) MatchString(s string) bool {
	ok, err := p.re.MatchString(s)
	return err == nil && ok
}

func (p pattern) String() string { return p.re.String() }

func compilePattern(src string) (jsonschema.Regexp, error) {
	re, err := regexp2.Compile(endAnchors(src), regexp2.None)
	if err != nil {
		return nil, err
	}
	return pattern{re}, nil
}

// endAnchors rewrites every "$" outside a character class to \z. In ECMAScript
// "$" matches only at the end of the input, but .NET-style engines also let it
// match before a final newline, which would accept "r-abcd\n" as a run id.
func endAnchors(src string) string {
	var b strings.Builder
	inClass := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\\' && i+1 < len(src):
			b.WriteByte(c)
			i++
			b.WriteByte(src[i])
			continue
		case inClass && c == ']':
			inClass = false
		case !inClass && c == '[':
			inClass = true
		case !inClass && c == '$':
			b.WriteString(`\z`)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
