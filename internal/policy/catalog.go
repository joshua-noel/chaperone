// Package policy is Chaperone's op catalog and policy engine (ticket L1-07).
//
// Two data sets drive it:
//
//   - the catalog (api/manual.yaml): which op kinds exist, their class and
//     reversibility and the `chap manual` text. It never enables anything;
//   - the baseline pack (data/baseline.yaml): which ops are enabled, rates,
//     caps and profile ceilings. Every op is disabled there until a policy PR
//     flips it.
//
// A project file (policy/<project>.yaml) may only narrow the baseline. The
// version string of the pack in force (policy_version) changes whenever
// either file's bytes change.
package policy

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Class is the spec's operation class (v0.1.1 section 5; decisions #15, #21).
type Class string

const (
	// ClassRoutine is allowed inside the token's scope and policy, no human step.
	ClassRoutine Class = "routine"
	// ClassGated is allowed only when its preconditions hold.
	ClassGated Class = "gated"
	// ClassHigh is never auto-allowed: one approval bound to the op_hash.
	ClassHigh Class = "high"
	// ClassCritical is high, plus the CRITICAL label and alerts.
	ClassCritical Class = "critical"
)

// NeedsApproval reports whether the class always requires an approval.
func (c Class) NeedsApproval() bool { return c == ClassHigh || c == ClassCritical }

// Valid reports whether c is one of the four classes.
func (c Class) Valid() bool {
	switch c {
	case ClassRoutine, ClassGated, ClassHigh, ClassCritical:
		return true
	}
	return false
}

// Surfaces an op may be asked for through.
const (
	SurfaceOp  = "op"
	SurfaceGit = "git"
)

// Entry is one op kind of the catalog.
type Entry struct {
	Op            string `yaml:"-"`
	Class         Class  `yaml:"class"`
	Reversibility string `yaml:"reversibility"`
	Surface       string `yaml:"surface"`
	Summary       string `yaml:"summary"`
	Usage         string `yaml:"usage"`
}

// Catalog is the set of op kinds Chaperone knows. It is immutable after load.
type Catalog struct {
	entries map[string]Entry
	order   []string
}

type catalogFile struct {
	Version int              `yaml:"version"`
	Ops     map[string]Entry `yaml:"ops"`
}

// criticalPrefixes are op families that are critical whatever the file says
// (decision #21: secrets.*). A catalog that lists one of them in a lower class
// is refused at load, so a typo cannot demote it.
var criticalOps = map[string]bool{
	"repo.settings":        true,
	"host.scripts.refresh": true,
	"approvers.enroll":     true,
	"policy.activate":      true,
}

const criticalPrefix = "secrets."

func mustBeCritical(op string) bool {
	return criticalOps[op] || strings.HasPrefix(op, criticalPrefix)
}

// LoadCatalog parses api/manual.yaml. Unknown keys, a bad class, reversibility
// or surface, an over-long summary or usage, or a critical op (decision #21)
// in a lower class are errors.
func LoadCatalog(data []byte) (*Catalog, error) {
	var f catalogFile
	if err := strictYAML(data, &f); err != nil {
		return nil, fmt.Errorf("policy: catalog: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("policy: catalog: version %d, want 1", f.Version)
	}
	if len(f.Ops) == 0 {
		return nil, fmt.Errorf("policy: catalog: no ops")
	}
	c := &Catalog{entries: make(map[string]Entry, len(f.Ops))}
	for name, e := range f.Ops {
		e.Op = name
		switch {
		case !e.Class.Valid():
			return nil, fmt.Errorf("policy: catalog: %s: bad class %q", name, e.Class)
		case e.Reversibility != "reversible" && e.Reversibility != "compensable" && e.Reversibility != "irreversible":
			return nil, fmt.Errorf("policy: catalog: %s: bad reversibility %q", name, e.Reversibility)
		case e.Surface != SurfaceOp && e.Surface != SurfaceGit:
			return nil, fmt.Errorf("policy: catalog: %s: bad surface %q", name, e.Surface)
		case e.Summary == "" || len(e.Summary) > 60:
			return nil, fmt.Errorf("policy: catalog: %s: summary must be 1-60 characters", name)
		case e.Usage == "" || len(e.Usage) > 100:
			return nil, fmt.Errorf("policy: catalog: %s: usage must be 1-100 characters", name)
		case mustBeCritical(name) && e.Class != ClassCritical:
			return nil, fmt.Errorf("policy: catalog: %s must be class critical (decision #21)", name)
		}
		c.entries[name] = e
		c.order = append(c.order, name)
	}
	sort.Strings(c.order)
	return c, nil
}

// Lookup returns the entry for op.
func (c *Catalog) Lookup(op string) (Entry, bool) {
	e, ok := c.entries[op]
	return e, ok
}

// Ops lists every op kind, sorted.
func (c *Catalog) Ops() []string { return append([]string(nil), c.order...) }

// strictYAML decodes one YAML document and refuses unknown fields, a second
// document and duplicate keys (yaml.v3 refuses those for mappings).
func strictYAML(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("more than one YAML document")
	}
	return nil
}
