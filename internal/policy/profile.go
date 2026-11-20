package policy

import (
	"errors"
	"fmt"
	"regexp"
)

// ConnectorProfile is one `connectors/<id>.yaml` file: the built ops of one
// connector with the facts a review needs and api/manual.yaml cannot hold (the
// unit, the conditions, the name the connector standard gives the capability).
// The standard is a design document outside this repository; a profile records
// only what is built. It is data for review and for the drift test
// (TestC19ProfilesTieToTheCatalogTheBaselineAndTheUsage); chapd does not read it at run time, and it enables
// nothing.
type ConnectorProfile struct {
	ProfileVersion int    `yaml:"profile_version"`
	Connector      string `yaml:"connector"`
	Standard       string `yaml:"standard"`
	Ops            []ProfileOp
	// StandardNotBuilt lists names the standard has for this connector that
	// Chaperone has not built.
	StandardNotBuilt []string `yaml:"standard_not_built"`
}

// ProfileOp is one op of a [ConnectorProfile].
type ProfileOp struct {
	Name string
	// StandardName is the standard's name for this capability when the built
	// (frozen) name differs: a mapping, never a second op.
	StandardName string `yaml:"standard_name"`
	// Extension marks a built op the standard does not have.
	Extension      bool
	Class          Class
	Reversibility  string
	Surface        string
	Unit           string
	EnabledDefault bool `yaml:"enabled_default"`
	// Chap is the `chap` command path ("issue get"); empty for an op without its
	// own subcommand.
	Chap string
	// OrchestratorOnly marks an op no key or run may hold: no run profile lists it.
	OrchestratorOnly bool `yaml:"orchestrator_only"`
	// NeedsPolicyBlock names a project policy block without which the op's
	// adapter refuses every request ("linear.issues").
	NeedsPolicyBlock string `yaml:"needs_policy_block"`
	Conditions       []string
}

var (
	profileConnectorRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}$`)
	profileOpNameRE    = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)
	profileCondRE      = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// ValidOpName reports whether name matches the op-name pattern of the
// contract (api/openapi.yaml, OpSubmit): lower-case dotted segments of letters
// and digits, at most 64 characters.
func ValidOpName(name string) bool { return len(name) <= 64 && profileOpNameRE.MatchString(name) }

// LoadProfile parses and validates one connector profile. Unknown keys, a bad
// connector id, op name, class, reversibility or surface, a repeated op, a
// standard name that equals the op's own, an op that is both an alias and an
// extension, and a bad condition id are errors.
func LoadProfile(data []byte) (*ConnectorProfile, error) {
	var p ConnectorProfile
	if err := strictYAML(data, &p); err != nil {
		return nil, fmt.Errorf("policy: profile: %w", err)
	}
	if p.ProfileVersion != 1 {
		return nil, fmt.Errorf("policy: profile: profile_version %d, want 1", p.ProfileVersion)
	}
	if !profileConnectorRE.MatchString(p.Connector) {
		return nil, fmt.Errorf("policy: profile: connector %q is not a connector id", p.Connector)
	}
	if p.Standard == "" {
		return nil, errors.New("policy: profile " + p.Connector + ": standard (the version it follows) is required")
	}
	if len(p.Ops) == 0 {
		return nil, errors.New("policy: profile " + p.Connector + ": no ops")
	}
	seen := map[string]bool{}
	for _, o := range p.Ops {
		bad := func(format string, a ...any) error {
			return fmt.Errorf("policy: profile %s: %s: %s", p.Connector, o.Name, fmt.Sprintf(format, a...))
		}
		switch {
		case !ValidOpName(o.Name):
			return nil, bad("not an op name")
		case seen[o.Name]:
			return nil, bad("listed twice")
		case !o.Class.Valid():
			return nil, bad("bad class %q", o.Class)
		case o.Reversibility != "reversible" && o.Reversibility != "compensable" && o.Reversibility != "irreversible":
			return nil, bad("bad reversibility %q", o.Reversibility)
		case o.Surface != SurfaceOp && o.Surface != SurfaceGit:
			return nil, bad("bad surface %q", o.Surface)
		case o.Unit == "":
			return nil, bad("no unit (every op names what it acts on: a repo, a team)")
		case o.StandardName != "" && !ValidOpName(o.StandardName):
			return nil, bad("standard_name %q is not an op name", o.StandardName)
		case o.StandardName == o.Name:
			return nil, bad("standard_name is the op's own name; leave it out")
		case o.StandardName != "" && o.Extension:
			return nil, bad("an op with a standard name is not an extension")
		}
		seen[o.Name] = true
		cs := map[string]bool{}
		for _, c := range o.Conditions {
			if !profileCondRE.MatchString(c) || cs[c] {
				return nil, bad("condition %q is not a snake_case id or is repeated", c)
			}
			cs[c] = true
		}
	}
	for _, n := range p.StandardNotBuilt {
		if !ValidOpName(n) {
			return nil, fmt.Errorf("policy: profile %s: standard_not_built %q is not an op name", p.Connector, n)
		}
	}
	return &p, nil
}
