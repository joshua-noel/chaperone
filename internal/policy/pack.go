package policy

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/joshua-noel/chaperone/internal/tierglob"
)

//go:embed data/baseline.yaml
var baselineYAML []byte

// BaselineBytes returns the embedded baseline pack source.
func BaselineBytes() []byte { return slices.Clone(baselineYAML) }

// OpRule is the policy for one op kind.
type OpRule struct {
	Enabled       bool `yaml:"enabled"`
	RatePerMinute int  `yaml:"rate_per_minute"`
	// RatePerHour is an optional second cap per caller: calls in any 60
	// minutes. 0 means no hourly cap.
	RatePerHour int `yaml:"rate_per_hour"`
}

// ThrashLimit says when repeated denials are flagged.
type ThrashLimit struct {
	Threshold     int `yaml:"threshold"`
	WindowSeconds int `yaml:"window_seconds"`
}

// PendingLimit caps the approvals agents may have pending.
type PendingLimit struct {
	PerRun     int `yaml:"per_run"`
	PerProject int `yaml:"per_project"`
	Total      int `yaml:"total"`
}

// Limits are the numeric guard rails of a pack.
type Limits struct {
	Thrash            ThrashLimit  `yaml:"thrash"`
	Pending           PendingLimit `yaml:"pending"`
	RequestTTLMinutes int          `yaml:"request_ttl_minutes"`
	DeployTTLMinutes  int          `yaml:"deploy_ttl_minutes"`
}

// Pack is a baseline pack, as parsed. Treat as immutable.
type Pack struct {
	Version  string              `yaml:"version"`
	Ops      map[string]OpRule   `yaml:"ops"`
	Profiles map[string][]string `yaml:"profiles"`
	Limits   Limits              `yaml:"limits"`

	raw []byte
}

var (
	labelRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)
	projectRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}$`)
)

// LoadBaseline parses a baseline pack and checks it against the catalog: every
// catalog op has a rule (so "disabled by default" is explicit), no rule names
// an unknown op, rates and limits are positive, profile entries are catalog ops.
func LoadBaseline(data []byte, cat *Catalog) (*Pack, error) {
	var p Pack
	if err := strictYAML(data, &p); err != nil {
		return nil, fmt.Errorf("policy: baseline: %w", err)
	}
	if !labelRe.MatchString(p.Version) {
		return nil, fmt.Errorf("policy: baseline: version %q is not a short label", p.Version)
	}
	for _, op := range cat.Ops() {
		if _, ok := p.Ops[op]; !ok {
			return nil, fmt.Errorf("policy: baseline: no rule for catalog op %s", op)
		}
	}
	for op, r := range p.Ops {
		if _, ok := cat.Lookup(op); !ok {
			return nil, fmt.Errorf("policy: baseline: rule for unknown op %s", op)
		}
		if r.RatePerMinute < 1 {
			return nil, fmt.Errorf("policy: baseline: %s: rate_per_minute must be at least 1", op)
		}
		if r.RatePerHour < 0 {
			return nil, fmt.Errorf("policy: baseline: %s: rate_per_hour must not be negative", op)
		}
	}
	for name, allow := range p.Profiles {
		for _, op := range allow {
			if _, ok := cat.Lookup(op); !ok {
				return nil, fmt.Errorf("policy: baseline: profile %s allows unknown op %s", name, op)
			}
		}
	}
	l := p.Limits
	if l.Thrash.Threshold < 1 || l.Thrash.WindowSeconds < 1 ||
		l.Pending.PerRun < 1 || l.Pending.PerProject < 1 || l.Pending.Total < 1 ||
		l.RequestTTLMinutes < 1 || l.DeployTTLMinutes < 1 {
		return nil, fmt.Errorf("policy: baseline: every limit must be at least 1")
	}
	p.raw = slices.Clone(data)
	return &p, nil
}

// Baseline loads the embedded baseline pack.
func Baseline(cat *Catalog) (*Pack, error) { return LoadBaseline(baselineYAML, cat) }

// Effective is the policy in force for one project: the baseline, narrowed by
// the project file if there is one. If the project file is invalid, Invalid is
// set and every op of the project is refused (fail closed).
type Effective struct {
	Project  string
	Version  string // policy_version
	Ops      map[string]OpRule
	Profiles map[string][]string
	Limits   Limits
	// PR is the project's `pr:` block; nil when the project file has none.
	PR *PR
	// Google is the project's `google:` block (mail and Drive allowlists,
	// L1-16); nil when the project file has none, and then mail.send and
	// drive.share refuse the project.
	Google *Google
	// Linear is the project's `linear:` block (the operator-board intake team,
	// label and states); nil when the project file has none, and
	// then the intake ops refuse the project.
	Linear  *Linear
	Invalid error
}

// PR is the merge policy of one project (policy/<project>.yaml, `pr:`).
type PR struct {
	Repo        string   // "owner/name": the repository PRs of this project live in
	Base        string   // the branch PRs merge into
	ExtraChecks []string // check names that must pass besides `verify`
	Tiers       struct{ High, Medium, Low []string }
	// LocalCI is the `pr.local_ci` block (ADR-002 amendment 10); nil when the project has none, and then pr.merge
	// reads `verify` from GitHub Actions and nothing else.
	LocalCI *LocalCI
}

// Modes of [LocalCI].
const (
	// LocalCIAlso: pr.merge needs the local CI check run on top of `verify` and the extra checks.
	LocalCIAlso = "also"
	// LocalCIInstead: pr.merge needs the local CI check run in place of `verify`. The extra checks still count.
	LocalCIInstead = "instead"
)

// DefaultLocalCICheck is the name of the check run `ci.report` posts when the policy names none.
const DefaultLocalCICheck = "local-ci"

// LocalCI says that a project accepts the result of a local CI run (a the runner room), posted by Chaperone's own GitHub
// App through `ci.report`, as a required check of `pr.merge`.
type LocalCI struct {
	Mode  string // LocalCIAlso or LocalCIInstead
	Check string // name of the check run; DefaultLocalCICheck when the file names none
}

var prRepoRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)

func (p *PR) validate() error {
	if !prRepoRE.MatchString(p.Repo) {
		return errors.New("repo must be owner/name")
	}
	if p.Base == "" || strings.ContainsAny(p.Base, " \t\r\n") {
		return errors.New("base must name a branch (no spaces)")
	}
	for _, n := range p.ExtraChecks {
		if strings.TrimSpace(n) == "" {
			return errors.New("extra_checks has an empty name")
		}
	}
	// A tier glob that no plain path can match would silently do nothing: refuse it here, when the file loads, as
	// the classifier does at request time (both call tierglob.Validate).
	for _, set := range []struct {
		name  string
		globs []string
	}{{"high", p.Tiers.High}, {"medium", p.Tiers.Medium}, {"low", p.Tiers.Low}} {
		for _, g := range set.globs {
			if err := tierglob.Validate(g); err != nil {
				return fmt.Errorf("tiers.%s: %w", set.name, err)
			}
		}
	}
	if l := p.LocalCI; l != nil {
		if err := l.validate(p.ExtraChecks); err != nil {
			return fmt.Errorf("local_ci: %w", err)
		}
	}
	return nil
}

func (l *LocalCI) validate(extra []string) error {
	if l.Mode != LocalCIAlso && l.Mode != LocalCIInstead {
		return fmt.Errorf("mode must be %q or %q, got %q", LocalCIAlso, LocalCIInstead, l.Mode)
	}
	if n := len([]rune(l.Check)); n < 1 || n > 64 || strings.TrimSpace(l.Check) != l.Check || strings.ContainsAny(l.Check, "\r\n\x00") {
		return errors.New("check must be a name of 1 to 64 characters, with no line break and no space at either end")
	}
	if l.Check == "verify" || slices.Contains(extra, l.Check) {
		return fmt.Errorf("check %q is already required from GitHub Actions; name another", l.Check)
	}
	return nil
}

// Enabled reports whether op is enabled for the project.
func (e *Effective) Enabled(op string) bool {
	return e.Invalid == nil && e.Ops[op].Enabled
}

// Rate returns the per-minute rate of op for one caller.
func (e *Effective) Rate(op string) int { return e.Ops[op].RatePerMinute }

// RateHour returns the per-hour cap of op for one caller; 0 means none.
func (e *Effective) RateHour(op string) int { return e.Ops[op].RatePerHour }

// ProfileCeiling returns the ops a profile may ever ask for, sorted.
func (e *Effective) ProfileCeiling(profile string) ([]string, bool) {
	allow, ok := e.Profiles[profile]
	if !ok {
		return nil, false
	}
	out := slices.Clone(allow)
	sort.Strings(out)
	return out, true
}

// TTL returns the lifetime in minutes of an unapproved request for op.
func (e *Effective) TTL(op string) int {
	if op == "deploy" {
		return e.Limits.DeployTTLMinutes
	}
	return e.Limits.RequestTTLMinutes
}

func digest(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		var n [8]byte
		l := uint64(len(p))
		for i := range n {
			n[i] = byte(l >> (8 * (7 - i)))
		}
		h.Write(n[:])
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// Version names the pack in force: the baseline label plus a digest of the
// baseline bytes and, when given, the project file bytes. Any byte change is
// a new version.
func (p *Pack) version(projectBytes []byte) string {
	if projectBytes == nil {
		return p.Version + "+" + digest(p.raw)
	}
	return p.Version + "+" + digest(p.raw, projectBytes)
}

// BaselineVersion is the policy_version of the baseline with no project file:
// what an event that belongs to no project (an operator command) records.
func (p *Pack) BaselineVersion() string { return p.version(nil) }

// ForProject returns the baseline unchanged for a project with no file.
func (p *Pack) ForProject(project string) *Effective {
	return &Effective{
		Project:  project,
		Version:  p.version(nil),
		Ops:      cloneOps(p.Ops),
		Profiles: cloneProfiles(p.Profiles),
		Limits:   p.Limits,
	}
}

func cloneOps(in map[string]OpRule) map[string]OpRule {
	out := make(map[string]OpRule, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneProfiles(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = slices.Clone(v)
	}
	return out
}
