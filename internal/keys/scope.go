package keys

import (
	"strings"

	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// ScopeRules are the rules of what a key may ever hold (ADR-008 rule R1) and the unit it is tied to . One
// copy serves the card that grants a key and the ask that precedes it, so an agent cannot ask for what no card
// could grant.
type ScopeRules struct {
	Catalog interface {
		Lookup(op string) (policy.Entry, bool)
	}
	// Enabled reports whether the policy turns op on for project.
	Enabled func(project, op string) bool
	// Project returns the project's pull-request repository (its `pr:` block).
	Project func(project string) (ops.PRProject, bool)
}

func (r ScopeRules) ok() bool { return r.Catalog != nil && r.Enabled != nil && r.Project != nil }

// Check judges a list of ops and repositories in project, both already sorted and in lower case. It reports
// whether the scope is sensitive (some op asks for a card every time), and the first rule it breaks as an
// *ops.Refusal.
func (r ScopeRules) Check(project string, opList, units []string) (sensitive bool, err error) {
	for _, op := range opList {
		if ops.NeverInKey(op) {
			return false, refuse("%s can never be in a key: a key cannot decide, issue or administer anything", clipText(op, 60))
		}
		entry, known := r.Catalog.Lookup(op)
		if !known {
			return false, invalid("unknown op %q", clipText(op, 60))
		}
		if entry.Class == policy.ClassCritical {
			return false, refuse("%s is critical, and a critical op is never in a key", op)
		}
		if _, has := ops.KeyUnitKind(op); !has {
			return false, refuse("%s names no unit a key can be bound to (a repository or the project), so it cannot be in a key yet", op)
		}
		if !r.Enabled(project, op) {
			return false, refuse("%s is disabled by policy for %s, so a key cannot hold it", op, project)
		}
		if entry.Class != policy.ClassRoutine {
			sensitive = true // it asks for a card every time: the key is sensitive, and capped at 7 days
		}
	}
	// A key is tied to a unit. A repository op needs the repositories; a repository named for no op is a mistake.
	needsRepo := false
	for _, op := range opList {
		if k, _ := ops.KeyUnitKind(op); k == ops.UnitRepo {
			needsRepo = true
		}
	}
	switch {
	case needsRepo && len(units) == 0:
		return false, refuse("a key with pull-request ops names the repository it covers (units)")
	case !needsRepo && len(units) > 0:
		return false, refuse("units name repositories, and none of the ops in this key is bound to one")
	}
	if needsRepo {
		pr, ok := r.Project(project)
		if !ok || pr.Repo == "" {
			return false, refuse("project %s has no pull request settings (a pr: block), so no repository can be named", project)
		}
		for _, u := range units {
			if !strings.EqualFold(u, pr.Repo) {
				return false, refuse("project %s is %s, so a key for it cannot cover %s", project, pr.Repo, clipText(u, 80))
			}
		}
	}
	return sensitive, nil
}

// ReadOps lists the ops "same as me, read-only" stands for: the routine ops a key may hold that the policy turns
// on for project (every one of them only reads). The repositories are the project's own.
func (r ScopeRules) ReadOps(project string) (opList, units []string) {
	for _, op := range ops.KeyCeilingOps() {
		entry, ok := r.Catalog.Lookup(op)
		if !ok || entry.Class != policy.ClassRoutine || ops.NeverInKey(op) || !r.Enabled(project, op) {
			continue
		}
		opList = append(opList, op)
		if k, _ := ops.KeyUnitKind(op); k == ops.UnitRepo && len(units) == 0 {
			if pr, ok := r.Project(project); ok && pr.Repo != "" {
				units = []string{strings.ToLower(pr.Repo)}
			}
		}
	}
	return opList, units
}
