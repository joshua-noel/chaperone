package ops

import (
	"sort"
	"strings"
)

// What a custom key may ever hold (ADR-008, rule R1; operator decisions of
// 3 Nov 2026): routine ops, and risky ops only as "ask" (each use still
// raises its card); never a critical op, never an op that decides, issues or
// administers; and only an op that says what unit of the project it is bound
// to, so that no key means "everything".

// Unit kinds an op can be bound to.
const (
	UnitProject = "project" // the key's one project
	UnitRepo    = "repo"    // owner/name; the key lists the repositories it covers
)

// keyUnitKinds is the key ceiling of this build: the ops a key may hold, and
// the unit of each. An op missing here fails closed for key callers. It grows
// with the preset registry; the pull-request read ops are the first adopters.
var keyUnitKinds = map[string]string{
	OpPRView:   UnitRepo,
	OpPRDiff:   UnitRepo,
	OpPRChecks: UnitRepo,
	OpPRFiles:  UnitRepo,
	"health":   UnitProject,
	"logs":     UnitProject,
	"deploy":   UnitProject, // class high: a key may hold it ask-only; every use raises a card
}

// KeyUnitKind returns the unit kind of an op a key may hold.
func KeyUnitKind(op string) (string, bool) {
	k, ok := keyUnitKinds[op]
	return k, ok
}

// KeyCeilingOps lists the ops a key may ever hold, sorted by name.
func KeyCeilingOps() []string {
	out := make([]string, 0, len(keyUnitKinds))
	for op := range keyUnitKinds {
		out = append(out, op)
	}
	sort.Strings(out)
	return out
}

// neverInKeyPrefixes and neverInKeyOps are the ops no key may ever hold,
// whatever its row says: they decide, issue, administer, read secrets or are
// the orchestrator's own.
var (
	neverInKeyPrefixes = []string{"keys.", "people.", "roles.", "secrets.", "issue.", "intake."}
	neverInKeyOps      = []string{"approvers.enroll", "policy.activate", "ci.report", "repo.settings", "host.scripts.refresh"}
)

// NeverInKey reports an op that can never be in a key.
func NeverInKey(op string) bool {
	for _, p := range neverInKeyPrefixes {
		if strings.HasPrefix(op, p) {
			return true
		}
	}
	return containsString(neverInKeyOps, op)
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
