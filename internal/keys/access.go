package keys

import (
	"context"
	"strings"
)

// Access says what an owner may ever be granted (ADR-008): a key, and so a request for
// one, never reaches past its owner's own access. People and their per-person access are not built yet
// (not built yet); until then every person at the console holds the operator's access (everything the policy allows),
// and anything that is not a person holds none.
type Access interface {
	// Within returns nil when owner's access covers every op and repository, or a *RuleError that names the owner.
	Within(ctx context.Context, owner, project string, ops, units []string) error
}

// PersonAccess gives a person at the console everything the policy and the key ceiling allow, and any other
// owner nothing.
type PersonAccess struct{}

// Within implements [Access].
func (PersonAccess) Within(_ context.Context, owner, _ string, _, _ []string) error {
	if !personRE.MatchString(owner) {
		return rule("%s is not a person, so they have no access to give an agent", clipText(owner, 60))
	}
	return nil
}

// ownerName is how a refusal names an owner: the person's id without the "person:" tag.
func ownerName(owner string) string { return strings.TrimPrefix(owner, "person:") }

// subset reports whether every name of sub is in all. Both are compared as given.
func subset(sub, all []string) bool {
	in := make(map[string]bool, len(all))
	for _, s := range all {
		in[s] = true
	}
	for _, s := range sub {
		if !in[s] {
			return false
		}
	}
	return true
}

// missing lists what is in all and not in kept, in the order of all.
func missing(all, kept []string) []string {
	in := make(map[string]bool, len(kept))
	for _, s := range kept {
		in[s] = true
	}
	var out []string
	for _, s := range all {
		if !in[s] {
			out = append(out, s)
		}
	}
	return out
}
