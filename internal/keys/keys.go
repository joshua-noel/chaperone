// Package keys is Chaperone's custom keys (ADR-008, operator decisions of 3 Nov
// 2026): a key a person builds for a script or an agent.
//
// A key is a Chaperone token, never a vendor secret. It names the ops Chaperone
// will do, one project and optionally the repositories inside it, an owner, a
// holder, an expiry and an hourly rate. It is made in two steps: the op
// `keys.issue` (a card the operator signs with Windows Hello) writes the key's
// row with no token; the claim, by the caller that asked, makes the token and
// stores only its SHA-256. A call under a key goes through the same policy,
// approval and ledger path as every other call: a key never pre-approves a
// risky op (a high op raises a card each time), never holds a critical op, and
// never decides or issues anything.
package keys

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/ops"
)

// The operator's limits (3 Nov 2026).
const (
	DefaultTTLHours  = 24
	MaxDays          = 30
	SensitiveMaxDays = 7
	// ClaimWindow is how long a granted key waits to be claimed before it is
	// revoked (the spec's one hour).
	ClaimWindow = time.Hour
)

// Prefix starts every key token.
const Prefix = ops.KeyPrefix

const secretChars = 43 // base64url of 32 bytes, unpadded

var (
	projectRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}$`)
	labelRE   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
	unitRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9._-]{1,100}$`)
	keyIDRE   = regexp.MustCompile(`^k-[0-9a-f]{16}$`)
)

// Holder kinds.
const (
	HolderPerson = "person"
	HolderAgent  = "agent"
)

// StoppedWhy is what a stopped agent is told, wherever it asks (an agent that a
// human stopped is told so: "stopped by a human: ask your owner").
const StoppedWhy = "stopped by a human: ask your owner"

// RuleError is a grant rule the request breaks. It is the caller's mistake, not
// a fault: the op is refused with Why.
type RuleError struct{ Why string }

func (e *RuleError) Error() string { return e.Why }

func rule(format string, a ...any) error { return &RuleError{Why: fmt.Sprintf(format, a...)} }

// Grant is a validated keys.issue request: what the card said and the operator
// signed. It holds no token.
type Grant struct {
	Project    string
	Owner      string // who the key acts for: the orchestrator that asked
	HolderKind string
	Holder     string
	Ops        []string
	Units      []string
	TTLHours   int
	Rate       int // calls an hour; 0 means the default
	Sensitive  bool

	// Set when the card was approved.
	ApprovalID string
	RequestID  string
	GrantedBy  string
	Claimant   string // Caller.Key() of who may claim it
}

// Limits checks the lifetime of a key (operator decisions: at most 30 days; a
// key that holds an ask-only op, which makes it sensitive, at most 7). The
// database enforces the same numbers with a CHECK.
func Limits(ttl time.Duration, sensitive bool) error {
	switch {
	case ttl < time.Hour:
		return rule("a key lasts at least 1 hour")
	case ttl > MaxDays*24*time.Hour:
		return rule("a key lasts at most %d days", MaxDays)
	case sensitive && ttl > SensitiveMaxDays*24*time.Hour:
		return rule("a key that holds an op that asks for a card each time (a sensitive key) lasts at most %d days", SensitiveMaxDays)
	}
	return nil
}

// Shape checks the fields every grant needs and puts the lists in the one
// order the card, the hash and the row all use (sorted, no duplicates).
func (g *Grant) Shape() error {
	if !projectRE.MatchString(g.Project) {
		return rule("a key needs a project")
	}
	if g.HolderKind != HolderPerson && g.HolderKind != HolderAgent {
		return rule("the holder is a person or an agent")
	}
	if !labelRE.MatchString(g.Holder) {
		return rule("the holder's name must match %s", labelRE)
	}
	if len(g.Ops) == 0 || len(g.Ops) > 16 {
		return rule("a key names 1 to 16 ops")
	}
	g.Ops = sortedUnique(g.Ops)
	g.Units = sortedUnique(lowerAll(g.Units))
	if len(g.Units) > 8 {
		return rule("a key covers at most 8 repositories")
	}
	for _, u := range g.Units {
		if !unitRE.MatchString(u) {
			return rule("%q is not a repository (owner/name)", clipText(u, 60))
		}
	}
	if g.TTLHours == 0 {
		g.TTLHours = DefaultTTLHours
	}
	if g.Rate == 0 {
		g.Rate = ops.DefaultKeyRatePerHour
	}
	if g.Rate < 1 || g.Rate > ops.DefaultKeyRatePerHour {
		return rule("the rate is 1 to %d calls an hour (it can be lowered, never raised)", ops.DefaultKeyRatePerHour)
	}
	return Limits(time.Duration(g.TTLHours)*time.Hour, g.Sensitive)
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func sortedUnique(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	n := 0
	for i, s := range out {
		if i == 0 || s != out[n-1] {
			out[n] = s
			n++
		}
	}
	return out[:n]
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Errors of the store the HTTP layer maps.
var (
	ErrNotFound       = errors.New("keys: no such key")
	ErrAlreadyClaimed = errors.New("keys: the key was already claimed")
	ErrClaimExpired   = errors.New("keys: the claim window has passed")
	ErrRevoked        = errors.New("keys: the key is revoked")
)
