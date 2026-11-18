package notify

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidWake is returned (wrapped) when a [Wake] field is outside its
// allowlist pattern. Nothing is sent.
var ErrInvalidWake = errors.New("notify: invalid wake-up")

// Notifier sends one wake-up. Drivers (ntfy; Pushover later) and [Service]
// implement it. A caller must never fail or delay an approval because Notify
// returned an error: the push is a convenience, the card is the product.
type Notifier interface {
	Notify(ctx context.Context, w Wake) error
}

// Wake is everything a push may be made from. It has no field for parameters,
// and that is the point: add a field only with an ADR-004 amendment, because
// TestWakeAndPushFieldAllowlist pins this list.
type Wake struct {
	// Kind is the operation kind, e.g. "deploy" or "mail.send" (spec op_kind).
	Kind string
	// Project is the project slug (spec project_id).
	Project string
	// OpHash is the request's op hash: "sha256:<64 hex>" as the spec writes it,
	// or the bare 64 hex. Only its first 8 characters reach the phone; the whole
	// value is the dedupe key.
	OpHash string
	// ExpiresAt is when the request expires.
	ExpiresAt time.Time
	// Pending is how many approvals are waiting, this one included.
	Pending int
}

// Push is the wire content of one wake-up. It has no link, no click target, no
// actions, no attachment and no tags. Priority is a constant: no quiet hours
// (decision #16).
type Push struct {
	Title    string `json:"title"`
	Message  string `json:"message"`
	Priority int    `json:"priority"`
}

const (
	pushTitle    = "Chaperone: approval waiting"
	pushPriority = 4 // ntfy "high"; the same at every hour
	maxPending   = 999
)

// The patterns are the factory-spec ones (common.schema.json op_kind and
// project_id). They are what keeps free text out: no space, no slash, no colon,
// no quote and no newline can match.
var (
	kindRE    = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)
	projectRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}$`)
	opHashRE  = regexp.MustCompile(`^(?:sha256:)?([0-9a-f]{64})$`)
)

const maxKind = 64

// normalizeHash returns the 64 hex characters of an op hash.
func normalizeHash(s string) (string, bool) {
	m := opHashRE.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// validate checks every field against its allowlist pattern.
func (w Wake) validate() (hash string, err error) {
	if len(w.Kind) > maxKind || !kindRE.MatchString(w.Kind) {
		return "", fmt.Errorf("%w: kind", ErrInvalidWake)
	}
	if !projectRE.MatchString(w.Project) {
		return "", fmt.Errorf("%w: project", ErrInvalidWake)
	}
	hash, ok := normalizeHash(w.OpHash)
	if !ok {
		return "", fmt.Errorf("%w: op hash", ErrInvalidWake)
	}
	if w.ExpiresAt.IsZero() {
		return "", fmt.Errorf("%w: expiry", ErrInvalidWake)
	}
	if w.Pending < 1 || w.Pending > maxPending {
		return "", fmt.Errorf("%w: pending count", ErrInvalidWake)
	}
	return hash, nil
}

// Build makes the push for w. It is pure, and the only place push text is made:
// the text is a fixed template with the five Wake fields in it, each checked
// against its pattern first. Anything else (a parameter, a recipient, a URL, a
// newline) makes Build return [ErrInvalidWake] instead of a push.
//
// Example message:
//
//	deploy storefront
//	op 1a2b3c4d, expires 14:32 UTC
//	3 pending
func Build(w Wake) (Push, error) {
	hash, err := w.validate()
	if err != nil {
		return Push{}, err
	}
	var b strings.Builder
	b.WriteString(w.Kind)
	b.WriteByte(' ')
	b.WriteString(w.Project)
	b.WriteString("\nop ")
	b.WriteString(hash[:8])
	b.WriteString(", expires ")
	b.WriteString(w.ExpiresAt.UTC().Format("15:04"))
	b.WriteString(" UTC\n")
	b.WriteString(strconv.Itoa(w.Pending))
	b.WriteString(" pending")
	return Push{Title: pushTitle, Message: b.String(), Priority: pushPriority}, nil
}
