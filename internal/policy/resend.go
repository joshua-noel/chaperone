package policy

import (
	"fmt"
	"slices"
	"strings"
)

// Resend is the connector policy of one project (policy/<project>.yaml,
// `resend:`): which sender addresses mail may go out as, who may receive it, and
// how many people one message may reach. It serves the `mail.send` operation
// when the request's target adapter is `resend` (the same operation name that the
// Google connector serves for `google`), and `mail.status`. Like `google:` it adds
// data and enables nothing: the baseline keeps both ops off, and without this block
// the Resend adapters refuse the project.
//
// A mistake in the block turns off the Resend side only, the way a bad `sentry:`
// block turns off the Sentry ops: [Resend].Invalid is set, every other field is
// left empty, and the Resend adapters refuse with the error. Mail through Gmail
// and every other op of the project keep working.
//
// The block names no host and no credential. The host is fixed in the connector
// and the API key is a vault secret.
type Resend struct {
	// Senders are the addresses a message may be sent from: bare, lower case,
	// matched exactly. The address must also be on the domain the API key is
	// restricted to; Resend enforces that, this list narrows it further.
	Senders []string
	// AllowRecipients lists who may receive mail: an exact address
	// ("ops@example.com") or a whole domain written "@example.com". A domain entry
	// matches that domain only, never a suffix: "@example.com" does not match
	// "x@mail.example.com". There is no other wildcard.
	AllowRecipients []string
	// MaxRecipients is the most people one message may reach, counting to, cc and
	// bcc together. 0 in the file means [ResendDefaultMaxRecipients]; the value
	// here is always the one in force.
	MaxRecipients int
	// Invalid is set when the block cannot be used. The other fields are then
	// empty. nil when the block is fine.
	Invalid error
}

// Limits of the block.
const (
	// ResendDefaultMaxRecipients is the cap when the block does not set one.
	ResendDefaultMaxRecipients = 5
	// ResendMaxRecipientsCeiling is the highest cap a block may set. It is the
	// most recipients one mail.send request may name, for either connector.
	ResendMaxRecipientsCeiling = 10
	ResendMaxSenders           = 5
	ResendMaxAllow             = 50
)

func (r *Resend) validate() error {
	if len(r.Senders) == 0 {
		return fmt.Errorf("senders must list at least one address: mail goes out from no address that is not listed")
	}
	if len(r.Senders) > ResendMaxSenders {
		return fmt.Errorf("senders lists %d addresses; at most %d", len(r.Senders), ResendMaxSenders)
	}
	seen := map[string]bool{}
	for _, s := range r.Senders {
		if !googleAddrRE.MatchString(s) {
			return fmt.Errorf("senders entry %q must be a bare lower-case address such as alerts@example.com (no name, no <>)", clipText(s, 60))
		}
		if seen[s] {
			return fmt.Errorf("senders lists %q twice", s)
		}
		seen[s] = true
	}
	if len(r.AllowRecipients) == 0 {
		return fmt.Errorf("allow_recipients must list at least one address or @domain: mail goes to nobody that is not listed")
	}
	if len(r.AllowRecipients) > ResendMaxAllow {
		return fmt.Errorf("allow_recipients lists %d entries; at most %d", len(r.AllowRecipients), ResendMaxAllow)
	}
	if err := validateAllow("allow_recipients", r.AllowRecipients); err != nil {
		return err
	}
	seen = map[string]bool{}
	for _, e := range r.AllowRecipients {
		if seen[e] {
			return fmt.Errorf("allow_recipients lists %q twice", e)
		}
		seen[e] = true
	}
	if r.MaxRecipients < 1 || r.MaxRecipients > ResendMaxRecipientsCeiling {
		return fmt.Errorf("max_recipients %d must be from 1 to %d (leave it out for %d)", r.MaxRecipients, ResendMaxRecipientsCeiling, ResendDefaultMaxRecipients)
	}
	return nil
}

// problem checks the block and says what is wrong with it, naming the project,
// the file and the field, or returns nil.
func (r *Resend) problem(project string) error {
	if err := r.validate(); err != nil {
		return fmt.Errorf("its policy file %s.yaml has a resend block that cannot be used, so the Resend side of mail.send and mail.status are off for project %s until it is fixed (mail through Gmail is not affected): %w", project, project, err)
	}
	return nil
}

// SenderAllowed reports whether addr is one of the listed senders. The match is
// exact.
func (r *Resend) SenderAllowed(addr string) bool { return slices.Contains(r.Senders, addr) }

// RecipientAllowed reports whether addr is an exact entry of allow_recipients or
// is in a domain that is an entry. The domain match is on the whole domain, never
// on a suffix.
func (r *Resend) RecipientAllowed(addr string) bool {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || strings.Contains(domain, "@") {
		return false
	}
	for _, e := range r.AllowRecipients {
		if e == addr || (strings.HasPrefix(e, "@") && e[1:] == domain) {
			return true
		}
	}
	return false
}
