package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Sentry is the connector policy of one project (policy/<project>.yaml,
// `sentry:`): which Sentry server and organisation the `errors.*` ops talk to,
// which Sentry projects they may touch, and which members `errors.assign` may
// assign to. Like `linear:` and `google:` it adds data and enables nothing: the
// baseline keeps every `errors.*` op off, and without this block the adapters
// refuse the project.
//
// A mistake in the block turns off the Sentry operations only, the way a bad
// `pr.tiers` glob turns off the merge ops: [Sentry].Invalid is set, every other
// field is left empty, and the adapters refuse with the error. The project and
// every other op keep working.
//
// The block names no credential. The token is a vault secret.
type Sentry struct {
	// BaseURL is the Sentry server, as an https origin with an exact host:
	// "https://sentry.io", "https://de.sentry.io" or a self-hosted
	// "https://sentry.example.com". See [CheckSentryBaseURL].
	BaseURL string
	// Organization is the organisation slug.
	Organization string
	// Projects are the Sentry project slugs the ops may read or change. An op
	// on an issue of any other project is refused.
	Projects []string
	// Assignees are the members errors.assign may assign to, written as Sentry
	// shows them: an email address or a username. Empty means errors.assign
	// refuses every request.
	Assignees []string
	// Invalid is set when the block cannot be used. The other fields are then
	// empty. nil when the block is fine.
	Invalid error
}

// Limits of the block.
const (
	SentryMaxProjects  = 20
	SentryMaxAssignees = 20
	SentryMaxSlug      = 50
	SentryMaxAssignee  = 100
	SentryMaxBaseURL   = 253 + len("https://") + len(":65535")
)

var (
	// A slug is what Sentry itself allows: lower-case letters, digits, hyphen
	// and underscore.
	sentrySlugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,49}$`)
	// An assignee is an email address or a username: letters, digits and the
	// few marks they use. It holds no ':' (so no "user:" or "team:" form that
	// names an actor by id), no '#' and no space.
	sentryAssigneeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._%+@-]{0,99}$`)
	// The one shape a base URL may have: https, a lower-case DNS name made of
	// labels, an optional port. No user name, no path, no query, no fragment.
	sentryBaseURLRE = regexp.MustCompile(`^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(:[1-9][0-9]{0,4})?$`)
	// A name whose last label is all digits is an IP address in dotted form.
	sentryNumericTLD = regexp.MustCompile(`\.[0-9]+(:[0-9]+)?$`)
)

// SentrySlugRE returns the shape of a Sentry organisation or project slug, so
// the connector and the policy agree on it.
func SentrySlugRE() *regexp.Regexp { return sentrySlugRE }

// CheckSentryBaseURL says whether s is a base URL the Sentry connector may send
// its token to. It is a narrow allow rule and not a list of bad hosts: the URL
// is https, the host is a lower-case DNS name with at least one dot that is not
// an IP address, and there is nothing after the host but an optional port. The
// connector checks every URL again with this function before it sends, so the
// rule does not rest on the policy file alone.
func CheckSentryBaseURL(s string) error {
	switch {
	case len(s) > SentryMaxBaseURL:
		return errors.New("base_url is too long")
	case !sentryBaseURLRE.MatchString(s):
		return errors.New("base_url must be an https origin with a lower-case host name and nothing after it, for example https://sentry.example.com (no user name, no path, no trailing slash, no IP address)")
	case sentryNumericTLD.MatchString(s):
		return errors.New("base_url must name a host by its DNS name, not an IP address")
	}
	if i := strings.LastIndexByte(s, ':'); i > len("https:") {
		if n, err := strconv.Atoi(s[i+1:]); err != nil || n > 65535 {
			return errors.New("base_url has a port above 65535")
		}
	}
	return nil
}

func (s *Sentry) validate() error {
	if err := CheckSentryBaseURL(s.BaseURL); err != nil {
		return err
	}
	if !sentrySlugRE.MatchString(s.Organization) {
		return errors.New("organization must be a Sentry organisation slug: lower-case letters, digits, '-' and '_', at most 50 characters")
	}
	if len(s.Projects) == 0 {
		return errors.New("projects must list at least one Sentry project slug: the ops touch no project that is not listed")
	}
	if len(s.Projects) > SentryMaxProjects {
		return fmt.Errorf("projects lists %d slugs; at most %d", len(s.Projects), SentryMaxProjects)
	}
	seen := map[string]bool{}
	for _, p := range s.Projects {
		if !sentrySlugRE.MatchString(p) {
			return fmt.Errorf("projects entry %q must be a Sentry project slug: lower-case letters, digits, '-' and '_', at most 50 characters", clipText(p, 60))
		}
		if seen[p] {
			return fmt.Errorf("projects lists %q twice", p)
		}
		seen[p] = true
	}
	if len(s.Assignees) > SentryMaxAssignees {
		return fmt.Errorf("assignees lists %d members; at most %d", len(s.Assignees), SentryMaxAssignees)
	}
	seen = map[string]bool{}
	for _, a := range s.Assignees {
		if !sentryAssigneeRE.MatchString(a) {
			return fmt.Errorf("assignees entry %q must be an email address or a username as Sentry shows it (letters, digits and . _ %% + @ -; no ':' form)", clipText(a, 60))
		}
		k := strings.ToLower(a)
		if seen[k] {
			return fmt.Errorf("assignees lists %q twice", a)
		}
		seen[k] = true
	}
	return nil
}

// problem checks the block and says what is wrong with it, naming the project,
// the file and the field, or returns nil.
func (s *Sentry) problem(project string) error {
	if err := s.validate(); err != nil {
		return fmt.Errorf("its policy file %s.yaml has a sentry block that cannot be used, so the Sentry operations (errors.list, errors.get, errors.resolve, errors.unresolve, errors.assign and errors.comment) are off for project %s until it is fixed: %w", project, project, err)
	}
	return nil
}

// ProjectAllowed reports whether the Sentry project slug is listed. The match is
// exact.
func (s *Sentry) ProjectAllowed(slug string) bool {
	for _, p := range s.Projects {
		if p == slug {
			return true
		}
	}
	return false
}

// AssigneeAllowed returns the policy's spelling of the member and whether the
// policy lists it, compared without regard to case.
func (s *Sentry) AssigneeAllowed(member string) (string, bool) { return foldFind(s.Assignees, member) }

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}
