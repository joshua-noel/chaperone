package console

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/store"
)

// Origin is one place the console is reached and the WebAuthn relying party
// that goes with it. ADR-004: the server is {localhost, http://localhost:55398};
// the phone (L1-22) is {<server>.<tailnet>.ts.net, https://<server>.<tailnet>.ts.net}.
type Origin struct {
	RPID string // WebAuthn RP ID: the origin's host name, no port
	URL  string // scheme://host[:port], no path
}

// LocalOrigin is the server console origin from ADR-004.
var LocalOrigin = Origin{RPID: "localhost", URL: "http://localhost:55398"}

// Config configures [New].
type Config struct {
	// DB is the migrated state database (internal/store).
	DB *store.DB
	// Origins lists every origin the console answers on. At least one. A
	// request whose Host is not the host of one of them is refused.
	Origins []Origin
	// DisplayName is the relying-party name the authenticator shows. Default
	// "Chaperone".
	DisplayName string
	// OnEvent receives audit events. It runs on the request goroutine and
	// must not block. Optional.
	OnEvent func(Event)
	// Log receives operational detail. Optional (discarded).
	Log *slog.Logger
	// Now is the clock. Default time.Now.
	Now func() time.Time
	// SessionIdle is how long a session lives without a request (default
	// 30 minutes); SessionMax is its absolute lifetime (default 8 hours).
	SessionIdle time.Duration
	SessionMax  time.Duration
	// CeremonyTTL is how long a Begin response stays valid (default 5 minutes).
	CeremonyTTL time.Duration
	// FrameAncestors lists the origins (scheme://host[:port], lower case) that may show the framable console pages
	// (guard.go: framablePaths) in a frame and ask for a passkey there. Empty, the default: nothing is framed and a
	// passkey made in a frame is refused. It never covers sign-in, enrolment, secret entry or any other page the guard
	// does not list.
	FrameAncestors []string
}

// Event is an audit record. Name is one of the Event* constants.
type Event struct {
	Name       string
	Reason     string // refusals: a short code such as "origin_mismatch"
	Detail     string // refusals: the library's message; for logs, never for clients
	ApproverID int64
	// Bootstrap is true on console.enrolled when the enrolment created the
	// first approver (chapd enroll). A later device is the approvers.enroll op
	// with its own approval, recorded by the approvals path, never by this flag.
	Bootstrap bool
	// ApproverSpecID is the spec approver id (approverSpecID) of a login.
	ApproverSpecID string
	// Ceremony is "login", "enroll" or "approve" on a refusal (spec v0.1.1,
	// console.refused).
	Ceremony     string
	CredentialID []byte
	RPID         string
	Origin       string
	UserVerified bool
	SignCount    uint32
}

// Event names.
const (
	EventEnrolled = "console.enrolled" // a credential was registered
	EventLogin    = "console.login"    // an assertion was verified and a session made
	EventRefused  = "console.refused"  // a WebAuthn ceremony was refused
)

func (c *Config) validate() error {
	if c.DB == nil {
		return errors.New("console: Config.DB is required")
	}
	if len(c.Origins) == 0 {
		return errors.New("console: Config.Origins is empty")
	}
	seen := map[string]bool{}
	for _, o := range c.Origins {
		host, err := o.check()
		if err != nil {
			return err
		}
		if seen[host] {
			return fmt.Errorf("console: origin host %q listed twice", host)
		}
		seen[host] = true
	}
	return checkFrameAncestors(c.FrameAncestors)
}

// ancestorHostRE is the host[:port] of a frame ancestor: lower-case letters, digits, dots and hyphens, an optional
// port. It has no wildcard, no userinfo and no character that could add a second source to a CSP header.
var ancestorHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)

// checkFrameAncestors refuses an ancestor that is not a plain origin. The values go into a Content-Security-Policy
// header and into the WebAuthn top-origin list, so each must be exactly one origin and nothing else. Plain http is
// for localhost only, as for the console's own origins.
func checkFrameAncestors(list []string) error {
	seen := map[string]bool{}
	for _, a := range list {
		u, err := url.Parse(a)
		switch {
		case err != nil, u.Scheme != "http" && u.Scheme != "https", u.Path != "", u.RawQuery != "", u.Fragment != "", u.User != nil, u.Opaque != "",
			!ancestorHostRE.MatchString(u.Host), strings.HasSuffix(a, "/"):
			return fmt.Errorf("console: frame ancestor %q must be a lower-case scheme://host[:port] and nothing else", a)
		case u.Scheme == "http" && u.Hostname() != "localhost":
			return fmt.Errorf("console: frame ancestor %q: plain http is only for localhost; use https", a)
		case seen[a]:
			return fmt.Errorf("console: frame ancestor %q listed twice", a)
		}
		seen[a] = true
	}
	return nil
}

// check validates one origin and returns its URL host (host[:port], lower case).
func (o Origin) check() (string, error) {
	u, err := url.Parse(o.URL)
	if err != nil {
		return "", fmt.Errorf("console: origin %q: %w", o.URL, err)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return "", fmt.Errorf("console: origin %q: scheme must be http or https", o.URL)
	case u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return "", fmt.Errorf("console: origin %q must be scheme://host[:port] and nothing else", o.URL)
	case u.Host != strings.ToLower(u.Host):
		return "", fmt.Errorf("console: origin %q must be lower case", o.URL)
	case u.Scheme == "http" && u.Hostname() != "localhost":
		return "", fmt.Errorf("console: origin %q: plain http is only for localhost; use https", o.URL)
	case o.RPID != u.Hostname():
		return "", fmt.Errorf("console: origin %q: RP ID %q must equal the origin's host name %q", o.URL, o.RPID, u.Hostname())
	}
	return u.Host, nil
}

func (o Origin) secure() bool { return strings.HasPrefix(o.URL, "https://") }
