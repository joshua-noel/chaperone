package google

import (
	"fmt"
	"regexp"
	"strings"
)

// addrRE is the only shape of recipient the connector accepts: a bare,
// lower-case ASCII address. No display name, no <> characters, no quotes, no
// comments, no IDN, no uppercase: a header-injection or look-alike trick has
// no character to hide in, and the card shows exactly what is sent. It is the
// same shape the policy file accepts for an allowlist entry.
var addrRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// checkAddress validates one recipient.
func checkAddress(a string) error {
	if len(a) > 254 || !addrRE.MatchString(a) {
		return fmt.Errorf("%q is not a plain lower-case address (no name, no <>, ASCII only)", clipText(a, 60))
	}
	return nil
}

// allowed reports whether addr is on list: an exact address or an "@domain"
// entry. The domain entry matches the address's whole domain, not a suffix:
// "@example.com" does not match "x@mail.example.com" or "x@notexample.com".
func allowed(list []string, addr string) bool {
	_, domain, _ := strings.Cut(addr, "@")
	for _, e := range list {
		if e == addr || (strings.HasPrefix(e, "@") && e[1:] == domain) {
			return true
		}
	}
	return false
}

// refuseUnlisted returns the addresses of recipients that are not on list.
func refuseUnlisted(list, recipients []string) []string {
	var bad []string
	for _, r := range recipients {
		if !allowed(list, r) {
			bad = append(bad, r)
		}
	}
	return bad
}
