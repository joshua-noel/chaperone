package policy

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Google is the connector policy of one project (policy/<project>.yaml,
// `google:`, ticket L1-16). Like `pr:` it adds data and enables nothing: the
// baseline keeps mail.send and drive.share off, and without this block the
// adapters refuse the project.
type Google struct {
	Mail struct {
		// AllowRecipients lists the addresses mail may go to: an exact address
		// ("gilliano@example.com") or a whole domain written "@example.com".
		AllowRecipients []string
	}
	Drive struct {
		// AllowRecipients has the same form as the mail list.
		AllowRecipients []string
		// MaxRole is the highest role a share may grant: reader, commenter or
		// writer. Empty means reader.
		MaxRole string
	}
}

var (
	googleAddrRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	googleDomainRE = regexp.MustCompile(`^@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// GoogleRoles lists the roles a drive.share may name, lowest first.
var GoogleRoles = []string{"reader", "commenter", "writer"}

func validateAllow(what string, list []string) error {
	for _, e := range list {
		if e != strings.ToLower(e) || !(googleAddrRE.MatchString(e) || googleDomainRE.MatchString(e)) {
			return fmt.Errorf("%s: %q is not a lower-case address or an @domain", what, e)
		}
	}
	return nil
}

func (g *Google) validate() error {
	if err := validateAllow("mail.allow_recipients", g.Mail.AllowRecipients); err != nil {
		return err
	}
	if err := validateAllow("drive.allow_recipients", g.Drive.AllowRecipients); err != nil {
		return err
	}
	if g.Drive.MaxRole != "" && !slices.Contains(GoogleRoles, g.Drive.MaxRole) {
		return fmt.Errorf("drive.max_role %q must be one of %v", g.Drive.MaxRole, GoogleRoles)
	}
	return nil
}
