// Package localtime is the one definition of "local time" for the operator. The default is UTC. Set CHAP_TIMEZONE to
// an IANA time zone name (for example "Europe/Berlin") to show the operator's own time instead. The signed approval
// card and the command line's human output use it; machine output (--json, the ledger, the API) stays UTC. The zone
// is read once, when the program starts; a name that is not a time zone stops the program with a clear message
// instead of silently showing a different time.
package localtime

import (
	"fmt"
	"os"
	"time"
	_ "time/tzdata" // the zone names work on a host with no time zone database (Windows, minimal containers)
)

// EnvZone is the setting that names the zone.
const EnvZone = "CHAP_TIMEZONE"

// Zone is the local time zone of the operator; UTC unless CHAP_TIMEZONE says otherwise.
var Zone = time.UTC

func init() {
	if err := Configure(os.Getenv(EnvZone)); err != nil {
		panic(fmt.Sprintf("%s: %v", EnvZone, err))
	}
}

// Configure sets the zone from an IANA name. "" and "UTC" mean UTC. It is for the start of a program and for tests;
// the approval card text depends on it, so a change while approvals are pending makes those cards be asked for again.
func Configure(name string) error {
	if name == "" || name == "UTC" {
		Zone = time.UTC
		return nil
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return fmt.Errorf("%q is not a time zone name (use an IANA name such as Europe/Berlin, or UTC)", name)
	}
	Zone = loc
	return nil
}

// Label names the zone for people: "UTC", or the IANA name.
func Label() string { return Zone.String() }

// RFC3339 formats t as local time with its offset ("2026-11-01T22:15:00-04:00"): one token, so a table column or a
// script that splits a line on spaces still finds it, and it names the same instant as the UTC form.
func RFC3339(t time.Time) string { return t.In(Zone).Format(time.RFC3339) }

// Clock formats t to the minute for people: "2026-11-01 22:15".
func Clock(t time.Time) string { return t.In(Zone).Format("2006-01-02 15:04") }

// FromRFC3339 rewrites an RFC 3339 time (any offset, as chapd's JSON writes it) as local time. A string that is not a
// time is returned unchanged, so an odd value is shown as it came.
func FromRFC3339(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return RFC3339(t)
}
