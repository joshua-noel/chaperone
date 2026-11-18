package approvals

import (
	"strings"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/localtime"
)

// Review item 6: the card says the deadline in the operator's zone and in UTC on one line, in the signed text. The
// default zone is UTC; CHAP_TIMEZONE names another. America/Puerto_Rico is UTC-4 all year (no daylight saving), so the
// offset is the same in July.
func TestCardWritesTheDeadlineInTheLocalZoneAndUTC(t *testing.T) {
	t.Cleanup(func() { _ = localtime.Configure("") })
	for name, c := range map[string]struct {
		zone string
		at   time.Time
		want string
	}{
		"default zone is UTC":                 {"", time.Date(2026, 11, 2, 2, 15, 0, 0, time.UTC), "Decide before 2026-11-02 02:15 UTC time (2026-11-02T02:15:00Z). After that the request is dropped."},
		"night, the day before in local time": {"America/Puerto_Rico", time.Date(2026, 11, 2, 2, 15, 0, 0, time.UTC), "Decide before 2026-11-01 22:15 America/Puerto_Rico time (2026-11-02T02:15:00Z). After that the request is dropped."},
		"midday":                              {"America/Puerto_Rico", time.Date(2026, 10, 24, 12, 15, 0, 0, time.UTC), "Decide before 2026-10-24 08:15 America/Puerto_Rico time (2026-10-24T12:15:00Z). After that the request is dropped."},
		"summer, no daylight saving":          {"America/Puerto_Rico", time.Date(2026, 7, 1, 3, 0, 0, 0, time.UTC), "Decide before 2026-06-30 23:00 America/Puerto_Rico time (2026-07-01T03:00:00Z). After that the request is dropped."},
	} {
		t.Run(name, func(t *testing.T) {
			if err := localtime.Configure(c.zone); err != nil {
				t.Fatal(err)
			}
			card := mustRender(t, baseApproval(func(a *Approval) { a.RequestExpires = c.at }))
			if !strings.Contains(card, "\n"+c.want+"\n") {
				t.Fatalf("card lacks %q:\n%s", c.want, card)
			}
			if !strings.HasPrefix(card, "CHAPERONE APPROVAL CARD v3\n") {
				t.Fatal("the template changed, so the card version is 3")
			}
			secs, ok := ParseCard(card)
			if !ok || len(secs) == 0 {
				t.Fatal("the card does not parse")
			}
		})
	}
}
