package localtime

import (
	"testing"
	"time"
)

func TestDefaultIsUTC(t *testing.T) {
	at := time.Date(2026, 11, 2, 2, 15, 0, 0, time.UTC)
	if got := RFC3339(at); got != "2026-11-02T02:15:00Z" {
		t.Errorf("RFC3339 = %s", got)
	}
	if got := Clock(at); got != "2026-11-02 02:15" {
		t.Errorf("Clock = %s", got)
	}
	if Label() != "UTC" {
		t.Errorf("Label = %s", Label())
	}
}

func TestConfiguredZone(t *testing.T) {
	t.Cleanup(func() { _ = Configure("") })
	if err := Configure("America/Puerto_Rico"); err != nil { // UTC-4 all year, no daylight saving
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 2, 2, 15, 0, 0, time.UTC)
	if got := RFC3339(at); got != "2026-11-01T22:15:00-04:00" {
		t.Errorf("RFC3339 = %s", got)
	}
	if got := Clock(at); got != "2026-11-01 22:15" {
		t.Errorf("Clock = %s", got)
	}
	// no daylight saving: July is the same offset
	if got := RFC3339(time.Date(2026, 7, 1, 3, 0, 0, 0, time.UTC)); got != "2026-06-30T23:00:00-04:00" {
		t.Errorf("July = %s", got)
	}
	if got := FromRFC3339("2026-10-24T09:43:00Z"); got != "2026-10-24T05:43:00-04:00" {
		t.Errorf("FromRFC3339 = %s", got)
	}
	if got := FromRFC3339("not a time"); got != "not a time" {
		t.Errorf("an odd value must come back as it was: %s", got)
	}
	if Label() != "America/Puerto_Rico" {
		t.Errorf("Label = %s", Label())
	}
	// one token, so `chapd orch list` rows still split into the same columns for the install scripts
	if s := RFC3339(at); len(s) != 25 || containsSpace(s) {
		t.Errorf("%q is not a single token", s)
	}
}

func TestUnknownZoneIsRefused(t *testing.T) {
	t.Cleanup(func() { _ = Configure("") })
	if err := Configure("Not/AZone"); err == nil {
		t.Fatal("an unknown zone name was accepted")
	}
	if Label() != "UTC" {
		t.Errorf("a refused name must leave the zone as it was, got %s", Label())
	}
}

func containsSpace(s string) bool {
	for _, r := range s {
		if r == ' ' {
			return true
		}
	}
	return false
}
