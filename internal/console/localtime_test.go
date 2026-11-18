package console

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/web"
)

// Review item 6: times are written as UTC in <time datetime>, and localtime.js shows them in the browser's time zone with
// the UTC time after each one. Without script the UTC text is still there.
func TestTimesAreTimeElementsWithTheUTCValue(t *testing.T) {
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	sr.seedRun("r-aaaa1", "acme-shop")
	sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "deploy pilot: OP_DISABLED")
	utc := regexp.MustCompile(`<time datetime="(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)">(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)</time>`)
	for _, p := range []string{"/", "/runs", "/ledger"} {
		page := get(t, b, p)
		if !strings.Contains(page, `/static/localtime.js`) {
			t.Errorf("%s does not load localtime.js", p)
		}
		m := utc.FindStringSubmatch(page)
		if m == nil {
			t.Errorf("%s has no <time datetime=UTC>UTC</time>", p)
		} else if m[1] != m[2] {
			t.Errorf("%s: the time text %q is not its datetime %q", p, m[2], m[1])
		}
	}
}

// The last anchor on /ledger and the "approval can be used until" line on /secrets were raw UTC text, so the script
// could not show them in local time; the ledger page also no longer says the UTC is only on hover.
func TestAnchorAndSecretDeadlineAreTimeElements(t *testing.T) {
	sr := newScrRig(t)
	b, auth := sr.signedIn()
	sr.seedDenial("r-aaaa1", "acme-shop", "OP_DISABLED", "x")
	if _, err := sr.led.Anchor(t.Context(), "offline-copy", "usb-1"); err != nil {
		t.Fatal(err)
	}
	ledger := get(t, b, "/ledger")
	if !regexp.MustCompile(`Event \d+ at <time datetime="\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ">`).MatchString(ledger) {
		t.Error("the last anchor time on /ledger is not a <time datetime>")
	}
	if strings.Contains(ledger, "hover for UTC") || !strings.Contains(ledger, "with the UTC time after each one") {
		t.Error("/ledger still says the UTC time is only on hover")
	}

	// An approved card whose value was not stored: the state that shows the deadline.
	id := sr.requestSecret(b, importForm("gh-app-key", canaryA))
	h := sr.con.scr.pend.take(id)
	sr.approveCard(b, auth, id)
	if err := sr.con.scr.pend.put(id, h); err != nil {
		t.Fatal(err)
	}
	secrets := get(t, b, "/secrets")
	if !regexp.MustCompile(`can be used until <time datetime="\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ">`).MatchString(secrets) {
		t.Error("the approval deadline on /secrets is not a <time datetime>")
	}
}

func TestLocalTimeScriptReadsTheZoneFromTheLayout(t *testing.T) {
	b, err := fs.ReadFile(web.Static(), "localtime.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`meta[name="time-zone"]`, "time[datetime]", "el.textContent.trim() !== utc", "'utc muted'"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("localtime.js lacks %q", want)
		}
	}
	if regexp.MustCompile(`[A-Z][a-z]+/[A-Z][A-Za-z_]+`).Match(b) {
		t.Error("localtime.js hard-codes a time zone name; it must read the layout's")
	}
	if strings.Contains(string(b), "el.title") {
		t.Error("localtime.js puts the UTC time in a title again; it must be visible text")
	}
}

// The UTC time must be in the rendered text, not only in a title (a title is not reachable by keyboard, touch or most
// screen readers). This runs localtime.js under Node against a stub document and reads back what it wrote.
func TestLocalTimeScriptWritesTheUTCTimeAsVisibleText(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; CI runs this test")
	}
	src, err := fs.ReadFile(web.Static(), "localtime.js")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "localtime.js")
	if err := os.WriteFile(file, src, 0o600); err != nil {
		t.Fatal(err)
	}
	const driver = `
const fs = require('fs'), vm = require('vm');
function el(utc, text) {
  return { textContent: text, dataset: {}, children: [],
    getAttribute(k) { return k === 'datetime' ? utc : null; },
    append(...xs) { this.children.push(...xs); } };
}
const document = { readyState: 'loading', addEventListener() {},
  querySelector() { return process.env.META_ZONE ? { content: process.env.META_ZONE } : null; },
  createElement() { return { className: '', textContent: '' }; } };
const module = { exports: {} };
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), { module, document });
// What a reader gets: the element's own text, then each appended string or span's text.
function shown(e) { return e.textContent + e.children.map(c => typeof c === 'string' ? c : c.textContent).join(''); }
const night = el('2026-11-02T02:15:00Z', '2026-11-02T02:15:00Z');
const ago = el('2026-11-02T02:15:00Z', '4 min ago');
const bad = el('not a time', 'not a time');
module.exports.convert(night); module.exports.convert(ago); module.exports.convert(bad);
const span = night.children.find(c => typeof c !== 'string');
console.log(JSON.stringify({ night: shown(night), cls: span && span.className, title: night.title === undefined, ago: shown(ago), bad: shown(bad) }));
`
	// The script shows the zone of the layout's time-zone meta; with no meta, or a name the browser does not know, it
	// shows the browser's own zone, which Node takes from TZ.
	for name, c := range map[string]struct{ tz, meta, local string }{
		"meta UTC":               {"Asia/Kolkata", "UTC", "2026-11-02 02:15"},
		"meta zone":              {"Asia/Kolkata", "America/Puerto_Rico", "2026-11-01 22:15"},
		"no meta, browser zone":  {"Asia/Kolkata", "", "2026-11-02 07:45"},
		"unknown meta, browser":  {"America/Puerto_Rico", "Not/AZone", "2026-11-01 22:15"},
		"no meta, UTC browser":   {"UTC", "", "2026-11-02 02:15"},
		"meta wins over browser": {"UTC", "Asia/Kolkata", "2026-11-02 07:45"},
	} {
		cmd := exec.Command(nodeBin, "-e", driver, file)
		cmd.Env = append(os.Environ(), "TZ="+c.tz, "META_ZONE="+c.meta)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: node: %v\n%s", name, err, out)
		}
		got := strings.TrimSpace(string(out))
		want := `{"night":"` + c.local + ` (2026-11-02 02:15 UTC)","cls":"utc muted","title":true,"ago":"4 min ago","bad":"not a time"}`
		if got != want {
			t.Errorf("%s: localtime.js wrote\n %s\nwant\n %s", name, got, want)
		}
	}
}

// The layout tells the script which zone to use: CHAP_TIMEZONE (UTC by default), through the time-zone meta.
func TestLayoutNamesTheConfiguredTimeZone(t *testing.T) {
	t.Cleanup(func() { _ = localtime.Configure("") })
	sr := newScrRig(t)
	b, _ := sr.signedIn()
	for _, c := range []struct{ zone, want string }{{"", "UTC"}, {"America/Puerto_Rico", "America/Puerto_Rico"}} {
		if err := localtime.Configure(c.zone); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{"/", "/ledger"} {
			if page := get(t, b, p); !strings.Contains(page, `<meta name="time-zone" content="`+c.want+`">`) {
				t.Errorf("zone %q: %s has no time-zone meta naming %s", c.zone, p, c.want)
			}
		}
	}
}
