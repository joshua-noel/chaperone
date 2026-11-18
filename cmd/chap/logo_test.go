package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var marker = filepath.Join(testConfigDir, "chaperone", "first-connect")

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("%s differs\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// The banner is plain ASCII (renders in Windows Terminal and conhost, no
// escape codes), fits 80 columns and is 6 to 7 lines of letters.
func TestLogoArt(t *testing.T) {
	for _, connected := range []string{"", "http://127.0.0.1:55398"} {
		s := logo(connected)
		letters := 0
		for _, line := range strings.Split(s, "\n") {
			if len(line) > 79 {
				t.Errorf("line of %d columns: %q", len(line), line)
			}
			if strings.Contains(line, "##") {
				letters++
			}
		}
		if letters < 6 || letters > 7 {
			t.Errorf("%d rows of letters, want 6 or 7", letters)
		}
		for i := range len(s) {
			if c := s[i]; c != '\n' && (c < 0x20 || c > 0x7e) {
				t.Fatalf("byte 0x%02x at %d is not printable ASCII", c, i)
			}
		}
		if !strings.Contains(s, tagline) || !strings.Contains(s, "chap ") {
			t.Errorf("no tagline or version:\n%s", s)
		}
		if strings.Contains(s, "connected to") != (connected != "") {
			t.Errorf("connected line wrong for %q:\n%s", connected, s)
		}
	}
	checkGolden(t, "logo-connected.golden", logo("http://127.0.0.1:55398"))
}

func TestLogoCommand(t *testing.T) {
	ta := newTestApp(t, env{})
	if code := ta.run([]string{"logo"}); code != 0 || ta.out.String() != logo("") || ta.errb.Len() != 0 {
		t.Errorf("exit %d, stdout %q, stderr %q", code, ta.out, ta.errb)
	}
	ta = newTestApp(t, env{})
	if code := ta.run([]string{"logo", "now"}); code != exitUsage {
		t.Errorf("exit %d, want usage", code)
	}
}

// The first successful reply shows the banner on stderr and leaves the
// marker; the second run shows nothing; stdout is the same either way.
func TestWelcomeOnce(t *testing.T) {
	chapd := newFakeChapd(t, *ok200("op-health"))
	first := newTestApp(t, env{chapd: chapd, token: "orch", tty: true})
	if code := first.run([]string{"health"}); code != 0 {
		t.Fatalf("exit %d: %s", code, first.errb)
	}
	if got, want := first.errb.String(), logo(chapd.URL); got != want {
		t.Errorf("stderr\n%q\nwant the banner\n%q", got, want)
	}
	if _, ok := first.files[marker]; !ok {
		t.Fatalf("no marker at %s; files: %v", marker, first.files)
	}

	second := newTestApp(t, env{chapd: chapd, token: "orch", tty: true})
	second.files = first.files
	if code := second.run([]string{"health"}); code != 0 {
		t.Fatalf("exit %d: %s", code, second.errb)
	}
	if second.errb.Len() != 0 {
		t.Errorf("the banner came back: %q", second.errb)
	}
	if second.out.String() != first.out.String() || strings.Contains(first.out.String(), tagline) {
		t.Errorf("stdout differs or holds the banner:\n%s\n%s", first.out, second.out)
	}
}

// Agents and scripts never get it, and a run that does not show it does not
// use up the marker.
func TestWelcomeNever(t *testing.T) {
	health := []string{"health"}
	for name, tc := range map[string]struct {
		args  []string
		env   env
		ans   answer
		check func(*testApp)
	}{
		"json":        {args: []string{"health", "--json"}, env: env{token: "orch", tty: true}, ans: *ok200("op-health")},
		"not a tty":   {args: health, env: env{token: "orch"}, ans: *ok200("op-health")},
		"run token":   {args: health, env: env{token: "run", tty: true}, ans: *ok200("op-health")},
		"CI":          {args: health, env: env{token: "orch", tty: true, extra: map[string]string{"CI": "true"}}, ans: *ok200("op-health")},
		"denied":      {args: health, env: env{token: "orch", tty: true}, ans: *withStatus(403, "api:denial-run-op-disabled")},
		"unavailable": {args: health, env: env{token: "orch", tty: true}, ans: *withStatus(503, "err-unavailable")},
		"auth error":  {args: health, env: env{token: "orch", tty: true}, ans: *withStatus(401, "err-auth")},
	} {
		t.Run(name, func(t *testing.T) {
			e := tc.env
			e.chapd = newFakeChapd(t, tc.ans)
			ta := newTestApp(t, e)
			ta.run(tc.args)
			if all := ta.out.String() + ta.errb.String(); strings.Contains(all, tagline) || strings.Contains(all, "##") {
				t.Errorf("the banner was printed:\n%s", all)
			}
			if _, ok := ta.files[marker]; ok {
				t.Error("the marker was written without a banner")
			}
		})
	}

	t.Run("chapd unreachable", func(t *testing.T) {
		chapd := newFakeChapd(t, *ok200("op-health"))
		chapd.Close()
		ta := newTestApp(t, env{chapd: chapd, token: "orch", tty: true})
		if code := ta.run(health); code != exitUnavailable {
			t.Errorf("exit %d", code)
		}
		if strings.Contains(ta.errb.String(), tagline) {
			t.Error("the banner was printed")
		}
		if _, ok := ta.files[marker]; ok {
			t.Error("the marker was written")
		}
	})

	// A marker that cannot be created (here: it exists) means no banner, not
	// a banner on every run.
	t.Run("marker exists", func(t *testing.T) {
		ta := newTestApp(t, env{chapd: newFakeChapd(t, *ok200("op-health")), token: "orch", tty: true})
		ta.files[marker] = []byte("x")
		ta.run(health)
		if ta.errb.Len() != 0 {
			t.Errorf("stderr %q", ta.errb)
		}
	})
}
