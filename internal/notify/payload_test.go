package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

const goodHash = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"

func goodWake() Wake {
	return Wake{
		Kind:      "deploy",
		Project:   "storefront",
		OpHash:    "sha256:" + goodHash,
		ExpiresAt: time.Date(2026, 10, 24, 14, 32, 10, 0, time.UTC),
		Pending:   3,
	}
}

// pushShape is every push Build may make: a fixed template around the five
// allowlisted fields. Nothing else can match it.
var pushShape = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)* [a-z][a-z0-9-]{1,38}\nop [0-9a-f]{8}, expires [0-2][0-9]:[0-5][0-9] UTC\n[1-9][0-9]* pending$`)

func TestBuildGolden(t *testing.T) {
	p, err := Build(goodWake())
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/push.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.TrimRight(want, "\n")) {
		t.Fatalf("push changed (a change here needs an ADR-004 amendment)\n got: %s\nwant: %s", got, want)
	}
}

func TestBuildAcceptsBareAndPrefixedHash(t *testing.T) {
	a := goodWake()
	b := goodWake()
	b.OpHash = goodHash
	pa, errA := Build(a)
	pb, errB := Build(b)
	if errA != nil || errB != nil || pa != pb {
		t.Fatalf("prefixed and bare hash differ: %v %v %+v %+v", errA, errB, pa, pb)
	}
}

func TestBuildUsesUTC(t *testing.T) {
	w := goodWake()
	w.ExpiresAt = time.Date(2026, 10, 24, 16, 32, 0, 0, time.FixedZone("x", 2*3600))
	p, err := Build(w)
	if err != nil || !strings.Contains(p.Message, "expires 14:32 UTC") {
		t.Fatalf("%v %q", err, p.Message)
	}
}

// TestWakeAndPushFieldAllowlist pins the fields. Adding a field to either type
// (a Params, a Link, an Actions) fails here until ADR-004 is amended.
func TestWakeAndPushFieldAllowlist(t *testing.T) {
	names := func(v any) []string {
		var out []string
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			out = append(out, rt.Field(i).Name)
		}
		return out
	}
	if got, want := names(Wake{}), []string{"Kind", "Project", "OpHash", "ExpiresAt", "Pending"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Wake fields = %v, want %v", got, want)
	}
	if got, want := names(Push{}), []string{"Title", "Message", "Priority"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Push fields = %v, want %v", got, want)
	}
	if got, want := names(wire{}), []string{"Topic", "Push"}; !reflect.DeepEqual(got, want) {
		t.Errorf("wire fields = %v, want %v", got, want)
	}
}

// paramText is what an agent's request could carry: recipients, bodies, SHAs,
// URLs, paths, JSON, shell, markup, secrets and control characters.
var paramText = []string{
	"to=ceo@example.com",
	"ceo@example.com",
	"Quarterly numbers attached, please wire the money",
	"https://evil.example/login",
	"evil.example/login",
	"http://100.64.0.1:55398/approve",
	`{"to":"x@y.z","subject":"hi"}`,
	"abcdef0123456789abcdef0123456789abcdef01", // a 40-hex commit SHA
	"deploy abcdef0123456789abcdef0123456789abcdef01",
	"deploy\nTo: ceo@example.com",
	"deploy\r\nClick: https://evil.example",
	"deploy\x00",
	"deploy ",
	" deploy",
	"deploy\n",
	"Deploy",
	"deploy;rm -rf /",
	"deploy$(id)",
	"<script>alert(1)</script>",
	"[approve](https://evil.example)",
	"ghs_" + strings.Repeat("A", 520),
	"-----BEGIN PRIVATE KEY-----",
	"store front",
	"Store-Front",
	"storefront",
	"storefront\nSECRET",
	"s",
	"é",
	"deploy\u202egnp.exe",
	"",
	strings.Repeat("a", 65),
}

// TestNoParameterTextCanEnterPush is the L1-13 golden test. Parameter text goes
// into every string field of Wake, alone and next to valid values; Build must
// refuse it, and anything it does build must match the fixed template, so no
// byte of the text appears in a push except a lowercase identifier that is
// legal as that field. Kind and Project are set by the caller from the op
// catalog and the project registry, never from request parameters; the pattern
// is the second line of defence, not the first.
func TestNoParameterTextCanEnterPush(t *testing.T) {
	setters := map[string]struct {
		set   func(*Wake, string)
		legal func(string) bool // text that is a valid identifier for the field
	}{
		"Kind":    {func(w *Wake, s string) { w.Kind = s }, func(s string) bool { return len(s) <= maxKind && kindRE.MatchString(s) }},
		"Project": {func(w *Wake, s string) { w.Project = s }, projectRE.MatchString},
		"OpHash":  {func(w *Wake, s string) { w.OpHash = s }, func(s string) bool { _, ok := normalizeHash(s); return ok }},
	}
	for field, f := range setters {
		for _, text := range paramText {
			w := goodWake()
			f.set(&w, text)
			p, err := Build(w)
			if err == nil {
				if !f.legal(text) || !pushShape.MatchString(p.Message) {
					t.Errorf("%s=%q built a push: %q", field, text, p.Message)
				}
				continue
			}
			if !errors.Is(err, ErrInvalidWake) {
				t.Errorf("%s=%q: error %v is not ErrInvalidWake", field, text, err)
			}
			if p != (Push{}) {
				t.Errorf("%s=%q: a push came back with the error: %+v", field, text, p)
			}
		}
	}

	// Text that happens to be a legal kind or project is not parameter text, but
	// whatever Build makes still has to be the template and nothing else.
	for _, kind := range []string{"deploy", "mail.send", "pr.merge", "secrets.write", "drive.share"} {
		w := goodWake()
		w.Kind = kind
		p, err := Build(w)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !pushShape.MatchString(p.Message) {
			t.Errorf("%s: message %q is not the template", kind, p.Message)
		}
	}

	// No push carries a URL, a link scheme, or markup, and the title is fixed.
	p, _ := Build(goodWake())
	for _, bad := range []string{"://", "http", "www.", "@", "<", ">", "[", "]", "`"} {
		if strings.Contains(p.Message, bad) || strings.Contains(p.Title, bad) {
			t.Errorf("push contains %q: %+v", bad, p)
		}
	}
}

func TestBuildRejectsBadNumbers(t *testing.T) {
	for _, n := range []int{-1, 0, maxPending + 1} {
		w := goodWake()
		w.Pending = n
		if _, err := Build(w); !errors.Is(err, ErrInvalidWake) {
			t.Errorf("pending %d: %v", n, err)
		}
	}
	w := goodWake()
	w.ExpiresAt = time.Time{}
	if _, err := Build(w); !errors.Is(err, ErrInvalidWake) {
		t.Errorf("zero expiry: %v", err)
	}
	for _, h := range []string{"", "sha256:", "sha256:" + goodHash[:63], goodHash + "0", strings.ToUpper(goodHash), "sha1:" + goodHash, "sha256:" + goodHash + "\n"} {
		w := goodWake()
		w.OpHash = h
		if _, err := Build(w); !errors.Is(err, ErrInvalidWake) {
			t.Errorf("hash %q: %v", h, err)
		}
	}
}

// FuzzBuild: whatever the input, a built push is exactly the template with the
// fixed title and priority. `go test` runs the seeds; `go test -fuzz` explores.
func FuzzBuild(f *testing.F) {
	for _, s := range paramText {
		f.Add(s, s, s, 1)
	}
	f.Add("deploy", "storefront", "sha256:"+goodHash, 3)
	f.Fuzz(func(t *testing.T, kind, project, hash string, pending int) {
		w := Wake{Kind: kind, Project: project, OpHash: hash, ExpiresAt: time.Date(2026, 10, 24, 14, 32, 0, 0, time.UTC), Pending: pending}
		p, err := Build(w)
		if err != nil {
			if p != (Push{}) {
				t.Fatalf("push with error: %+v", p)
			}
			return
		}
		if !pushShape.MatchString(p.Message) || p.Title != pushTitle || p.Priority != pushPriority {
			t.Fatalf("not the template: %+v", p)
		}
	})
}
