package approvals

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/localtime"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// cardVersion is the first line of every card. A change of the template text
// is a change of this number: a pending card made by an older template fails
// the re-render check (DISPLAY_MISMATCH) and the request is asked for again.
// v2 (plain wording): the card opens with who wants to do what and the risk,
// then what changes; ids, hashes and the policy version come last.
// v3: the time to decide by is also written in the operator's local time zone (UTC unless CHAP_TIMEZONE is set): "Decide before 2026-11-01 22:15 America/Puerto_Rico time (2026-11-02T02:15:00Z)".
const cardVersion = "3"

// localts formats a time for the card in the operator's local zone (internal/localtime), to the minute: "2026-11-01 22:15".
func localts(t time.Time) string { return localtime.Clock(t) }

// maxCardBytes bounds a card. A request whose card would be larger is refused:
// text that cannot be shown in full cannot be approved.
const maxCardBytes = 512 << 10

// DisplayHash is display_sha256: the SHA-256 of the exact card text, in the
// spec's "sha256:<hex>" form. The console shows the text as is, and the
// browser hashes what it rendered to check this value before it asks for a
// signature.
func DisplayHash(cardText string) string { return spec.SHA256Tagged([]byte(cardText)) }

// ts formats a time the way the spec writes timestamps: UTC, seconds, literal Z.
func ts(t time.Time) string { return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z") }

// ---- escaping: nothing an agent wrote may change how the card looks ----

// printable reports whether r may appear unescaped in free text. A space other
// than U+0020 is not allowed (a no-break space is a look-alike), and neither
// are control, format (bidi override, zero width) and private-use characters.
func printable(r rune) bool {
	return r == ' ' || (unicode.IsGraphic(r) && !unicode.Is(unicode.Zs, r))
}

func escapeRune(b *strings.Builder, r rune, size int, s string, i int) {
	switch {
	case r == utf8.RuneError && size == 1:
		fmt.Fprintf(b, `\x{%02X}`, s[i])
	case r == '\n':
		b.WriteString(`\n`)
	case r == '\r':
		b.WriteString(`\r`)
	case r == '\t':
		b.WriteString(`\t`)
	default:
		fmt.Fprintf(b, `\u{%X}`, r)
	}
}

// text makes one line of free text safe: every character that is not
// printable becomes a visible escape such as \u{202E} or \n.
func text(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if printable(r) && !(r == utf8.RuneError && size == 1) {
			b.WriteRune(r)
		} else {
			escapeRune(&b, r, size, s, i)
		}
		i += size
	}
	return b.String()
}

// ident makes an identifier (an address, a SHA, a branch, a key) safe: printable
// ASCII only. Anything else, including a letter that looks like an ASCII one,
// is shown as an escape, so a look-alike address cannot pass for the real one.
func ident(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r > 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			escapeRune(&b, r, size, s, i)
		}
		i += size
	}
	return b.String()
}

// quoted makes free text safe to put between double quotes in a sentence. Like ident it lets printable ASCII through
// and escapes everything else (bidi controls, combining marks, look-alike letters and quotes such as U+201D). It also
// escapes the backslash and the ASCII quote, so the text can neither close the quotes nor look as if it did: a
// literal \u{202E} typed in the text shows as \\u{202E}, and a trailing backslash cannot hide the closing quote.
func quoted(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '\\' || r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		default:
			escapeRune(&b, r, size, s, i)
		}
		i += size
	}
	return b.String()
}

// block renders multi-line untrusted text: each line is prefixed, so a line of
// the text cannot pass for a line of the card.
func block(s string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = "    | " + text(l)
	}
	return out
}

// jsonText renders any value as one line of canonical JSON, then makes it safe.
func jsonText(v any) string {
	b, err := spec.JCS(v)
	if err != nil {
		return text(fmt.Sprint(v))
	}
	return text(string(b))
}

// ---- templates ----

type fieldKind int

const (
	kIdent  fieldKind = iota // one identifier
	kText                    // one line of free text
	kBlock                   // many lines of free text
	kIdents                  // a list of identifiers
	kJSON                    // anything else, as canonical JSON
)

type field struct {
	key   string
	label string
	kind  fieldKind
}

// cardTemplate is a per-op card layout (ADR-004 section 3). The fields it knows
// are shown first with their labels; every other parameter is shown after them
// under "Other parameters", so no parameter can be left off a card.
type cardTemplate struct {
	target string // label for the target line
	fields []field
}

var cardTemplates = map[string]cardTemplate{
	"deploy": {target: "Deploys to", fields: []field{
		{"sha", "Commit", kIdent},
		{"backup_verified_at", "Last backup checked at", kIdent},
	}},
	"mail.send": {target: "Sent from account", fields: []field{
		{"to", "To", kIdents}, {"cc", "Cc", kIdents}, {"bcc", "Bcc", kIdents},
		{"subject", "Subject", kText},
		{"body", "Message (exactly as it will be sent)", kBlock},
		{"attachments", "Attachments (name and SHA-256)", kJSON},
	}},
	"drive.share": {target: "Google account", fields: []field{
		{"file_name", "File", kText}, {"file_id", "File id", kIdent},
		{"recipients", "Shared with", kIdents}, {"role", "They can", kIdent},
		{"link_visibility", "Link visible to", kIdent},
	}},
	"pr.merge": {target: "Pull request", fields: []field{
		{"base", "Into branch", kIdent}, {"head_sha", "Commit", kIdent}, {"method", "Merge method", kIdent},
	}},
	"pr.push.workflow":     {target: "Repository"},
	"data.apply":           {target: "Where"},
	"secrets.write":        {target: "Secret"},
	"repo.settings":        {target: "Repository"},
	"host.scripts.refresh": {target: "Host"},
	"approvers.enroll": {target: "For", fields: []field{
		{"label", "Device name", kText}, {"origin", "Address", kIdent},
	}},
}

func templateFor(op string) cardTemplate {
	if t, ok := cardTemplates[op]; ok {
		return t
	}
	return cardTemplate{target: "Target"}
}

func (f field) lines(v any) []string {
	switch f.kind {
	case kIdent:
		if s, ok := v.(string); ok {
			return []string{"  " + f.label + ": " + ident(s)}
		}
	case kText:
		if s, ok := v.(string); ok {
			return []string{"  " + f.label + ": " + text(s)}
		}
	case kBlock:
		if s, ok := v.(string); ok {
			return append([]string{"  " + f.label + ":"}, block(s)...)
		}
	case kIdents:
		if list, ok := v.([]any); ok {
			out := []string{"  " + f.label + ":"}
			all := true
			for _, e := range list {
				s, ok := e.(string)
				if !ok {
					all = false
					break
				}
				out = append(out, "    - "+ident(s))
			}
			if all {
				if len(list) == 0 {
					out = append(out, "    (none)")
				}
				return out
			}
		}
	}
	// A value of an unexpected shape is still shown, as JSON.
	return []string{"  " + f.label + ": " + jsonText(v)}
}

// renderCard makes the card text for a. It is a pure function of the stored
// request, checks, evidence, class, policy version and expiry, so the engine
// can re-derive it at decision time and compare it with the text that was shown.
// The text is the whole of what the operator signs: the plain summary the console
// lists and the folded technical details are parts of it, not a second text.
func renderCard(a *Approval) (string, error) {
	req := a.Request
	var out []string
	add := func(s ...string) { out = append(out, s...) }
	section := func(heading string, body ...string) {
		add(heading)
		add(body...)
		add("")
	}

	who, err := whoLine(req.Requester)
	if err != nil {
		return "", err
	}

	add(headVersion)
	if a.Class == ClassCritical {
		add("*** CRITICAL OPERATION ***",
			"One approval authorises this. An alert is raised on request, approval and execution.")
	}
	add("")

	section(headAsk,
		who+" wants to:",
		"  "+wantsTo(req, a.Evidence),
		"Risk: "+strings.ToUpper(Risk(a)),
		"If you approve: it runs once. If you deny: nothing runs, and the same request is refused for a while.",
		"Decide before "+localts(a.RequestExpires)+" "+localtime.Label()+" time ("+ts(a.RequestExpires)+"). After that the request is dropped.")

	tpl := templateFor(req.Op)
	used := map[string]bool{}
	var details []string
	for _, f := range tpl.fields {
		if v, ok := req.Params[f.key]; ok {
			used[f.key] = true
			details = append(details, f.lines(v)...)
		}
	}
	var rest []string
	for _, k := range sortedKeys(req.Params) {
		if !used[k] {
			rest = append(rest, "  "+ident(k)+": "+jsonText(req.Params[k]))
		}
	}
	changes := []string{
		"  Project: " + ident(req.Project),
		"  " + tpl.target + ": " + ident(req.Target.Adapter) + " / " + ident(req.Target.Ref),
	}
	changes = append(changes, details...)
	if len(rest) > 0 {
		changes = append(changes, "Other parameters:")
		changes = append(changes, rest...)
	}
	section(headChanges, changes...)

	if req.Reason != "" {
		section(headReason, block(req.Reason)...)
	}

	var checks []string
	if len(a.Checks) == 0 {
		checks = append(checks, "  (none)")
	}
	for _, c := range a.Checks {
		mark := "[pass]"
		if !c.Passed {
			mark = "[FAIL]"
		}
		line := "  " + mark + " " + ident(c.Name)
		if c.Detail != "" {
			line += ": " + text(c.Detail)
		}
		checks = append(checks, line)
	}
	section(headChecks, checks...)

	for _, e := range a.Evidence {
		section(headEvidence+text(e.Title), append([]string{"  (from the adapter at request time; untrusted text)"}, block(e.Body)...)...)
	}

	section(headTech,
		"Operation: "+ident(req.Op)+" (class "+string(a.Class)+")",
		"Request: "+ident(req.RequestID),
		"Op hash: "+ident(a.OpHash),
		"Policy version: "+text(a.PolicyVersion))
	add(headEnd)

	card := strings.Join(out, "\n") + "\n"
	if len(card) > maxCardBytes {
		return "", fmt.Errorf("approvals: the card is %d bytes; the limit is %d", len(card), maxCardBytes)
	}
	return card, nil
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
