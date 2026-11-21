package approvals

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// Section headings of a v2 card. Each stands alone on a line. Untrusted text
// cannot produce one: free text is escaped onto one labelled line, or every one
// of its lines is prefixed "    | ", so [ParseCard] can split a card without
// trusting what is in it. Splitting only decides how the console lays the text
// out; the signed text is the whole card, byte for byte.
const (
	headVersion  = "CHAPERONE APPROVAL CARD v" + cardVersion
	headAsk      = "WHAT YOU ARE ASKED TO APPROVE"
	headChanges  = "WHAT CHANGES"
	headReason   = "WHY THE REQUESTER ASKS (written by the requester; untrusted)"
	headChecks   = "CHECKS"
	headEvidence = "EVIDENCE: "
	headTech     = "TECHNICAL DETAILS"
	headEnd      = "END OF CARD"
)

// Keys of the sections of a parsed card.
const (
	SectionHead     = "head"
	SectionAsk      = "ask"
	SectionChanges  = "changes"
	SectionReason   = "reason"
	SectionChecks   = "checks"
	SectionEvidence = "evidence"
	SectionTech     = "tech"
	SectionEnd      = "end"
)

// CardSection is one part of a card. Heading is the heading line with its
// newline, Body the lines after it; Heading+Body of every section, in order,
// is the card text exactly.
type CardSection struct {
	Key, Heading, Body string
}

// Text is the section's part of the card text.
func (s CardSection) Text() string { return s.Heading + s.Body }

// sectionRank orders the sections of a card.
var sectionRank = map[string]int{SectionHead: 0, SectionAsk: 1, SectionChanges: 2, SectionReason: 3, SectionChecks: 4, SectionEvidence: 5, SectionTech: 6, SectionEnd: 7}

func sectionKey(line string) (string, bool) {
	switch line {
	case headAsk:
		return SectionAsk, true
	case headChanges:
		return SectionChanges, true
	case headReason:
		return SectionReason, true
	case headChecks:
		return SectionChecks, true
	case headTech:
		return SectionTech, true
	case headEnd:
		return SectionEnd, true
	}
	if strings.HasPrefix(line, headEvidence) {
		return SectionEvidence, true
	}
	return "", false
}

// ParseCard splits a v2 card into its sections. It reports false for a card it
// does not recognise (an older version, or a section out of order); the console
// then shows the whole text unsplit. The parts always add up to the text.
func ParseCard(card string) ([]CardSection, bool) {
	lines := strings.SplitAfter(card, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 || lines[0] != headVersion+"\n" || !strings.HasSuffix(card, "\n") {
		return nil, false
	}
	secs := []CardSection{{Key: SectionHead, Heading: lines[0]}}
	for _, l := range lines[1:] {
		if key, ok := sectionKey(strings.TrimSuffix(l, "\n")); ok {
			secs = append(secs, CardSection{Key: key, Heading: l})
			continue
		}
		secs[len(secs)-1].Body += l
	}
	last := -1
	seen := map[string]bool{}
	for _, s := range secs {
		r := sectionRank[s.Key]
		if r < last || (seen[s.Key] && s.Key != SectionEvidence) {
			return nil, false
		}
		last, seen[s.Key] = r, true
	}
	for _, k := range []string{SectionAsk, SectionChanges, SectionChecks, SectionTech, SectionEnd} {
		if !seen[k] {
			return nil, false
		}
	}
	if secs[len(secs)-1].Key != SectionEnd {
		return nil, false
	}
	var b strings.Builder
	for _, s := range secs {
		b.WriteString(s.Text())
	}
	if b.String() != card {
		return nil, false
	}
	return secs, true
}

// CardAsk reads the two lines at the top of a card's first section: who, and
// what they want to do. The console's one-line list shows these, so the line the
// operator picks from is part of the text he signs.
func CardAsk(secs []CardSection) (who, what string, ok bool) {
	for _, s := range secs {
		if s.Key != SectionAsk {
			continue
		}
		body := strings.Split(s.Body, "\n")
		if len(body) < 2 || !strings.HasSuffix(body[0], " wants to:") || !strings.HasPrefix(body[1], "  ") {
			return "", "", false
		}
		return strings.TrimSuffix(body[0], " wants to:"), strings.TrimPrefix(body[1], "  "), true
	}
	return "", "", false
}

// ---- plain words ----

// whoLine says who asks, in words: an agent run (with its profile) or the orchestrator.
func whoLine(r spec.Requester) (string, error) {
	switch r.Kind {
	case "run":
		who := "Agent " + ident(r.RunID)
		if r.Profile != "" {
			who += " (" + ident(r.Profile) + ")"
		}
		return who, nil
	case "orchestrator":
		if id, ok := spec.KeyIDOf(r); ok {
			return "Key " + ident(id), nil
		}
		if r.ID == "main" {
			return "The orchestrator", nil
		}
		if r.ID == "operator" {
			return "You, at the console", nil
		}
		return "Orchestrator " + ident(r.ID), nil
	}
	return "", fmt.Errorf("approvals: requester kind %q", r.Kind)
}

var tierRE = regexp.MustCompile(`^tier (low|medium|high)\b`)

// Risk is the card's risk word: low, medium, high or critical. It follows the
// op's class; for a merge it is the pull request's own tier, which the risk_tier
// check carries. The console colours its list by this word, and the card shows it.
func Risk(a *Approval) string {
	if a.Op == "pr.merge" {
		for _, c := range a.Checks {
			if c.Name == "risk_tier" {
				if m := tierRE.FindStringSubmatch(c.Detail); m != nil {
					return m[1]
				}
			}
		}
	}
	switch a.Class {
	case ClassCritical:
		return "critical"
	case ClassHigh:
		return "high"
	case ClassGated:
		return "medium"
	}
	return "low"
}

func strParam(req spec.Request, key string) string {
	s, _ := req.Params[key].(string)
	return s
}

// strList lists a parameter that should be a list of strings. An element that is not a string is kept, shown as
// JSON, so nothing in the list is dropped from the one-line summary.
func strList(req spec.Request, key string) []string {
	list, _ := req.Params[key].([]any)
	var out []string
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, jsonText(e))
		}
	}
	return out
}

// clip shortens a line of free text for the one-line summary; the card shows it in full below.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "..."
}

// people lists up to three addresses, then "and N more".
func people(list []string) string {
	if len(list) == 0 {
		return "no one named"
	}
	var out []string
	for i, s := range list {
		if i == 3 {
			out = append(out, fmt.Sprintf("and %d more", len(list)-3))
			break
		}
		out = append(out, ident(s))
	}
	return strings.Join(out, ", ")
}

// EvidencePR is the title of the evidence block that names a pull request, and EvidenceTitlePrefix starts its first
// line: "Title: <title>". They are the words of ops.PRSubjectEvidence and ops.PRTitlePrefix; the two packages do not
// import each other, so cmd/chapd's TestPRSubjectEvidenceWordsAgree pins them together. The card's headline quotes the
// title so the operator sees which change he is approving.
const (
	EvidencePR          = "pull request"
	EvidenceTitlePrefix = "Title: "
)

// prTitle reads the pull request's title from the evidence, or "" when the adapter gave none (or a first line that
// does not start with the prefix: then no title is quoted, never another line of the block).
func prTitle(ev []Evidence) string {
	for _, e := range ev {
		if e.Title == EvidencePR {
			line, _, _ := strings.Cut(e.Body, "\n")
			t, ok := strings.CutPrefix(line, EvidenceTitlePrefix)
			if !ok {
				return ""
			}
			return t
		}
	}
	return ""
}

// wantsTo says what the request does, in a plain sentence fragment. Every value
// in it is escaped as in the rest of the card; the full values are under
// WHAT CHANGES. ev is the card's evidence: a merge quotes the pull request's title from it.
func wantsTo(req spec.Request, ev []Evidence) string {
	ref := ident(req.Target.Ref)
	switch req.Op {
	case "pr.merge":
		n := ref
		if i := strings.LastIndex(req.Target.Ref, "#"); i >= 0 {
			n = "#" + ident(req.Target.Ref[i+1:])
		}
		s := "merge pull request " + n
		if t := prTitle(ev); t != "" {
			// The title is the author's text and is never clipped here (ops keeps it whole, 72 characters at most): the
			// headline must be the text that is merged. quoted keeps it from ending the quotes or from passing for
			// another sentence.
			s += ` "` + quoted(t) + `"`
		}
		if base := strParam(req, "base"); base != "" {
			s += " into " + ident(base)
		}
		return s
	case "deploy":
		s := "deploy"
		if sha := strParam(req, "sha"); sha != "" {
			s += " commit " + ident(clip(sha, 12))
		}
		return s + " to " + ref
	case "mail.send":
		return mailSentence(req)
	case "drive.share":
		s := "share"
		if f := strParam(req, "file_name"); f != "" {
			s += ` "` + text(clip(f, 80)) + `"`
		} else {
			s += " a Drive item"
		}
		s += " with " + people(strList(req, "recipients"))
		if role := strParam(req, "role"); role != "" {
			s += " (they can " + ident(role) + ")"
		}
		if vis := strParam(req, "link_visibility"); vis != "" {
			s += "; link visible to " + ident(vis)
		} else {
			s += "; link visibility not stated"
		}
		return s
	case "pr.push.workflow":
		return "push a change to a workflow file in " + ref
	case "data.apply":
		return "change live data on " + ref
	case "secrets.write":
		return "store a secret named " + ref
	case "repo.settings":
		return "change the settings of " + ref
	case "host.scripts.refresh":
		return "replace the host scripts on " + ref
	case "keys.issue":
		if strParam(req, "enrolment") != "" {
			return "enrol the agent " + ident(strParam(req, "holder")) + " for " + ident(strParam(req, "owner")) + " in project " + ident(req.Project) +
				": a key that can only ask for more access, and can do nothing else"
		}
		s := "give " + ident(strParam(req, "holder_kind")) + " " + ident(strParam(req, "holder")) + " a key that can use " + joinIdents(strList(req, "ops"))
		if u := strList(req, "units"); len(u) > 0 {
			s += " on " + joinIdents(u)
		} else {
			s += " in project " + ident(req.Project)
		}
		return s + " (a key can never approve anything or issue keys)"
	case "keys.extend":
		return "make the key " + ident(strParam(req, "key")) + " of agent " + ident(strParam(req, "holder")) + " last " + jsonText(req.Params["extend_hours"]) +
			" hours longer (it gets no more access)"
	case "approvers.enroll":
		if l := strParam(req, "label"); l != "" {
			return `add a new approver device named "` + text(clip(l, 60)) + `"`
		}
		return "add a new approver device"
	}
	return "run the operation " + ident(req.Op) + " on " + ref
}

// mailSentence names every class of recipient and the attachments, so a Cc, a Bcc or a file cannot hide below the
// headline. Bcc recipients are called hidden: the other recipients do not see them.
func mailSentence(req spec.Request) string {
	to, cc, bcc := strList(req, "to"), strList(req, "cc"), strList(req, "bcc")
	n := func(k int, one, many string) string {
		if k == 1 {
			return fmt.Sprintf("%d %s", k, one)
		}
		return fmt.Sprintf("%d %s", k, many)
	}
	var s string
	if len(to)+len(cc) == 0 {
		s = "send an email to 0 visible recipients"
	} else {
		s = "send an email to " + people(to)
		if len(to) == 0 {
			s = "send an email to 0 'To' recipients"
		}
		if len(cc) > 0 {
			s += ", Cc " + people(cc)
		}
	}
	if len(bcc) > 0 {
		s += " and " + n(len(bcc), "hidden (bcc) recipient", "hidden (bcc) recipients") + " (" + people(bcc) + ")"
	}
	if atts, _ := req.Params["attachments"].([]any); len(atts) > 0 {
		s += ", " + n(len(atts), "attachment", "attachments")
	}
	if sub := strParam(req, "subject"); sub != "" {
		s += ` with the subject "` + text(clip(sub, 80)) + `"`
	}
	return s
}

// joinIdents renders a list of identifiers for a headline.
func joinIdents(list []string) string {
	if len(list) == 0 {
		return "nothing"
	}
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = ident(s)
	}
	return strings.Join(out, ", ")
}
