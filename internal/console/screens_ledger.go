package console

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// Ledger: search by run, request, op, event name and time; the integrity check
// button; the last anchor. Events are shown as the ledger stores them, which
// is already redacted (ADR-003 item 6, ADR-006).

type ledgerForm struct {
	Run, Request, Op, Event, From, To string
}

type ledgerRow struct {
	Seq                                int64
	When, Event, Run, Project, Op, Req string
	Detail, Text                       string
	Tone                               string // success, warning, danger, info or neutral; the words stay in Event and Detail
}

type anchorView struct {
	Seq             int64
	When, Kind, Ref string
	HeadSeq         int64
	HeadHash        string
}

type ledgerView struct {
	shell
	Form     ledgerForm
	Searched bool
	Rows     []ledgerRow
	Limit    int
	Note     string
	Error    string
	Chain    string
	HeadSeq  int64
	HeadHash string
	Anchor   *anchorView
}

const (
	ledgerRowLimit = 100
	formTimeLayout = "2006-01-02T15:04" // <input type="datetime-local">, read as UTC
)

// detailKeys are the attributes that say what an event was about, in the
// order they are shown.
var detailKeys = []struct{ key, label string }{
	{"factory.outcome", "outcome"}, {"factory.cause_code", "cause"}, {"factory.decision", "decision"},
	{"factory.revoke.reason", "revoke"}, {"factory.surface", "surface"}, {"factory.anchor.kind", "anchor"},
}

func detailOf(e spec.Event) string {
	var parts []string
	for _, k := range detailKeys {
		if v := attrString(e, k.key); v != "" {
			parts = append(parts, k.label+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

// toneOf picks the state colour of an event. The colour only adds to the
// words in the row: the event name and the outcome or decision are always shown.
func toneOf(e spec.Event) string {
	switch outcome, decision := attrString(e, "factory.outcome"), attrString(e, "factory.decision"); {
	case e.EventName == "denial", decision == "denied", outcome == "failed", outcome == "error":
		return "danger"
	case outcome == "succeeded", decision == "approved":
		return "success"
	case outcome == "killed", e.EventName == "token.revoke":
		return "warning"
	case e.EventName == "op.request":
		return "info"
	}
	return "neutral"
}

func rowOf(e spec.Event) ledgerRow {
	return ledgerRow{
		Seq: e.Seq, When: stamp(eventTime(e)), Event: e.EventName, Run: e.RunID, Project: e.Project,
		Op: attrString(e, "factory.op"), Req: attrString(e, "factory.request_id"), Detail: detailOf(e), Text: clip(bodyOf(e), 200),
		Tone: toneOf(e),
	}
}

func anchorOf(e spec.Event) *anchorView {
	a := &anchorView{Seq: e.Seq, When: stamp(eventTime(e)), Kind: attrString(e, "factory.anchor.kind"),
		Ref: attrString(e, "factory.anchor.ref"), HeadHash: attrString(e, "factory.anchor.head_hash")}
	if f, ok := e.Attributes["factory.anchor.head_seq"].(float64); ok {
		a.HeadSeq = int64(f)
	}
	return a
}

// parseLedgerForm reads the search form from the query string.
func parseLedgerForm(r *http.Request) (ledgerForm, ledger.QueryParams, string) {
	q := r.URL.Query()
	get := func(k string) string { return strings.TrimSpace(clip(q.Get(k), 128)) }
	f := ledgerForm{Run: get("run"), Request: get("request"), Op: get("op"), Event: get("event"), From: get("from"), To: get("to")}
	if f.From == "frame" {
		f.From = "" // the console's own mark on a window opened from a frame (Console.restricted), not a date
	}
	p := ledger.QueryParams{RunID: f.Run, RequestID: f.Request, EventName: f.Event}
	for _, t := range []struct {
		name string
		in   string
		out  *time.Time
	}{{"From", f.From, &p.From}, {"To", f.To, &p.To}} {
		if t.in == "" {
			continue
		}
		v, err := time.Parse(formTimeLayout, t.in)
		if err != nil {
			return f, p, t.name + " is not a date and time (use the picker; times are UTC)."
		}
		*t.out = v
	}
	return f, p, ""
}

func (f ledgerForm) empty() bool { return f == ledgerForm{} }

// lastAnchor returns the newest ledger.anchor event, nil when there is none.
func (s *screens) lastAnchor(ctx context.Context) (*anchorView, error) {
	evs, _, err := s.newestEvents(ctx, ledger.QueryParams{EventName: "ledger.anchor"}, 1, nil)
	if err != nil || len(evs) == 0 {
		return nil, err
	}
	return anchorOf(evs[0]), nil
}

// ledgerPage is GET /ledger. With no search term it shows the newest events.
func (s *screens) ledgerPage(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	form, params, bad := parseLedgerForm(r)
	v := ledgerView{shell: s.shell(st, "Ledger"), Form: form, Searched: !form.empty(), Limit: ledgerRowLimit,
		Chain: s.cfg.Ledger.Chain(), Error: bad}
	seq, hash, err := s.cfg.Ledger.Head(ctx)
	if err != nil {
		s.fail(w, "ledger head", err)
		return
	}
	v.HeadSeq, v.HeadHash = seq, hash
	if v.Anchor, err = s.lastAnchor(ctx); err != nil {
		s.fail(w, "last anchor", err)
		return
	}
	status := http.StatusOK
	if bad != "" {
		status = http.StatusBadRequest
	} else {
		var keep func(spec.Event) bool
		if form.Op != "" {
			keep = func(e spec.Event) bool { return attrString(e, "factory.op") == form.Op }
		}
		evs, truncated, err := s.newestEvents(ctx, params, ledgerRowLimit, keep)
		if err != nil {
			s.fail(w, "ledger search", err)
			return
		}
		for _, e := range evs {
			v.Rows = append(v.Rows, rowOf(e))
		}
		if truncated {
			v.Note = "Only the newest events were searched. Narrow the search with a run, a request or a time range to reach older ones."
		}
	}
	s.page(w, status, "ledger", v)
}

type verifyView struct {
	OK              bool
	Chain           string
	Events          int64
	HeadSeq         int64
	HeadHash        string
	Export          bool
	ExportedThrough int64
	Unexported      int64
	Problems        []string
}

// ledgerVerify is POST /ledger/verify: the integrity check button. With
// against_export=1 it also compares SQLite with the JSONL export.
func (s *screens) ledgerVerify(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.user(w, r); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		s.say(w, http.StatusBadRequest, "Malformed request", "The form could not be read.")
		return
	}
	export := r.PostForm.Get("against_export") == "1"
	rep, err := s.cfg.Ledger.Verify(r.Context(), export)
	if err != nil {
		s.c.log.Error("ledger verify", "err", err)
		s.say(w, http.StatusInternalServerError, "The check could not run",
			"The ledger or its export could not be read. Nothing was verified; see the log.")
		return
	}
	v := verifyView{OK: rep.OK(), Chain: s.cfg.Ledger.Chain(), Export: export, Problems: []string{}}
	for _, c := range rep.Chains {
		if c.Chain == v.Chain {
			v.Events, v.HeadSeq, v.HeadHash = c.Events, c.HeadSeq, c.HeadHash
			v.ExportedThrough, v.Unexported = c.ExportedThrough, c.Unexported
		}
	}
	for _, p := range rep.Problems() {
		v.Problems = append(v.Problems, p.String())
	}
	status := http.StatusOK
	if !v.OK {
		s.c.log.Error("ledger verify found problems", "problems", len(v.Problems))
		status = http.StatusConflict
	}
	s.fragment(w, status, "verify-result", v)
}
