package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/joshua-noel/chaperone/internal/denialtext"
	"github.com/joshua-noel/chaperone/internal/localtime"
)

// Human output is plain lines: no color, no cursor control, stable words, so
// an agent can read it and a golden test can pin it. Every string that came
// from chapd passes through clean().

type denial struct {
	Type      string `json:"type"`
	DenialID  string `json:"denial_id"`
	RunID     string `json:"run_id"`
	Project   string `json:"project"`
	Profile   string `json:"profile"`
	Surface   string `json:"surface"`
	CauseCode string `json:"cause_code"`
	Why       string `json:"why"`
	Action    struct {
		Verb   string `json:"verb"`
		Target string `json:"target"`
	} `json:"action"`
	Request struct {
		Possible bool   `json:"possible"`
		Command  string `json:"command"`
	} `json:"request"`
	Thrash struct {
		Count         int  `json:"count"`
		WindowSeconds int  `json:"window_seconds"`
		Flagged       bool `json:"flagged"`
	} `json:"thrash"`
	PolicyVersion  string `json:"policy_version"`
	OrchestratorID string `json:"orchestrator_id"`
}

// renderDenial is the spec's three-line form (factory-spec src/render.mjs)
// with the cause code on a line of its own, so an agent can quote or match it:
//
//	DENIED <op> on <target> (profile <p>, run <r>)
//	cause: <CAUSE_CODE>
//	why: <why>
//	next: <what to do>   (or) request: <the chap request line | not possible, ...>
//
// An orchestrator is named instead of a profile and run. The header names the op that was refused and the thing it
// was aimed at; before, it printed the target after the word "op", so a denied intake.states read "DENIED op board".
// "not possible" is printed only when nothing the caller can do changes the answer; a cause with a next step (a
// stale branch, a flood of requests, an expired token) prints that step instead (internal/denialtext).
func renderDenial(d *denial) string {
	who := fmt.Sprintf("profile %s, run %s", clean(d.Profile), clean(d.RunID))
	if d.RunID == "" {
		who = "orchestrator " + clean(d.OrchestratorID)
	}
	var b strings.Builder
	if d.Surface == "op" && d.Action.Verb != "" && d.Action.Verb != "request" && d.Action.Verb != d.Action.Target {
		fmt.Fprintf(&b, "DENIED %s on %s (%s)\n", clean(d.Action.Verb), clean(d.Action.Target), who)
	} else {
		fmt.Fprintf(&b, "DENIED %s %s (%s)\n", clean(d.Surface), clean(d.Action.Target), who)
	}
	if d.CauseCode != "" {
		fmt.Fprintf(&b, "cause: %s\n", clean(d.CauseCode))
	}
	fmt.Fprintf(&b, "why: %s\n", clean(d.Why))
	next := denialtext.NextStep(d.CauseCode, d.Why, d.OrchestratorID)
	switch {
	case d.Request.Possible:
		fmt.Fprintf(&b, "request: %s\n", clean(d.Request.Command))
	case next != "":
		fmt.Fprintf(&b, "next: %s\n", clean(next))
	default:
		b.WriteString("request: not possible, policy does not allow asking\n")
	}
	if d.Thrash.Flagged {
		fmt.Fprintf(&b, "note: repeated attempt %d in %ds, flagged as thrash\n", d.Thrash.Count, d.Thrash.WindowSeconds)
	}
	return b.String()
}

type check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

func renderChecks(b *strings.Builder, checks []check) {
	if len(checks) == 0 {
		return
	}
	b.WriteString("checks:\n")
	for _, c := range checks {
		mark := "ok  "
		if !c.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(b, "  %s %s", mark, clean(c.Name))
		if c.Detail != "" {
			fmt.Fprintf(b, ": %s", clean(c.Detail))
		}
		b.WriteByte('\n')
	}
}

type approvalSummary struct {
	ID            string `json:"id"`
	RequestID     string `json:"request_id"`
	Op            string `json:"op"`
	OpHash        string `json:"op_hash"`
	State         string `json:"state"`
	Class         string `json:"class"`
	Critical      bool   `json:"critical"`
	PolicyVersion string `json:"policy_version"`
	CreatedAt     string `json:"created_at"`
	DecidedAt     string `json:"decided_at"`
	ExpiresAt     string `json:"expires_at"`
}

type op struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Op     string `json:"op"`
	Target struct {
		Ref string `json:"ref"`
	} `json:"target"`
	Class         string           `json:"class"`
	PolicyVersion string           `json:"policy_version"`
	Approval      *approvalSummary `json:"approval"`
	ExecutionID   string           `json:"execution_id"`
	ExternalRef   string           `json:"external_ref"`
	Result        json.RawMessage  `json:"result"`
	Checks        []check          `json:"checks"`
	Denial        *denial          `json:"denial"`
}

// opState maps an Op's state to the exit code and, for a state that is not
// final, what to do next.
func opCode(state string) int {
	switch state {
	case "succeeded":
		return exitOK
	case "denied":
		return exitDenied
	case "failed", "refused", "expired", "cancelled":
		return exitNotOK
	default: // requested, pending_approval, allowed, executing, unconfirmed
		return exitPending
	}
}

func renderOp(o *op) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s: %s\n", clean(o.Op), clean(o.Target.Ref), clean(o.State))
	fmt.Fprintf(&b, "id: %s", clean(o.ID))
	if o.Class != "" {
		fmt.Fprintf(&b, "  class: %s", clean(o.Class))
	}
	if o.PolicyVersion != "" {
		fmt.Fprintf(&b, "  policy: %s", clean(o.PolicyVersion))
	}
	b.WriteByte('\n')
	if o.ExecutionID != "" {
		fmt.Fprintf(&b, "execution: %s\n", clean(o.ExecutionID))
	}
	if o.ExternalRef != "" {
		fmt.Fprintf(&b, "external_ref: %s\n", clean(o.ExternalRef))
	}
	if !renderIntake(&b, o.Op, o.Result) && !renderPRRead(&b, o.Op, o.Result) {
		renderResult(&b, o.Result)
	}
	renderChecks(&b, o.Checks)
	if a := o.Approval; a != nil {
		fmt.Fprintf(&b, "approval: %s %s, expires %s\n", clean(a.ID), clean(a.State), clean(localtime.FromRFC3339(a.ExpiresAt)))
	}
	if o.Denial != nil {
		b.WriteString(renderDenial(o.Denial))
	} else if o.State == "refused" || o.State == "denied" {
		// Every refusal chapd makes carries a denial. An op without one was
		// refused by a chapd that did not record the reason: say so, never
		// leave the passed checks looking like the whole answer.
		fmt.Fprintf(&b, "why: chapd recorded no reason for this refusal; the cause code is in the ledger, op.result of %s\n", clean(o.ID))
	}
	switch o.State {
	case "pending_approval":
		b.WriteString("waiting for the operator to approve in the console; nothing has run\n")
	case "allowed", "executing", "requested":
		b.WriteString("not finished\n")
	case "unconfirmed":
		b.WriteString("sent, no receipt yet; chapd will settle it, do not retry\n")
	}
	switch o.State {
	case "pending_approval", "allowed", "executing", "requested", "unconfirmed":
		fmt.Fprintf(&b, "follow: chap op show %s --wait 30\n", clean(o.ID))
	}
	return b.String()
}

// renderResult prints an op's result object: scalars as key: value, a
// `lines` list of strings (logs) as raw lines, anything else as compact JSON.
func renderResult(b *strings.Builder, raw json.RawMessage) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b.WriteString("result:\n")
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			fmt.Fprintf(b, "  %s: %s\n", clean(k), clean(v))
		case json.Number:
			fmt.Fprintf(b, "  %s: %s\n", clean(k), v)
		case bool:
			fmt.Fprintf(b, "  %s: %t\n", clean(k), v)
		case []any:
			if lines, ok := stringList(v); ok && k == "lines" {
				fmt.Fprintf(b, "  %s:\n", clean(k))
				for _, l := range lines {
					fmt.Fprintf(b, "    %s\n", clean(l))
				}
				continue
			}
			j, _ := json.Marshal(v)
			fmt.Fprintf(b, "  %s: %s\n", clean(k), clean(string(j)))
		default:
			j, _ := json.Marshal(v)
			fmt.Fprintf(b, "  %s: %s\n", clean(k), clean(string(j)))
		}
	}
}

func stringList(v []any) ([]string, bool) {
	out := make([]string, 0, len(v))
	for _, x := range v {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

type verdict struct {
	WouldAllow    bool    `json:"would_allow"`
	Outcome       string  `json:"outcome"`
	OpHash        string  `json:"op_hash"`
	Class         string  `json:"class"`
	PolicyVersion string  `json:"policy_version"`
	Checks        []check `json:"checks"`
	Denial        *denial `json:"denial"`
}

func renderVerdict(opName, ref string, v *verdict) string {
	var b strings.Builder
	switch v.Outcome {
	case "allow":
		fmt.Fprintf(&b, "dry run %s %s: would be released now\n", clean(opName), clean(ref))
	case "approval":
		fmt.Fprintf(&b, "dry run %s %s: would need an approval\n", clean(opName), clean(ref))
	default:
		fmt.Fprintf(&b, "dry run %s %s: would be refused\n", clean(opName), clean(ref))
	}
	fmt.Fprintf(&b, "class: %s  policy: %s\nop_hash: %s\n", clean(v.Class), clean(v.PolicyVersion), clean(v.OpHash))
	renderChecks(&b, v.Checks)
	if v.Denial != nil {
		b.WriteString(renderDenial(v.Denial))
	}
	return b.String()
}

func verdictCode(v *verdict) int {
	switch v.Outcome {
	case "allow":
		return exitOK
	case "approval":
		return exitPending
	default:
		return exitDenied
	}
}

// table renders rows with aligned columns.
func table(header []string, rows [][]string) string {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(header, "\t"))
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = clean(c)
		}
		fmt.Fprintln(w, strings.Join(cells, "\t"))
	}
	w.Flush()
	return b.String()
}
