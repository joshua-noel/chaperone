package conformance

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/joshua-noel/chaperone/internal/ops"
)

// problem formats one finding. who names the sample.
func problem(who, format string, a ...any) string {
	return fmt.Sprintf("%s: %s", who, fmt.Sprintf(format, a...))
}

func (h *harness) samples() []Sample {
	return append(append([]Sample(nil), h.spec.Valid...), h.spec.Invalid...)
}

func (h *harness) isValid(s Sample) bool {
	for _, v := range h.spec.Valid {
		if v.Name == s.Name {
			return true
		}
	}
	return false
}

// ---- 1. Check changes nothing -----------------------------------------------

// checkRepeats is how many times Check is called on each request.
const checkRepeats = 3

func (h *harness) checkNoSideEffects() []string {
	var out []string
	for _, s := range h.samples() {
		r := h.rig()
		req := h.build(r, s, "")
		before := cloneRequest(req)
		w0 := r.WriteCalls()
		a := r.Adapters[h.op]
		first, ferr := callCheck(a, req)
		for i := 1; i < checkRepeats; i++ {
			again, aerr := callCheck(a, req)
			if !reflect.DeepEqual(first, again) || fmt.Sprint(ferr) != fmt.Sprint(aerr) {
				out = append(out, problem(s.Name, "Check gave a different answer on call %d for the same request and the same state (first: %v; now: %v)", i+1, ferr, aerr))
				break
			}
		}
		if w := r.WriteCalls() - w0; w != 0 {
			out = append(out, problem(s.Name, "Check sent %d write call(s) to the service in %d calls; it must send none", w, checkRepeats))
		}
		if !reflect.DeepEqual(before, req) {
			out = append(out, problem(s.Name, "Check changed the request it was given"))
		}
		switch valid := h.isValid(s); {
		case valid && ferr != nil:
			out = append(out, problem(s.Name, "a valid sample was refused by Check: %v", clip(ferr.Error(), 200)))
		case !valid && ferr == nil:
			out = append(out, problem(s.Name, "an invalid sample was accepted by Check"))
		}
	}
	return out
}

// ---- 2. Execute acts once ---------------------------------------------------

func (h *harness) checkActsOnce() []string {
	var out []string
	if h.spec.ReadOnly && h.spec.NotRepeatable != "" {
		out = append(out, "the operation is declared both ReadOnly and NotRepeatable")
	}
	wrote, repeated := false, false
	for _, s := range h.spec.Valid {
		r := h.rig()
		a := r.Adapters[h.op]
		if _, err := callCheck(a, h.build(r, s, "")); err != nil {
			out = append(out, problem(s.Name, "a valid sample was refused by Check: %v", clip(err.Error(), 200)))
			continue
		}
		req := h.build(r, s, ExecutionID)
		w0, a0 := r.WriteCalls(), r.WritesApplied()
		o1, e1 := callExecute(a, cloneRequest(req))
		if !succeeded(o1, e1) {
			out = append(out, problem(s.Name, "a valid sample's Execute did not succeed (%s)", describe(o1, e1)))
			continue
		}
		w1, a1 := r.WriteCalls(), r.WritesApplied()
		if h.spec.ReadOnly && w1 != w0 {
			out = append(out, problem(s.Name, "the operation is declared ReadOnly and Execute sent %d write call(s)", w1-w0))
		}
		wrote = wrote || a1 > a0
		_, e2 := callExecute(a, cloneRequest(req))
		if _, p := e2.(panicError); p {
			out = append(out, problem(s.Name, "the second Execute with the same execution id panicked: %v", e2))
		}
		a2 := r.WritesApplied()
		repeated = repeated || a2 > a1
		if h.spec.NotRepeatable == "" && a2 != a1 {
			out = append(out, problem(s.Name, "Execute twice with the same execution id changed the service %d more time(s); derive the id you send from Request.ExecutionID so the service refuses the repeat, or declare the operation NotRepeatable with the reason", a2-a1))
		}
	}
	if !h.spec.ReadOnly && !wrote {
		out = append(out, "no valid sample made Execute change the fake, so the check proves nothing: add a sample that writes, or declare the operation ReadOnly")
	}
	if h.spec.NotRepeatable != "" && !repeated {
		out = append(out, "the operation is declared NotRepeatable, but a second Execute with the same execution id changed nothing: the declaration is stale, remove NotRepeatable")
	}
	return out
}

// ---- 3. No secret in any output ---------------------------------------------

func (h *harness) checkNoSecret() []string {
	logs := captureLogs(h.t)
	var tr transcript
	var secrets, rigLogs []string
	canBeHostile := false
	// one runs one request on a fresh rig and records everything the adapter said.
	one := func(who string, hostile bool, build func(r *Rig) *ops.Request) {
		r := h.rig()
		if hostile {
			r.Hostile()
		}
		canBeHostile = canBeHostile || r.Hostile != nil
		req := build(r)
		a := r.Adapters[h.op]
		cr, err := callCheck(a, cloneRequest(req))
		tr.add(who+": Check", cr)
		tr.addErr(who+": Check", err)
		ex := cloneRequest(req)
		ex.ExecutionID = ExecutionID
		o, err := callExecute(a, ex)
		tr.add(who+": Execute", o)
		tr.addErr(who+": Execute", err)
		secrets = append(secrets, r.Secrets()...)
		if r.Logs != nil {
			rigLogs = append(rigLogs, r.Logs())
		}
	}
	sweep := func(prefix string, hostile bool) {
		for _, s := range h.samples() {
			one(prefix+s.Name, hostile, func(r *Rig) *ops.Request { return h.build(r, s, "") })
		}
		for _, m := range h.mutants() {
			one(prefix+m.name, hostile, func(r *Rig) *ops.Request {
				req := h.build(r, h.spec.Valid[0], "")
				m.apply(req)
				return req
			})
		}
	}
	sweep("", false)
	if len(secrets) == 0 {
		return []string{"Rig.Secrets returned no credential after the samples ran: the suite has nothing to look for"}
	}
	if canBeHostile {
		sweep("hostile service, ", true)
	}
	secrets = unique(append(secrets, Canary))

	var out []string
	seen := map[string]bool{}
	report := func(where, text string) {
		for _, l := range leaks(text, secrets) {
			key := where + "|" + l
			if !seen[key] {
				seen[key] = true
				out = append(out, fmt.Sprintf("%s holds %s", where, l))
			}
		}
	}
	for _, it := range tr.items {
		report(it.where, it.text)
	}
	report("the captured log output (slog default and log)", logs.String())
	for _, l := range rigLogs {
		report("the connector's own log (Rig.Logs)", l)
	}
	return out
}

// ---- 4. Every refusal has a known cause code --------------------------------

func (h *harness) checkRefusalCodes() []string {
	var out []string
	if len(h.spec.Invalid) == 0 {
		return []string{"no invalid sample: add at least one request the adapter refuses by hand (a caller who may not ask, a target out of scope)"}
	}
	for _, s := range h.spec.Invalid {
		r := h.rig()
		a := r.Adapters[h.op]
		_, err := callCheck(a, h.build(r, s, ""))
		if p := refusalProblem(err, s.Code); p != "" {
			out = append(out, problem(s.Name, "Check: %s", p))
		}
		w0, a0 := r.WriteCalls(), r.WritesApplied()
		o, eerr := callExecute(a, h.build(r, s, ExecutionID))
		if succeeded(o, eerr) {
			out = append(out, problem(s.Name, "Execute succeeded for a request Check refuses: the adapter must check again before it acts"))
		}
		if r.WriteCalls() != w0 || r.WritesApplied() != a0 {
			out = append(out, problem(s.Name, "Execute sent a write for a request Check refuses"))
		}
		if eerr != nil {
			if _, isRef := refusalOf(eerr); isRef {
				if p := refusalProblem(eerr, ""); p != "" {
					out = append(out, problem(s.Name, "Execute: %s", p))
				}
			}
		}
	}
	return out
}

// ---- 5. Undeclared params are refused; declared limits are enforced ---------

func (h *harness) checkParamsAndLimits() []string {
	var out []string
	if len(h.spec.Valid) == 0 {
		return nil
	}
	{
		r := h.rig()
		if _, err := callCheck(r.Adapters[h.op], h.build(r, h.spec.Valid[0], "")); err != nil {
			return []string{problem(h.spec.Valid[0].Name, "the first valid sample is the base of the generated requests and Check refused it: %v", clip(err.Error(), 200))}
		}
	}
	for _, m := range h.mutants() {
		r := h.rig()
		a := r.Adapters[h.op]
		req := h.build(r, h.spec.Valid[0], "")
		m.apply(req)
		_, err := callCheck(a, cloneRequest(req))
		if p := refusalProblem(err, ops.CodeParamsInvalid); p != "" {
			out = append(out, problem(m.name, "Check: %s", p))
		}
		w0 := r.WriteCalls()
		ex := cloneRequest(req)
		ex.ExecutionID = ExecutionID
		o, eerr := callExecute(a, ex)
		if succeeded(o, eerr) {
			out = append(out, problem(m.name, "Execute succeeded: the adapter checks this in Check only, or not at all"))
		}
		if r.WriteCalls() != w0 {
			out = append(out, problem(m.name, "Execute sent a write for a request that breaks a declared limit"))
		}
	}
	return out
}

// ---- 6. Service text is carried as untrusted --------------------------------

// textRun is one Check and one Execute of the first valid sample after Plant.
type textRun struct {
	cr         ops.CheckResult
	cerr, eerr error
	out        ops.Outcome
	strs       []string // every string of the outcome
}

func (h *harness) plantAndRun(p Planted) textRun {
	r := h.rig()
	h.spec.Plant(r, p)
	a := r.Adapters[h.op]
	s := h.spec.Valid[0]
	var run textRun
	run.cr, run.cerr = callCheck(a, h.build(r, s, ""))
	run.out, run.eerr = callExecute(a, h.build(r, s, ExecutionID))
	walkStrings(run.out.Result, func(s string) { run.strs = append(run.strs, s) })
	run.strs = append(run.strs, run.out.ExternalRef)
	return run
}

func (h *harness) checkServiceText() []string {
	if h.spec.Plant == nil || len(h.spec.Valid) == 0 {
		return nil
	}
	full := NewPlanted()
	who := h.spec.Valid[0].Name
	var out []string
	// The checks are shown to the operator as plain lines. Service text may be
	// in them (a state name), but cleaned of control and format characters,
	// capped, and never shaped like a secret. (Evidence is the one place for
	// raw text: the card labels it untrusted.)
	checkLines := func(run textRun) {
		var lines []string
		for _, c := range run.cr.Checks {
			lines = append(lines, c.Name, c.Detail)
		}
		lines = append(lines, run.cr.ApprovalWhy)
		if run.cerr != nil {
			lines = append(lines, run.cerr.Error())
		}
		for _, l := range lines {
			for _, f := range hostileIn(l, full, false) {
				out = append(out, problem(who, "a CheckResult line or the Check error carries %s from the service", f))
			}
			if len(l) >= len(full.Long) {
				out = append(out, problem(who, "a CheckResult line or the Check error is not capped: %d bytes", len(l)))
			}
		}
	}
	ran := func(run textRun) bool {
		if run.cerr != nil {
			out = append(out, problem(who, "Check refused the first valid sample once the text was planted: %v", clip(run.cerr.Error(), 200)))
		}
		if !succeeded(run.out, run.eerr) {
			out = append(out, problem(who, "Execute of the first valid sample did not succeed once the text was planted (%s)", describe(run.out, run.eerr)))
			return false
		}
		return true
	}

	switch h.spec.Text {
	case NoServiceText:
		run := h.plantAndRun(full)
		checkLines(run)
		if ran(run) {
			for _, t := range run.strs {
				for _, f := range hostileIn(t, full, true) {
					out = append(out, problem(who, "the operation is declared to return no service text, and its result carries %s", f))
				}
			}
		}
	case ServiceText:
		// Phase A: control characters, words and a very long text.
		a := h.plantAndRun(Planted{Control: full.Control, Long: full.Long})
		checkLines(a)
		if ran(a) {
			if a.out.Result[UntrustedFlag] != true {
				out = append(out, problem(who, "the result is not marked %s: true, and it carries text the service wrote", UntrustedFlag))
			}
			reached, longest := false, 0
			for _, t := range a.strs {
				reached = reached || strings.Contains(t, ControlWord)
				longest = max(longest, len(t))
				for _, f := range hostileIn(t, full, false) {
					out = append(out, problem(who, "the result carries %s", f))
				}
			}
			if longest >= len(full.Long) {
				out = append(out, problem(who, "service text is not capped: a result string is %d bytes, the planted text was %d", longest, len(full.Long)))
			}
			if !reached {
				out = append(out, problem(who, "the planted words did not reach the result, so the check proved nothing: Plant must put them where the first valid sample reads them"))
			}
		}
		// Phase B: text shaped like a secret.
		b := h.plantAndRun(Planted{Control: "plain words", Secret: full.Secret})
		checkLines(b)
		if ran(b) {
			for _, t := range b.strs {
				if strings.Contains(t, full.Secret) {
					out = append(out, problem(who, "service text shaped like a secret is not withheld: the result carries it"))
					break
				}
			}
		}
	}
	return unique(out)
}

// hostileIn names what in text came from the planted hostile text. echo also
// counts the cleaned words and the start of the long text: for an operation
// that returns no service text they must not appear at all.
func hostileIn(text string, p Planted, echo bool) []string {
	var found []string
	for _, r := range "\u202e\u200d\x07" {
		if strings.ContainsRune(text, r) {
			found = append(found, fmt.Sprintf("the control or format character U+%04X", r))
		}
	}
	if strings.Contains(text, p.Secret) {
		found = append(found, "text shaped like a secret")
	}
	if echo {
		if strings.Contains(text, ControlWord) {
			found = append(found, "the planted words")
		}
		if strings.Contains(text, p.Long[:64]) {
			found = append(found, "the start of the planted long text")
		}
	}
	return found
}

// ---- 7. Class matches the pin -----------------------------------------------

func (h *harness) checkPin() []string {
	var out []string
	pin, ok := h.c.Pins[h.op]
	switch {
	case !ok:
		out = append(out, "the operation has no pin: add its class and reversibility to the pin table (internal/connectors/pintable), written out by hand")
	case pin.Class != h.decl.Class:
		out = append(out, fmt.Sprintf("the declaration says class %s, the pin says %s", h.decl.Class, pin.Class))
	case pin.Reversibility != h.decl.Reversibility:
		out = append(out, fmt.Sprintf("the declaration says reversibility %s, the pin says %s", h.decl.Reversibility, pin.Reversibility))
	}
	if !h.decl.Class.Valid() {
		out = append(out, fmt.Sprintf("class %q is not one of the four classes", h.decl.Class))
	}
	if !h.decl.Reversibility.Valid() {
		out = append(out, fmt.Sprintf("reversibility %q is not one of the three values", h.decl.Reversibility))
	}
	if err := h.decl.Validate(); err != nil {
		out = append(out, "the declaration is invalid: "+err.Error())
	}
	return out
}
