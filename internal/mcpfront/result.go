package mcpfront

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	approvalIDRE = regexp.MustCompile(`^a-[0-9a-z]{6,32}$`)
	classes      = map[string]bool{"routine": true, "gated": true, "high": true, "critical": true}
)

// toolOK is a successful tool result: text for every client, the same data
// structured for clients that read it.
func (s *server) toolOK(text string, structured map[string]any) map[string]any {
	res := map[string]any{
		"content": []any{map[string]any{"type": "text", "text": s.cfg.Scrub(text)}},
		"isError": false,
	}
	if structured != nil {
		res["structuredContent"] = s.scrubValue(structured)
	}
	return res
}

// toolError is a failed tool result: the model reads the text and recovers.
func (s *server) toolError(text string) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": s.cfg.Scrub(text)}},
		"isError": true,
	}
}

// scrubValue masks secrets in every string of a decoded JSON value.
func (s *server) scrubValue(v any) any {
	switch x := v.(type) {
	case string:
		return s.cfg.Scrub(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[s.cfg.Scrub(k)] = s.scrubValue(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = s.scrubValue(e)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = s.scrubValue(e)
		}
		return out
	}
	return v
}

// decodeAny decodes JSON keeping number text.
func decodeAny(raw []byte) (any, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

func pretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// fromReply maps chapd's answer to an op call (or a status read) to a tool
// result. forOp says the call was a tool for an op, so a refusal may point at
// request_approval.
func (s *server) fromReply(rep *Reply, forOp bool) map[string]any {
	if rep.Status < 200 || rep.Status >= 300 {
		text, structured := s.refusalText(rep, forOp)
		res := s.toolError(text)
		res["structuredContent"] = s.scrubValue(structured)
		return res
	}
	var head struct {
		Type string `json:"type"`
	}
	json.Unmarshal(rep.Body, &head)
	if head.Type == "dry_run" {
		return s.dryRun(rep.Body)
	}
	return s.opResult(rep.Body)
}

// opView is the part of an Op this server reads.
type opView struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Op          string `json:"op"`
	Class       string `json:"class"`
	ExternalRef string `json:"external_ref"`
	ExpiresAt   string `json:"expires_at"`
	Approval    *struct {
		ID        string `json:"id"`
		ExpiresAt string `json:"expires_at"`
	} `json:"approval"`
	Result json.RawMessage `json:"result"`
	Checks json.RawMessage `json:"checks"`
	Denial json.RawMessage `json:"denial"`
}

func (s *server) opResult(body []byte) map[string]any {
	var o opView
	if err := json.Unmarshal(body, &o); err != nil || !opIDRE.MatchString(o.ID) {
		return s.toolError("Chaperone's reply cannot be read as an op; nothing can be said about the outcome. Look the op up before retrying.")
	}
	switch o.State {
	case "succeeded":
		return s.succeeded(&o)
	case "requested", "pending_approval", "allowed", "executing", "unconfirmed":
		return s.pending(&o)
	}
	return s.notDone(&o)
}

// pending is the result of an op that is not finished. It carries only the
// fixed fields below. Nothing from the approval is copied in, so no card text
// can pass through here (the no-card rule): the card is shown by the
// console and by nothing else.
func (s *server) pending(o *opView) map[string]any {
	res := map[string]any{"status": "pending", "state": o.State, "op_id": o.ID}
	switch o.State {
	case "pending_approval":
		res["next"] = nextApproval
	case "unconfirmed":
		res["next"] = nextUnconfirm
	default:
		res["next"] = nextUnfinished
	}
	if classes[o.Class] {
		res["class"] = o.Class
	}
	expires := o.ExpiresAt
	if o.Approval != nil {
		if approvalIDRE.MatchString(o.Approval.ID) {
			res["approval_id"] = o.Approval.ID
		}
		if o.State == "pending_approval" && o.Approval.ExpiresAt != "" {
			expires = o.Approval.ExpiresAt
		}
	}
	if t, err := time.Parse(time.RFC3339, expires); err == nil {
		left := int(t.Sub(s.cfg.Now()).Seconds())
		if left < 0 {
			left = 0
		}
		res["seconds_left"] = left
	}
	b, _ := json.Marshal(res)
	return s.toolOK(string(b), res)
}

func (s *server) succeeded(o *opView) map[string]any {
	res := map[string]any{"status": "succeeded", "op": o.Op, "op_id": o.ID}
	if classes[o.Class] {
		res["class"] = o.Class
	}
	if o.ExternalRef != "" {
		res["external_ref"] = o.ExternalRef
	}
	if v, ok := decodeAny(o.Checks); ok {
		res["checks"] = v
	}
	text := ""
	untrusted := false
	if v, ok := decodeAny(o.Result); ok {
		// Whatever the op read from outside stays in a field named for it,
		// behind a fixed notice, never merged into the fields above.
		res["untrusted_result"] = v
		text = UntrustedNotice + "\n"
		untrusted = true
	}
	body := text + pretty(s.scrubValue(res))
	if untrusted {
		// A client that hands the model only structuredContent must still
		// see the warning: it is a fixed field next to untrusted_result.
		// (Added after the text is built, so the text carries it once.)
		res["untrusted_notice"] = UntrustedNotice
	}
	return s.toolOK(body, res)
}

// notDone is the result of an op that ended without success.
func (s *server) notDone(o *opView) map[string]any {
	res := map[string]any{"status": o.State, "op": o.Op, "op_id": o.ID}
	if classes[o.Class] {
		res["class"] = o.Class
	}
	var b strings.Builder
	rendered := "" // the step the rendered denial already gives
	fmt.Fprintf(&b, "%s: %s\n", o.Op, o.State)
	if len(o.Denial) > 0 && string(o.Denial) != "null" {
		var d struct {
			CauseCode string `json:"cause_code"`
			Why       string `json:"why"`
		}
		if json.Unmarshal(o.Denial, &d) == nil {
			res["cause_code"], res["why"] = d.CauseCode, d.Why
		}
		var dtext string
		dtext, rendered = s.denialText(o.Denial)
		b.WriteString(dtext)
	} else {
		b.WriteString("why: Chaperone recorded no reason for this refusal; the cause code is in the ledger.\n")
	}
	if v, ok := decodeAny(o.Checks); ok {
		res["checks"] = v
	}
	if rendered != "" {
		res["next"] = rendered
	} else {
		switch o.State {
		case "expired":
			res["next"] = "The request or approval ran out; nothing ran. Ask again with request_approval=true if it is still needed."
		case "failed":
			res["next"] = "The op ran and failed. Read why before trying again."
		default:
			res["next"] = "Nothing ran. Do not retry unchanged."
		}
		fmt.Fprintf(&b, "next: %s\n", res["next"])
	}
	out := s.toolError(b.String())
	out["structuredContent"] = s.scrubValue(res)
	return out
}

// dryRun maps a dry-run verdict: information, not an error, even when the op
// would be refused.
func (s *server) dryRun(body []byte) map[string]any {
	var v struct {
		Outcome       string          `json:"outcome"`
		Class         string          `json:"class"`
		PolicyVersion string          `json:"policy_version"`
		OpHash        string          `json:"op_hash"`
		Checks        json.RawMessage `json:"checks"`
		Denial        json.RawMessage `json:"denial"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return s.toolError("Chaperone's dry-run answer cannot be read.")
	}
	res := map[string]any{"status": "dry_run", "outcome": v.Outcome, "policy_version": v.PolicyVersion, "op_hash": v.OpHash}
	if classes[v.Class] {
		res["class"] = v.Class
	}
	if c, ok := decodeAny(v.Checks); ok {
		res["checks"] = c
	}
	var b strings.Builder
	switch v.Outcome {
	case "allow":
		b.WriteString("dry run: would be released now\n")
	case "approval":
		b.WriteString("dry run: would need an approval (call again with request_approval=true and a reason)\n")
	default:
		b.WriteString("dry run: would be refused\n")
	}
	if len(v.Denial) > 0 && string(v.Denial) != "null" {
		var d struct {
			CauseCode string `json:"cause_code"`
			Why       string `json:"why"`
		}
		if json.Unmarshal(v.Denial, &d) == nil {
			res["cause_code"], res["why"] = d.CauseCode, d.Why
		}
		dtext, _ := s.denialText(v.Denial)
		b.WriteString(dtext)
	}
	return s.toolOK(b.String(), res)
}

// denialText is a denial in the wording `chap` uses, without its
// `request: chap request ...` line: that is a command-line instruction, and
// here the way to ask is the tool's request_approval argument. It also returns
// the step of the `next:` line the rendering already has ("" when it has none),
// so a caller never adds a second, contradicting `next:`.
func (s *server) denialText(denial []byte) (text, next string) {
	if s.cfg.RenderDenial != nil {
		text = s.cfg.RenderDenial(denial)
	} else {
		var d struct {
			CauseCode string `json:"cause_code"`
			Why       string `json:"why"`
		}
		json.Unmarshal(denial, &d)
		text = "DENIED\ncause: " + d.CauseCode + "\nwhy: " + d.Why + "\n"
	}
	var out strings.Builder
	for _, line := range strings.SplitAfter(text, "\n") {
		if strings.HasPrefix(line, "request:") {
			continue
		}
		if step, ok := strings.CutPrefix(line, "next:"); ok && next == "" {
			next = strings.TrimSpace(step)
		}
		out.WriteString(line)
	}
	return out.String(), next
}

// refusalText words a non-2xx answer and returns its structured form.
func (s *server) refusalText(rep *Reply, forOp bool) (string, map[string]any) {
	var head struct {
		Type      string `json:"type"`
		CauseCode string `json:"cause_code"`
		Why       string `json:"why"`
		Retryable bool   `json:"retryable"`
		State     string `json:"state"`
		Request   struct {
			Possible bool `json:"possible"`
		} `json:"request"`
	}
	if json.Unmarshal(rep.Body, &head) != nil {
		msg := fmt.Sprintf("Chaperone answered %d with a body that is not JSON; nothing can be said about the outcome.", rep.Status)
		return msg, map[string]any{"status": "error", "http_status": rep.Status}
	}
	structured := map[string]any{"status": "refused", "http_status": rep.Status}
	if n, err := strconv.Atoi(rep.RetryAfter); err == nil && n > 0 {
		structured["retry_after_seconds"] = n
	}
	var b strings.Builder
	switch head.Type {
	case "denial":
		text, rendered := s.denialText(rep.Body)
		b.WriteString(text)
		structured["status"] = "denied"
		structured["cause_code"], structured["why"] = head.CauseCode, head.Why
		// The rendered denial already says the real next step when it has one
		// (a stale branch, a flood, an expired token); that line stays the
		// only `next:` and is the structured next. The generic MCP line is
		// for a denial that has none.
		next := rendered
		if next == "" {
			switch {
			case !head.Request.Possible:
				next = "Asking is not possible: policy does not allow it. Do not retry unchanged."
			case forOp:
				next = "A human can approve this. Call this tool again with request_approval=true and a reason; nothing runs until they decide in the Chaperone console."
			default:
				next = "Do not retry unchanged."
			}
		}
		structured["next"] = next
		if n, ok := structured["retry_after_seconds"]; ok {
			fmt.Fprintf(&b, "retry after %d s\n", n)
		}
		if rendered == "" {
			fmt.Fprintf(&b, "next: %s\n", next)
		}
	case "auth_error":
		structured["status"] = "auth_failed"
		structured["why"] = head.Why
		fmt.Fprintf(&b, "AUTH FAILED: Chaperone could not identify the caller\nwhy: %s\nnext: check CHAP_RUN_TOKEN or the orchestrator token file; asking is not possible\n", head.Why)
	case "unavailable":
		structured["status"] = "unavailable"
		structured["why"] = head.Why
		kind := "not retryable as is"
		if head.Retryable {
			kind = "retryable"
		}
		fmt.Fprintf(&b, "UNAVAILABLE (%s): Chaperone failed closed, nothing ran\nwhy: %s\n", kind, head.Why)
	case "not_found":
		structured["status"] = "not_found"
		structured["why"] = head.Why
		fmt.Fprintf(&b, "NOT FOUND\nwhy: %s\n", head.Why)
	case "conflict":
		structured["status"] = "conflict"
		structured["why"] = head.Why
		b.WriteString("CONFLICT")
		if head.State != "" {
			fmt.Fprintf(&b, " (state %s)", head.State)
		}
		fmt.Fprintf(&b, "\nwhy: %s\n", head.Why)
	default:
		structured["status"] = "error"
		fmt.Fprintf(&b, "Chaperone answered %d.\n", rep.Status)
	}
	return b.String(), structured
}
