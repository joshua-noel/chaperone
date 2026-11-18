package spec

import (
	"fmt"
	"sort"
)

// Cross-event rules of the ledger that JSON Schema cannot express, ported from
// the reference implementation (checkRequesterIdentity, checkVaultWrites;
// spec v0.1.1, section 5). The problem strings are the reference messages.

func attrStr(e Event, name string) string {
	s, _ := e.Attributes[name].(string)
	return s
}

func sortedEvents(events []Event) []Event {
	out := append([]Event(nil), events...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Chain != out[j].Chain {
			return out[i].Chain < out[j].Chain
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

// CheckRequesterIdentity checks who caused each event of a request: every
// op.request, op.approve, op.result and vault.write of one request_id names the
// same requester (factory.requester.kind and factory.orchestrator.id), and,
// given the request documents, matches the document's requester.
func CheckRequesterIdentity(events []Event, requests []Request) []string {
	var problems []string
	docs := map[string]Request{}
	for _, r := range requests {
		docs[r.RequestID] = r
	}
	type first struct{ where, who string }
	seen := map[string]first{}
	for _, e := range sortedEvents(events) {
		switch e.EventName {
		case "op.request", "op.approve", "op.result", "vault.write":
		default:
			continue
		}
		where := fmt.Sprintf("%s seq %d", e.Chain, e.Seq)
		who := "run " + e.RunID
		if attrStr(e, "factory.requester.kind") == "orchestrator" {
			who = "orchestrator " + attrStr(e, "factory.orchestrator.id")
		}
		rid := attrStr(e, "factory.request_id")
		if f, ok := seen[rid]; !ok {
			seen[rid] = first{where, who}
		} else if f.who != who {
			problems = append(problems, fmt.Sprintf("%s: request %s was caused by %s here but by %s at %s", where, rid, who, f.who, f.where))
		}
		doc, ok := docs[rid]
		if !ok {
			continue
		}
		want := "run " + doc.Requester.RunID
		if doc.Requester.Kind == "orchestrator" {
			want = "orchestrator " + doc.Requester.ID
		}
		if who != want {
			problems = append(problems, fmt.Sprintf("%s: the request document names %s, the event names %s", where, want, who))
		}
	}
	return problems
}

// CheckVaultWrites checks the vault writes of a ledger: each vault.write is
// the record of one approved secrets.write (the request was a secrets.write,
// an approval of that op_hash came first, one execution wrote once, and the
// op.result of that execution reports the same outcome), and a succeeded
// secrets.write result without a vault.write is reported.
func CheckVaultWrites(events []Event) []string {
	var problems []string
	sorted := sortedEvents(events)
	same := func(e, w Event) bool {
		return e.Chain == w.Chain && attrStr(e, "factory.request_id") == attrStr(w, "factory.request_id")
	}
	find := func(pred func(Event) bool) (Event, bool) {
		for _, e := range sorted {
			if pred(e) {
				return e, true
			}
		}
		return Event{}, false
	}
	var writes []Event
	for _, e := range sorted {
		if e.EventName == "vault.write" {
			writes = append(writes, e)
		}
	}
	written := map[string]bool{}
	for _, w := range writes {
		where := fmt.Sprintf("%s seq %d", w.Chain, w.Seq)
		rid, hash, xid, outcome := attrStr(w, "factory.request_id"), attrStr(w, "factory.op_hash"), attrStr(w, "factory.execution_id"), attrStr(w, "factory.outcome")
		request, ok := find(func(e Event) bool { return e.EventName == "op.request" && same(e, w) })
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: no op.request for request %s", where, rid))
		case attrStr(request, "factory.op") != "secrets.write":
			problems = append(problems, fmt.Sprintf("%s: request %s is %s, not secrets.write", where, rid, attrStr(request, "factory.op")))
		case attrStr(request, "factory.op_hash") != hash:
			problems = append(problems, fmt.Sprintf("%s: op_hash differs from the request's", where))
		}
		if _, ok := find(func(e Event) bool {
			return e.EventName == "op.approve" && same(e, w) && e.Seq < w.Seq &&
				attrStr(e, "factory.decision") == "approved" && attrStr(e, "factory.op_hash") == hash
		}); !ok {
			problems = append(problems, fmt.Sprintf("%s: the vault was written without an earlier approval of op_hash %s", where, hash))
		}
		if written[xid] {
			problems = append(problems, fmt.Sprintf("%s: execution %s already wrote the vault", where, xid))
		}
		written[xid] = true
		if _, ok := find(func(e Event) bool {
			return e.EventName == "op.result" && same(e, w) && attrStr(e, "factory.execution_id") == xid && attrStr(e, "factory.outcome") == outcome
		}); !ok {
			problems = append(problems, fmt.Sprintf("%s: no op.result with execution_id %s and outcome %s", where, xid, outcome))
		}
	}
	for _, e := range sorted {
		if e.EventName != "op.request" || attrStr(e, "factory.op") != "secrets.write" {
			continue
		}
		done, ok := find(func(r Event) bool {
			return r.EventName == "op.result" && same(r, e) && attrStr(r, "factory.outcome") == "succeeded"
		})
		if !ok {
			continue
		}
		wrote := false
		for _, w := range writes {
			if same(w, e) {
				wrote = true
				break
			}
		}
		if !wrote {
			problems = append(problems, fmt.Sprintf("%s seq %d: secrets.write request %s succeeded with no vault.write", done.Chain, done.Seq, attrStr(e, "factory.request_id")))
		}
	}
	return problems
}
