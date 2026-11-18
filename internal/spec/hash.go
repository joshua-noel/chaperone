package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
)

// ZeroHash is the prev_hash of the first event of a chain.
const ZeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func sha256Tagged(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SHA256Tagged is "sha256:" + lowercase hex of SHA-256 over data.
func SHA256Tagged(data []byte) string { return sha256Tagged(data) }

// Tree turns any JSON-encodable Go value (a typed Request, a map, raw decoded
// JSON) into a document tree by way of its JSON form, parsed with ParseStrict.
// The I-JSON rules therefore hold for in-memory values too: a params number
// above 2^53 is refused here, not hashed.
func Tree(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return ParseStrict(b)
}

func treeObject(v any) (map[string]any, error) {
	t, err := Tree(v)
	if err != nil {
		return nil, err
	}
	m, ok := t.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected a JSON object, got %T", t)
	}
	return m, nil
}

func jcsHash(v any) (string, error) {
	b, err := JCS(v)
	if err != nil {
		return "", err
	}
	return sha256Tagged(b), nil
}

// pick copies the named members of m. A missing member is an error: the
// reference implementation refuses to hash `undefined`.
func pick(m map[string]any, what string, names ...string) (map[string]any, error) {
	out := make(map[string]any, len(names))
	for _, n := range names {
		v, ok := m[n]
		if !ok {
			return nil, fmt.Errorf("%s has no %q", what, n)
		}
		out[n] = v
	}
	return out, nil
}

func member(m map[string]any, what, outer, inner string) (any, error) {
	o, ok := m[outer].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s has no %q object", what, outer)
	}
	v, ok := o[inner]
	if !ok {
		return nil, fmt.Errorf("%s has no %q", what, outer+"."+inner)
	}
	return v, nil
}

// OpHash is the op_hash of an operation request: SHA-256 over the JCS form of
// {spec_version, project, op, target, params}. request is a Request, a decoded
// map, or anything with that JSON form; other members are ignored.
func OpHash(request any) (string, error) {
	m, err := treeObject(request)
	if err != nil {
		return "", err
	}
	in, err := pick(m, "request", "spec_version", "project", "op", "target", "params")
	if err != nil {
		return "", err
	}
	return jcsHash(in)
}

// ApprovalChallenge is the challenge an approver's authenticator signs: SHA-256
// over the JCS form of {approval_id, request_id, run_id (omitted when absent),
// op_hash, decision, approver_id, nonce, expires_at, policy_version,
// display_sha256}. decision and approver_id are bound so an assertion given for
// a denial cannot be replayed as an approval, or under another approver.
func ApprovalChallenge(approval any) (string, error) {
	m, err := treeObject(approval)
	if err != nil {
		return "", err
	}
	in, err := pick(m, "approval", "approval_id", "request_id", "op_hash", "decision", "nonce", "expires_at", "policy_version")
	if err != nil {
		return "", err
	}
	if in["approver_id"], err = member(m, "approval", "approver", "id"); err != nil {
		return "", err
	}
	if in["display_sha256"], err = member(m, "approval", "shown", "display_sha256"); err != nil {
		return "", err
	}
	if v, ok := m["run_id"]; ok {
		in["run_id"] = v
	}
	return jcsHash(in)
}

// EventHash is the hash of a ledger event: SHA-256 over the JCS form of the
// event without its "hash" member.
func EventHash(event any) (string, error) {
	m, err := treeObject(event)
	if err != nil {
		return "", err
	}
	delete(m, "hash")
	return jcsHash(m)
}

// TraceID is the first 16 bytes of SHA-256(s) in lowercase hex. s is a run_id,
// or a chain id for an event that has no run.
func TraceID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

// traceIDOf is the trace_id an event must carry: from its run_id, else its chain.
func traceIDOf(event map[string]any) (string, error) {
	if run, ok := event["run_id"].(string); ok {
		return TraceID(run), nil
	}
	if event["run_id"] != nil {
		return "", fmt.Errorf("run_id is not a string")
	}
	if chain, ok := event["chain"].(string); ok {
		return TraceID(chain), nil
	}
	return "", fmt.Errorf("event has neither run_id nor chain")
}

// Traceparent is a parsed W3C traceparent, version 00.
type Traceparent struct {
	TraceID  string
	ParentID string
	Flags    string
}

func isLowerHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool {
	for i := range len(s) {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// ParseTraceparent parses "00-<32 hex>-<16 hex>-<2 hex>" in lowercase hex,
// neither id all zeros. It reports false when the text is malformed.
func ParseTraceparent(text string) (Traceparent, bool) {
	// 2+1+32+1+16+1+2
	if len(text) != 55 || text[:3] != "00-" || text[35] != '-' || text[52] != '-' {
		return Traceparent{}, false
	}
	tp := Traceparent{TraceID: text[3:35], ParentID: text[36:52], Flags: text[53:]}
	if !isLowerHex(tp.TraceID) || !isLowerHex(tp.ParentID) || !isLowerHex(tp.Flags) ||
		allZero(tp.TraceID) || allZero(tp.ParentID) {
		return Traceparent{}, false
	}
	return tp, true
}

// TraceparentFor builds the traceparent for a run: the run's derived trace id,
// the parent span id of the injecting component, and flags ("01" = sampled).
func TraceparentFor(runID, parentID, flags string) (string, error) {
	text := "00-" + TraceID(runID) + "-" + parentID + "-" + flags
	if _, ok := ParseTraceparent(text); !ok {
		return "", fmt.Errorf("not a valid traceparent: %s", text)
	}
	return text, nil
}

// jsString renders a decoded value the way a JavaScript template literal does,
// so problem strings match the reference implementation.
func jsString(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case float64:
		return esNumber(x)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

// VerifyChain verifies one hash chain: the events of a single "chain", in any
// order. It returns one problem string per defect, in the order and wording of
// the spec's verifyChain; an empty result means the chain is intact. It detects
// an edited event, a deleted event, a reordered chain and an edited event with
// a recomputed hash (the next event's prev_hash breaks). It cannot detect
// truncation at the head or a wholesale rewrite: that is what ledger.anchor is for.
func VerifyChain[E any](events []E) []string {
	trees := make([]map[string]any, 0, len(events))
	var problems []string
	for i, e := range events {
		m, err := treeObject(e)
		if err != nil {
			problems = append(problems, fmt.Sprintf("event %d: %v", i, err))
			continue
		}
		trees = append(trees, m)
	}
	seqOf := func(m map[string]any) float64 {
		if f, ok := m["seq"].(float64); ok {
			return f
		}
		return -1
	}
	sort.SliceStable(trees, func(i, j int) bool { return seqOf(trees[i]) < seqOf(trees[j]) })
	for index, event := range trees {
		where := fmt.Sprintf("chain %s seq %s", jsString(event["chain"]), jsString(event["seq"]))
		if seq, ok := event["seq"].(float64); !ok || seq != float64(index) {
			problems = append(problems, fmt.Sprintf("%s: expected seq %d (gap or duplicate)", where, index))
		}
		expectedPrev := ZeroHash
		if index > 0 {
			expectedPrev = jsString(trees[index-1]["hash"])
		}
		if event["prev_hash"] != expectedPrev {
			problems = append(problems, where+": prev_hash does not match the previous event")
		}
		if got, err := EventHash(event); err != nil {
			problems = append(problems, fmt.Sprintf("%s: hash cannot be computed: %v", where, err))
		} else if event["hash"] != got {
			problems = append(problems, where+": hash does not match the event content")
		}
		if want, err := traceIDOf(event); err != nil || event["trace_id"] != want {
			problems = append(problems, where+": trace_id is not derived from run_id (or chain id when there is no run)")
		}
		if index > 0 && !reflect.DeepEqual(trees[index-1]["chain"], event["chain"]) {
			problems = append(problems, where+": mixed chains")
		}
	}
	return problems
}
