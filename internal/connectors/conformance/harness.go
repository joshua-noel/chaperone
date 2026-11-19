package conformance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/denialtext"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// harness is the state of one evaluation: one connector, one operation.
type harness struct {
	t    testing.TB
	c    Connector
	op   string
	spec Op
	decl kit.Op
}

// rig builds a fresh rig and checks it is usable. A broken rig is a fatal test
// error: nothing the suite says about the adapters would mean anything.
func (h *harness) rig() *Rig {
	h.t.Helper()
	r := h.c.NewRig(h.t, Canary)
	switch {
	case r == nil:
		h.t.Fatal("NewRig returned nil")
	case r.WriteCalls == nil || r.WritesApplied == nil || r.Secrets == nil:
		h.t.Fatal("NewRig: Rig.WriteCalls, WritesApplied and Secrets are required")
	case r.Adapters[h.op] == nil:
		h.t.Fatalf("NewRig: no adapter for %s", h.op)
	}
	if len(r.Adapters) != len(h.c.Declared.Ops) {
		h.t.Fatalf("NewRig: %d adapters for %d declared operations: the rig must build the adapters the connector registers", len(r.Adapters), len(h.c.Declared.Ops))
	}
	for _, o := range h.c.Declared.Ops {
		if r.Adapters[o.Name] == nil {
			h.t.Fatalf("NewRig: no adapter for declared operation %s", o.Name)
		}
	}
	return r
}

// build makes the request of a sample for one call. The suite owns the
// execution id: empty for Check, ExecutionID for Execute.
func (h *harness) build(r *Rig, s Sample, exec string) *ops.Request {
	req := cloneRequest(s.Req(r))
	req.ExecutionID = exec
	return req
}

// panicError is what a call that panicked returns, so the check that made the
// call reports it as a problem instead of ending the test binary.
type panicError struct{ v any }

func (e panicError) Error() string { return fmt.Sprintf("the adapter panicked: %v", e.v) }

func callCheck(a ops.Adapter, req *ops.Request) (res ops.CheckResult, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = panicError{p}
		}
	}()
	return a.Check(context.Background(), req)
}

func callExecute(a ops.Adapter, req *ops.Request) (out ops.Outcome, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = panicError{p}
		}
	}()
	return a.Execute(context.Background(), req)
}

// succeeded reports whether an Execute answered success.
func succeeded(out ops.Outcome, err error) bool { return err == nil && !out.Failed && !out.Unconfirmed }

// describe says in one line how an Execute answered.
func describe(out ops.Outcome, err error) string {
	switch {
	case err != nil:
		return "error: " + clip(err.Error(), 200)
	case out.Failed:
		return "failed outcome: " + clip(fmt.Sprint(out.Result["error"]), 200)
	case out.Unconfirmed:
		return "unconfirmed outcome: " + clip(fmt.Sprint(out.Result["error"]), 200)
	}
	return "succeeded"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

// knownCode reports whether chapd knows the cause code: denialtext holds the
// one table of the codes Chaperone emits, and a test there keeps it equal to the
// enum of denial.schema.json.
func knownCode(code string) bool { return denialtext.Plain(code) != "" }

// refusalOf returns the refusal inside err.
func refusalOf(err error) (*ops.Refusal, bool) {
	var ref *ops.Refusal
	return ref, errors.As(err, &ref)
}

// refusalProblem says what is wrong with err as a refusal, or "" when it is a
// well-formed refusal. want is the exact code wanted, or "".
func refusalProblem(err error, want string) string {
	if err == nil {
		return "it was accepted"
	}
	ref, ok := refusalOf(err)
	switch {
	case !ok:
		return fmt.Sprintf("the error is not a *ops.Refusal, so chapd treats it as \"the service could not be asked\": %v", clip(err.Error(), 200))
	case !knownCode(ref.Code):
		return fmt.Sprintf("the refusal has cause code %q, which is not a code chapd knows", ref.Code)
	case want != "" && ref.Code != want:
		return fmt.Sprintf("the refusal has cause code %s, the sample wants %s (%s)", ref.Code, want, clip(ref.Why, 120))
	case strings.TrimSpace(ref.Why) == "":
		return "the refusal has no Why"
	}
	return ""
}

// ---- requests ---------------------------------------------------------------

func cloneValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = cloneValue(e)
		}
		return m
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = cloneValue(e)
		}
		return s
	case []string:
		return append([]string(nil), x...)
	}
	return v
}

func cloneRequest(r *ops.Request) *ops.Request {
	c := *r
	if r.Params != nil {
		c.Params = cloneValue(r.Params).(map[string]any)
	}
	if r.Caller != nil {
		cc := *r.Caller
		cc.Paths = append([]string(nil), r.Caller.Paths...)
		cc.TokenOps = append([]string(nil), r.Caller.TokenOps...)
		cc.Projects = append([]string(nil), r.Caller.Projects...)
		cc.ScopeOps = append([]string(nil), r.Caller.ScopeOps...)
		c.Caller = &cc
	}
	c.ApprovedEvidence = append([]ops.Evidence(nil), r.ApprovedEvidence...)
	return &c
}

// ---- text of outputs --------------------------------------------------------

// walkStrings calls f for every string reachable from v: map keys, map values,
// slice items, struct fields, whatever a result holds.
func walkStrings(v any, f func(string)) { walk(reflect.ValueOf(v), f, 0) }

func walk(v reflect.Value, f func(string), depth int) {
	if !v.IsValid() || depth > 24 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		f(v.String())
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			walk(it.Key(), f, depth+1)
			walk(it.Value(), f, depth+1)
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			f(string(v.Bytes()))
			return
		}
		for i := range v.Len() {
			walk(v.Index(i), f, depth+1)
		}
	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			walk(v.Elem(), f, depth+1)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				walk(v.Field(i), f, depth+1)
			}
		}
	}
}

// transcript is everything an adapter said: results, checks, errors.
type transcript struct{ items []spoken }

type spoken struct{ where, text string }

func (tr *transcript) add(where string, v any) {
	walkStrings(v, func(s string) { tr.items = append(tr.items, spoken{where, s}) })
}

func (tr *transcript) addErr(where string, err error) {
	if err == nil {
		return
	}
	tr.items = append(tr.items, spoken{where + " (error text)", err.Error()})
	if ref, ok := refusalOf(err); ok {
		tr.add(where+" (refusal)", *ref)
	}
}

// ---- logs -------------------------------------------------------------------

type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// captureLogs sends the default slog logger and the log package to a buffer
// until the test ends. A connector that logs through either is seen; one that
// logs to its own logger reports it in Rig.Logs.
func captureLogs(t testing.TB) *logCapture {
	t.Helper()
	l := &logCapture{}
	prevSlog, prevOut := slog.Default(), log.Writer()
	slog.SetDefault(slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(l)
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevOut)
	})
	return l
}

// secretLabel names a credential for a message without printing it.
func secretLabel(s string) string {
	if s == Canary {
		return "the planted canary credential"
	}
	return fmt.Sprintf("a credential the fake saw (%d bytes)", len(s))
}

// leaks returns the labels of the credentials found in text. A long value is
// also looked for by its last 24 bytes, so a clipped copy is seen.
func leaks(text string, secrets []string) []string {
	var found []string
	for _, s := range secrets {
		if len(s) < 8 {
			continue
		}
		if strings.Contains(text, s) || (len(s) >= 48 && strings.Contains(text, s[len(s)-24:])) {
			found = append(found, secretLabel(s))
		}
	}
	return found
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
