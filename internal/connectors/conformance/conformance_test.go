package conformance_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unicode"

	"github.com/joshua-noel/chaperone/internal/connectors/conformance"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/redact"
	"github.com/joshua-noel/chaperone/internal/spec"
)

// This file tests the suite itself. A small connector ("toy") with a fake
// service passes every check; then one defect at a time is switched on and the
// check that is meant to catch it must fail. A check that cannot be made to
// fail proves nothing, so each of the seven has at least one defect here.

// ---- the toy service --------------------------------------------------------

type toySvc struct {
	*httptest.Server
	mu         sync.Mutex
	secret     string
	echo       bool
	notes      map[string]string
	board      string
	writeCalls int
	applied    int
	seen       []string
}

func newToySvc(t testing.TB, secret string) *toySvc {
	s := &toySvc{secret: secret, notes: map[string]string{"n1": "a plain note"}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *toySvc) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.seen = append(s.seen, bearer)
	write := r.Method != http.MethodGet
	if write {
		s.writeCalls++
	}
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	if bearer != s.secret {
		msg := "bad credential"
		if s.echo {
			msg += " " + bearer
		}
		reply(http.StatusUnauthorized, map[string]string{"error": msg})
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/notes/"):
		text, ok := s.notes[strings.TrimPrefix(r.URL.Path, "/notes/")]
		if !ok {
			reply(http.StatusNotFound, map[string]string{"error": "no such note"})
			return
		}
		reply(http.StatusOK, map[string]string{"text": text, "board": s.board})
	case r.Method == http.MethodPost && r.URL.Path == "/notes":
		var in struct{ ID, Text string }
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &in)
		if _, dup := s.notes[in.ID]; dup || in.ID == "" {
			reply(http.StatusConflict, map[string]string{"error": "the note exists"})
			return
		}
		s.notes[in.ID] = in.Text
		s.applied++
		reply(http.StatusCreated, map[string]string{"id": in.ID, "board": s.board})
	default:
		reply(http.StatusNotFound, map[string]string{"error": "no route"})
	}
}

func (s *toySvc) set(f func()) { s.mu.Lock(); f(); s.mu.Unlock() }

// ---- the toy connector ------------------------------------------------------

var (
	toyShow = kit.Op{
		Name: "note.show", Class: kit.Routine, Reversibility: kit.Reversible,
		Summary: "Read one note.", Usage: "chap note show <n1> [--verbose]", RatePerMinute: 12,
		Doc:    "Target is a note id. Returns the note's text.",
		Target: kit.Target{Adapter: "toy", Pattern: `^n[0-9]{1,4}$`, Why: "the note must be an id such as n1", Positional: "n1"},
		Params: []kit.Param{{Name: "verbose", Kind: kit.Bool, Help: "say more"}},
	}
	toyAdd = kit.Op{
		Name: "note.add", Class: kit.Routine, Reversibility: kit.Compensable,
		Summary: "Add a note.", Usage: "chap note add <n1> --text <t>", RatePerMinute: 6,
		Doc:    "Target is the parent note id. Adds one note.",
		Target: kit.Target{Adapter: "toy", Pattern: `^n[0-9]{1,4}$`, Why: "the note must be an id such as n1", Positional: "n1"},
		Params: []kit.Param{{Name: "text", Kind: kit.String, Required: true, MinLength: 1, MaxLength: 20, Placeholder: "t", Help: "the text"}},
	}
	toyDecl = kit.Connector{Name: "toy", Ops: []kit.Op{toyShow, toyAdd}}
	toyPins = map[string]kit.Pin{
		"note.show": {Class: kit.Routine, Reversibility: kit.Reversible},
		"note.add":  {Class: kit.Routine, Reversibility: kit.Compensable},
	}
)

// defects are the ways the toy adapters can be wrong, one switch each.
type defects struct {
	checkWrites      bool // Check posts a probe note
	idFromCounter    bool // add sends a fresh id on every Execute
	leakResult       bool // the credential goes into a result
	leakLog          bool // the credential goes into the log
	relayBody        bool // the service's error body goes into the error text
	plainError       bool // a refusal is a plain error
	badCode          bool // a refusal carries an invented code
	noParamCheck     bool // an undeclared param is accepted
	noMaxCheck       bool // the length of text is not checked by the adapter
	noExecuteRecheck bool // Execute does not check the request again
	noFlag           bool // show does not mark its text untrusted
	noClean          bool // show keeps control characters
	noCap            bool // show does not cap the text
	noWithhold       bool // show passes text that looks like a secret
	echoBoard        bool // add puts the service's board title in its result
	execWritesInShow bool // show Execute posts a note (a read that writes)
	leakBase64       bool // the credential goes into a result, base64-encoded
	leakUpper        bool // ... in upper case
	leakClipped      bool // ... cut to its first 30 bytes
	leakSplit        bool // ... split across two fields (the suite does not find this)
	ownCredential    bool // the rig ignores the canary and uses a credential of its own
	noHostile        bool // the rig has no hostile mode
	blindCounters    bool // the fake counts no writes
}

type toyAdapter struct {
	op   kit.Op
	base string
	cred string
	d    defects
	reg  *redact.Registry
	n    *atomic.Int64
}

var refRE = regexp.MustCompile(`^n[0-9]{1,4}$`)

func (a *toyAdapter) refuse(code, format string, args ...any) error {
	if a.d.plainError {
		return fmt.Errorf(format, args...)
	}
	if a.d.badCode {
		code = "NOPE"
	}
	return &ops.Refusal{Code: code, Why: fmt.Sprintf(format, args...)}
}

func (a *toyAdapter) parse(r *ops.Request) (map[string]any, error) {
	if r.Caller == nil || r.Caller.Kind != ops.KindOrchestrator {
		return nil, a.refuse(ops.CodePolicyRefused, "%s is for the orchestrator only", r.Op)
	}
	if r.Target.Adapter != "toy" || !refRE.MatchString(r.Target.Ref) {
		return nil, a.refuse(ops.CodeParamsInvalid, "target must be toy:n<number>")
	}
	allowed := a.op.ParamNames()
	for k := range r.Params {
		if a.d.noParamCheck {
			break
		}
		ok := false
		for _, n := range allowed {
			ok = ok || n == k
		}
		if !ok {
			return nil, a.refuse(ops.CodeParamsInvalid, "unknown param %q; this op takes %s", k, strings.Join(allowed, ", "))
		}
	}
	switch a.op.Name {
	case "note.show":
		if v, ok := r.Params["verbose"]; ok {
			if _, isBool := v.(bool); !isBool {
				return nil, a.refuse(ops.CodeParamsInvalid, "verbose must be true or false")
			}
		}
	case "note.add":
		s, ok := r.Params["text"].(string)
		if !ok || s == "" {
			return nil, a.refuse(ops.CodeParamsInvalid, "text is required, 1-20 bytes")
		}
		if len(s) > 20 && !a.d.noMaxCheck {
			return nil, a.refuse(ops.CodeParamsInvalid, "text is longer than 20 bytes")
		}
	}
	return r.Params, nil
}

// call sends one request to the service with the credential.
func (a *toyAdapter) call(method, path string, body any) (int, map[string]string, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, a.base+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.cred)
	if a.d.leakLog {
		slog.Info("calling the service", "authorization", req.Header.Get("Authorization"))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, errors.New("the service could not be asked")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]string
	_ = json.Unmarshal(raw, &m)
	if resp.StatusCode == http.StatusUnauthorized && a.d.relayBody {
		return resp.StatusCode, m, fmt.Errorf("the service answered %d: %s", resp.StatusCode, raw)
	}
	return resp.StatusCode, m, nil
}

func (a *toyAdapter) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	if _, err := a.parse(r); err != nil {
		return ops.CheckResult{}, err
	}
	if a.d.checkWrites {
		_, _, _ = a.call(http.MethodPost, "/notes", map[string]string{"id": "probe", "text": "x"})
	}
	return ops.CheckResult{Checks: []ops.Check{{Name: "target", Passed: true, Detail: r.Target.Ref}}}, nil
}

func (a *toyAdapter) Execute(_ context.Context, r *ops.Request) (ops.Outcome, error) {
	if !a.d.noExecuteRecheck {
		if _, err := a.parse(r); err != nil {
			return ops.Outcome{Failed: true, Result: map[string]any{"error": err.Error()}}, nil
		}
	}
	if a.op.Name == "note.show" {
		return a.show(r)
	}
	return a.add(r)
}

func failed(msg string) ops.Outcome {
	return ops.Outcome{Failed: true, Result: map[string]any{"error": msg}}
}

func (a *toyAdapter) show(r *ops.Request) (ops.Outcome, error) {
	if a.d.execWritesInShow {
		_, _, _ = a.call(http.MethodPost, "/notes", map[string]string{"id": "side", "text": "x"})
	}
	code, m, err := a.call(http.MethodGet, "/notes/"+r.Target.Ref, nil)
	if err != nil {
		return failed(err.Error()), nil
	}
	if code != http.StatusOK {
		return failed(fmt.Sprintf("the service answered %d", code)), nil
	}
	text := m["text"]
	if !a.d.noClean {
		text = strings.Map(func(r rune) rune {
			if r != '\n' && r != '\t' && (r < ' ' || unicode.Is(unicode.C, r)) {
				return ' '
			}
			return r
		}, text)
	}
	if !a.d.noCap && len(text) > 200 {
		text = text[:200]
	}
	if _, res := a.reg.Redact(text); res.Blocked() && !a.d.noWithhold {
		text = "[withheld: the text looks like a secret]"
	}
	res := map[string]any{"id": r.Target.Ref, "text": text}
	if !a.d.noFlag {
		res[conformance.UntrustedFlag] = true
	}
	if a.d.leakResult {
		res["debug"] = "auth " + a.cred
	}
	switch {
	case a.d.leakBase64:
		res["debug"] = base64.StdEncoding.EncodeToString([]byte("user:" + a.cred))
	case a.d.leakUpper:
		res["debug"] = strings.ToUpper(a.cred)
	case a.d.leakClipped:
		res["debug"] = a.cred[:30]
	case a.d.leakSplit:
		res["debug"], res["debug2"] = a.cred[:20], a.cred[20:]
	}
	return ops.Outcome{Result: res, ExternalRef: r.Target.Ref}, nil
}

func (a *toyAdapter) add(r *ops.Request) (ops.Outcome, error) {
	id := "note-" + r.ExecutionID
	if a.d.idFromCounter {
		id = fmt.Sprintf("note-%d", a.n.Add(1))
	}
	code, m, err := a.call(http.MethodPost, "/notes", map[string]string{"id": id, "text": r.Params["text"].(string)})
	if err != nil {
		return failed(err.Error()), nil
	}
	switch code {
	case http.StatusCreated:
	case http.StatusConflict:
		return failed("the service already has this note"), nil
	default:
		return failed(fmt.Sprintf("the service answered %d", code)), nil
	}
	res := map[string]any{"note_id": id}
	if a.d.echoBoard {
		res["board"] = m["board"]
	}
	return ops.Outcome{Result: res, ExternalRef: id}, nil
}

// toyConnector builds the suite's input for a toy with the defects d.
func toyConnector(d defects) conformance.Connector {
	req := func(op string, ref string, params map[string]any) func(*conformance.Rig) *ops.Request {
		return func(*conformance.Rig) *ops.Request {
			return &ops.Request{
				ID: "q-1", Op: op, Project: "demo", Target: spec.Target{Adapter: "toy", Ref: ref}, Params: params,
				Caller: &ops.Caller{Kind: ops.KindOrchestrator, OrchID: "main"},
			}
		}
	}
	asRun := func(op, ref string, params map[string]any) func(*conformance.Rig) *ops.Request {
		return func(r *conformance.Rig) *ops.Request {
			q := req(op, ref, params)(r)
			q.Caller = &ops.Caller{Kind: ops.KindRun, RunID: "r-1"}
			return q
		}
	}
	plantShow := func(r *conformance.Rig, p conformance.Planted) {
		r.World.(*toySvc).set(func() {
			r.World.(*toySvc).notes["n1"] = strings.Join([]string{p.Control, p.Long, p.Secret}, " ")
		})
	}
	plantAdd := func(r *conformance.Rig, p conformance.Planted) {
		r.World.(*toySvc).set(func() { r.World.(*toySvc).board = strings.Join([]string{p.Control, p.Long, p.Secret}, " ") })
	}
	return conformance.Connector{
		Declared: toyDecl,
		Pins:     toyPins,
		NewRig: func(t testing.TB, canary string) *conformance.Rig {
			svc := newToySvc(t, canary)
			cred := canary
			if d.ownCredential {
				cred = "own-credential-9f8e7d6c5b4a39281706"
				svc.set(func() { svc.secret = cred })
			}
			reg := redact.NewRegistry()
			counter := &atomic.Int64{}
			ads := map[string]ops.Adapter{}
			for _, o := range toyDecl.Ops {
				ads[o.Name] = &toyAdapter{op: o, base: svc.URL, cred: cred, d: d, reg: reg, n: counter}
			}
			rig := &conformance.Rig{
				Adapters:      ads,
				WriteCalls:    func() int { svc.mu.Lock(); defer svc.mu.Unlock(); return svc.writeCalls },
				WritesApplied: func() int { svc.mu.Lock(); defer svc.mu.Unlock(); return svc.applied },
				// Only what the service saw: a rig that reported the canary itself
				// would hide a connector that ignores it.
				Secrets: func() []string { svc.mu.Lock(); defer svc.mu.Unlock(); return append([]string(nil), svc.seen...) },
				Hostile: func() { svc.set(func() { svc.secret, svc.echo = "rotated-"+canary, true }) },
				World:   svc,
			}
			if d.blindCounters {
				rig.WriteCalls, rig.WritesApplied = func() int { return 0 }, func() int { return 0 }
			}
			if d.noHostile {
				rig.Hostile = nil
			}
			return rig
		},
		Ops: map[string]conformance.Op{
			"note.show": {
				Valid:    []conformance.Sample{{Name: "show n1", Req: req("note.show", "n1", nil)}, {Name: "show verbose", Req: req("note.show", "n1", map[string]any{"verbose": true})}},
				Invalid:  []conformance.Sample{{Name: "a run asks", Req: asRun("note.show", "n1", nil), Code: ops.CodePolicyRefused}, {Name: "bad ref", Req: req("note.show", "x1", nil), Code: ops.CodeParamsInvalid}},
				ReadOnly: true, Text: conformance.ServiceText, Plant: plantShow,
			},
			"note.add": {
				Valid:   []conformance.Sample{{Name: "add", Req: req("note.add", "n1", map[string]any{"text": "hello"})}},
				Invalid: []conformance.Sample{{Name: "a run asks", Req: asRun("note.add", "n1", map[string]any{"text": "hello"}), Code: ops.CodePolicyRefused}},
				Text:    conformance.NoServiceText, Plant: plantAdd,
			},
		},
	}
}

// ---- the tests --------------------------------------------------------------

func allOps() []string { return []string{"note.show", "note.add"} }

// A toy without defects passes every check of every operation.
func TestHealthyToyPassesEveryCheck(t *testing.T) {
	c := toyConnector(defects{})
	for _, op := range allOps() {
		for _, id := range conformance.Checks {
			if ps := conformance.Evaluate(t, c, op, id); len(ps) > 0 {
				t.Errorf("%s / %s: %v", op, id, ps)
			}
		}
	}
}

// Each defect must fail the check that is meant to catch it, for the operation
// it affects, and say something that names the cause.
func TestEachCheckBites(t *testing.T) {
	cases := []struct {
		name   string
		d      defects
		op     string
		check  conformance.CheckID
		expect string // a word the message must hold
	}{
		{"1 Check writes", defects{checkWrites: true}, "note.add", conformance.CheckNoSideEffects, "write call"},
		{"1 Check writes (read op)", defects{checkWrites: true}, "note.show", conformance.CheckNoSideEffects, "write call"},
		{"2 a fresh id on every Execute", defects{idFromCounter: true}, "note.add", conformance.CheckExecuteActsOnce, "same execution id"},
		{"2 a read that writes", defects{execWritesInShow: true}, "note.show", conformance.CheckExecuteActsOnce, "ReadOnly"},
		{"3 credential in a result", defects{leakResult: true}, "note.show", conformance.CheckNoSecretInOutput, "canary"},
		{"3 credential in the log", defects{leakLog: true}, "note.add", conformance.CheckNoSecretInOutput, "log"},
		{"3 service error body relayed", defects{relayBody: true}, "note.show", conformance.CheckNoSecretInOutput, "canary"},
		{"3 credential base64-encoded in a result", defects{leakBase64: true}, "note.show", conformance.CheckNoSecretInOutput, "canary"},
		{"3 credential in upper case in a result", defects{leakUpper: true}, "note.show", conformance.CheckNoSecretInOutput, "canary"},
		{"3 credential clipped in a result", defects{leakClipped: true}, "note.show", conformance.CheckNoSecretInOutput, "canary"},
		{"3 a rig that ignores the canary and leaks its own credential", defects{ownCredential: true, leakResult: true}, "note.show", conformance.CheckNoSecretInOutput, "credential the fake saw"},
		{"2 a fake that counts no writes", defects{blindCounters: true}, "note.add", conformance.CheckExecuteActsOnce, "proves nothing"},
		{"4 plain error", defects{plainError: true}, "note.add", conformance.CheckRefusalCodes, "not a *ops.Refusal"},
		{"4 invented code", defects{badCode: true}, "note.show", conformance.CheckRefusalCodes, "NOPE"},
		{"5 undeclared param accepted", defects{noParamCheck: true}, "note.show", conformance.CheckParamsAndLimits, "undeclared param"},
		{"5 limit not enforced", defects{noMaxCheck: true}, "note.add", conformance.CheckParamsAndLimits, "over the maximum"},
		{"5 Execute does not check again", defects{noExecuteRecheck: true}, "note.show", conformance.CheckParamsAndLimits, "Execute succeeded"},
		{"6 no untrusted flag", defects{noFlag: true}, "note.show", conformance.CheckServiceText, "untrusted_text"},
		{"6 control characters kept", defects{noClean: true}, "note.show", conformance.CheckServiceText, "control or format"},
		{"6 no cap", defects{noCap: true}, "note.show", conformance.CheckServiceText, "not capped"},
		{"6 secret-shaped text kept", defects{noWithhold: true}, "note.show", conformance.CheckServiceText, "withheld"},
		{"6 service text echoed by a write", defects{echoBoard: true}, "note.add", conformance.CheckServiceText, "no service text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := conformance.Evaluate(t, toyConnector(tc.d), tc.op, tc.check)
			if len(ps) == 0 {
				t.Fatalf("the check did not fail")
			}
			if !strings.Contains(strings.Join(ps, "\n"), tc.expect) {
				t.Fatalf("the check failed, but not as expected (%q): %v", tc.expect, ps)
			}
		})
	}
}

// Check 7: a declaration that differs from the pin, in class or reversibility,
// and an operation with no pin.
func TestClassMustMatchThePin(t *testing.T) {
	for name, mutate := range map[string]func(map[string]kit.Pin){
		"class":         func(p map[string]kit.Pin) { p["note.add"] = kit.Pin{Class: kit.Gated, Reversibility: kit.Compensable} },
		"reversibility": func(p map[string]kit.Pin) { p["note.add"] = kit.Pin{Class: kit.Routine, Reversibility: kit.Reversible} },
		"missing":       func(p map[string]kit.Pin) { delete(p, "note.add") },
	} {
		t.Run(name, func(t *testing.T) {
			c := toyConnector(defects{})
			pins := map[string]kit.Pin{}
			for k, v := range c.Pins {
				pins[k] = v
			}
			mutate(pins)
			c.Pins = pins
			if ps := conformance.Evaluate(t, c, "note.add", conformance.CheckClassMatchesPin); len(ps) == 0 {
				t.Fatal("the check did not fail")
			}
			if ps := conformance.Evaluate(t, c, "note.show", conformance.CheckClassMatchesPin); len(ps) != 0 {
				t.Fatalf("an unrelated operation fails: %v", ps)
			}
		})
	}
}

// The not-repeatable declaration is checked, not trusted: it is accepted when
// the second Execute does act again, and refused when it does not.
func TestNotRepeatableIsChecked(t *testing.T) {
	declared := toyConnector(defects{idFromCounter: true})
	add := declared.Ops["note.add"]
	add.NotRepeatable = "the toy service has no idempotency key"
	declared.Ops["note.add"] = add
	if ps := conformance.Evaluate(t, declared, "note.add", conformance.CheckExecuteActsOnce); len(ps) != 0 {
		t.Fatalf("a true declaration failed: %v", ps)
	}

	stale := toyConnector(defects{})
	add = stale.Ops["note.add"]
	add.NotRepeatable = "the toy service has no idempotency key"
	stale.Ops["note.add"] = add
	ps := conformance.Evaluate(t, stale, "note.add", conformance.CheckExecuteActsOnce)
	if len(ps) == 0 || !strings.Contains(strings.Join(ps, "\n"), "stale") {
		t.Fatalf("a stale declaration was accepted: %v", ps)
	}
}

// An operation declared ReadOnly whose samples never write is fine; one that is
// not declared ReadOnly and never writes proves nothing, and is refused.
func TestAWriteOperationMustWrite(t *testing.T) {
	c := toyConnector(defects{})
	show := c.Ops["note.show"]
	show.ReadOnly = false
	c.Ops["note.show"] = show
	ps := conformance.Evaluate(t, c, "note.show", conformance.CheckExecuteActsOnce)
	if len(ps) == 0 || !strings.Contains(strings.Join(ps, "\n"), "proves nothing") {
		t.Fatalf("a read declared as a write was accepted: %v", ps)
	}
}

// Connector.validate refuses an incomplete input: an operation with no samples
// cannot be skipped by leaving it out.
func TestRunRefusesAnIncompleteInput(t *testing.T) {
	c := toyConnector(defects{})
	delete(c.Ops, "note.add")
	got := conformance.Problems(c)
	if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), "note.add: no samples") {
		t.Fatalf("an operation with no samples was accepted: %v", got)
	}
	c = toyConnector(defects{})
	show := c.Ops["note.show"]
	show.Text = 0
	show.Plant = nil
	show.Known = map[conformance.CheckID]conformance.Gap{conformance.CheckNoSideEffects: {Reason: " ", Match: ""}}
	c.Ops["note.show"] = show
	joined := strings.Join(conformance.Problems(c), "\n")
	for _, want := range []string{"Text is not set", "Known[", "no Match"} {
		if !strings.Contains(joined, want) {
			t.Errorf("want %q in %s", want, joined)
		}
	}
}

// Run itself, on the healthy toy, as a connector's test calls it.
func TestRunOnTheHealthyToy(t *testing.T) {
	conformance.Run(t, toyConnector(defects{}))
}

// CleanedText holds an operation to clean and cap, and nothing more: the
// missing flag and the secret-shaped text that the strict kind refuses are
// accepted, a control character kept and a missing cap are not.
func TestCleanedTextAsksForCleanAndCapOnly(t *testing.T) {
	cleaned := func(d defects) conformance.Connector {
		c := toyConnector(d)
		show := c.Ops["note.show"]
		show.Text = conformance.CleanedText
		c.Ops["note.show"] = show
		return c
	}
	for name, d := range map[string]defects{"no flag": {noFlag: true}, "secret-shaped text kept": {noWithhold: true}} {
		if ps := conformance.Evaluate(t, cleaned(d), "note.show", conformance.CheckServiceText); len(ps) != 0 {
			t.Errorf("%s: CleanedText fails: %v", name, ps)
		}
	}
	for name, d := range map[string]defects{"control characters kept": {noClean: true}, "no cap": {noCap: true}} {
		if ps := conformance.Evaluate(t, cleaned(d), "note.show", conformance.CheckServiceText); len(ps) == 0 {
			t.Errorf("%s: CleanedText did not fail", name)
		}
	}
}

// A value split across two fields is not found. The guide says so; this test
// keeps the statement true.
func TestASplitCredentialIsNotFound(t *testing.T) {
	if ps := conformance.Evaluate(t, toyConnector(defects{leakSplit: true}), "note.show", conformance.CheckNoSecretInOutput); len(ps) != 0 {
		t.Fatalf("the suite found a split credential, so the guide's list of what is not found is out of date: %v", ps)
	}
}

// recorder is a testing.TB that keeps what is logged.
type recorder struct {
	testing.TB
	logs []string
}

func (r *recorder) Logf(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

// A rig with no hostile mode is allowed, but the suite says that the pass did
// not run.
func TestAMissingHostileModeIsLogged(t *testing.T) {
	rec := &recorder{TB: t}
	if ps := conformance.Evaluate(rec, toyConnector(defects{noHostile: true}), "note.show", conformance.CheckNoSecretInOutput); len(ps) != 0 {
		t.Fatal(ps)
	}
	if len(rec.logs) == 0 || !strings.Contains(rec.logs[0], "Rig.Hostile is nil") {
		t.Fatalf("no note that the hostile pass did not run: %v", rec.logs)
	}
	// And the defect the hostile pass exists for goes unseen without it.
	if ps := conformance.Evaluate(rec, toyConnector(defects{noHostile: true, relayBody: true}), "note.show", conformance.CheckNoSecretInOutput); len(ps) != 0 {
		t.Fatalf("expected the relay defect to pass without a hostile mode: %v", ps)
	}
}

// A Plant that plants nothing cannot make the strict text check pass: phase A
// sees that the words did not arrive, and phase B that the secret left no trace.
func TestANoOpPlantFailsAServiceTextOperation(t *testing.T) {
	c := toyConnector(defects{})
	show := c.Ops["note.show"]
	show.Plant = func(*conformance.Rig, conformance.Planted) {}
	c.Ops["note.show"] = show
	ps := strings.Join(conformance.Evaluate(t, c, "note.show", conformance.CheckServiceText), "\n")
	for _, want := range []string{"did not reach the result", "left no trace"} {
		if !strings.Contains(ps, want) {
			t.Errorf("want %q in %s", want, ps)
		}
	}
}

// A Plant that drops Secret but keeps Control still lets the secret reach the
// adapter in phase B, so a missing withhold is found.
func TestAPlantThatDropsSecretStillFindsAMissingWithhold(t *testing.T) {
	c := toyConnector(defects{noWithhold: true})
	show := c.Ops["note.show"]
	show.Plant = func(r *conformance.Rig, p conformance.Planted) {
		svc := r.World.(*toySvc)
		svc.set(func() { svc.notes["n1"] = p.Control + " " + p.Long })
	}
	c.Ops["note.show"] = show
	if ps := conformance.Evaluate(t, c, "note.show", conformance.CheckServiceText); !strings.Contains(strings.Join(ps, "\n"), "not withheld") {
		t.Fatalf("a missing withhold was not found: %v", ps)
	}
}
