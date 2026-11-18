package spec

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestParseStrictAcceptsOrdinaryDocuments(t *testing.T) {
	got, err := ParseStrict([]byte(`{"a":[1,2.5,-0,1e-7,"\u00e9\n"],"b":{"c":null,"d":true},"e":false,"__proto__":{"x":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	a := m["a"].([]any)
	if a[0] != 1.0 || a[1] != 2.5 || a[3] != 1e-7 || a[4] != "é\n" || !math.Signbit(a[2].(float64)) {
		t.Fatalf("a = %#v", a)
	}
	if _, ok := m["__proto__"].(map[string]any); !ok {
		t.Fatal("a __proto__ key is an ordinary member")
	}
	for _, lit := range []string{"9007199254740991", "9007199254740991.0", "-9007199254740991", "1.5e-300", "0.1", "1e-999"} {
		if _, err := ParseStrict([]byte(`{"n":` + lit + `}`)); err != nil {
			t.Errorf("%s refused: %v", lit, err)
		}
	}
	if v, err := ParseStrict([]byte(`"\ud83d\ude00"`)); err != nil || v != "😀" {
		t.Errorf("surrogate pair: %q %v", v, err)
	}
}

func TestParseStrictRejects(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	cases := []struct{ name, text, want string }{
		{"duplicate key", `{"method":"rebase","method":"squash"}`, "duplicate key 'method'"},
		{"duplicate key nested", `{"p":{"a":1,"a":2}}`, "duplicate key 'a'"},
		{"duplicate key in array", `[{"a":1,"a":1}]`, "duplicate key"},
		{"duplicate key by escape", `{"a":1,"\u0061":2}`, "duplicate key 'a'"},
		{"unsafe integer", `{"n":9007199254740993}`, "safe range"},
		{"2^53", `{"n":9007199254740992}`, "safe range"},
		{"negative unsafe integer", `{"n":-9007199254740993}`, "safe range"},
		{"fraction form", `{"n":9007199254740993.0}`, "safe range"},
		{"exponent form", `{"n":9.007199254740993e15}`, "safe range"},
		{"1e20", `{"n":1e20}`, "safe range"},
		{"-1e20", `{"n":-1e20}`, "safe range"},
		{"1.5e300", `{"n":1.5e300}`, "safe range"},
		{"scaled", `{"n":90071992547409930e-1}`, "safe range"},
		{"overflow", `{"n":1e999}`, "overflows"},
		{"lone high surrogate", `{"s":"\ud800"}`, "lone surrogate"},
		{"lone low surrogate", `{"s":"\udc00"}`, "lone surrogate"},
		{"reversed pair", `{"s":"\ude00\ud83d"}`, "lone surrogate"},
		{"high then letter", `{"s":"\ud83dx"}`, "lone surrogate"},
		{"invalid UTF-8", "{\"s\":\"\xff\"}", "UTF-8"},
		{"control character", "{\"s\":\"a\tb\"}", "control character"},
		{"bad escape", `{"s":"\x"}`, "invalid string"},
		{"short unicode escape", `{"s":"\u12"}`, "invalid string"},
		{"unterminated", `{"s":"abc`, "unterminated"},
		{"trailing content", `{} x`, "trailing"},
		{"two documents", `{} {}`, "trailing"},
		{"single quotes", `{'a':1}`, "string key"},
		{"trailing comma", `[1,]`, "unexpected"},
		{"leading zero", `[01]`, "expected"},
		{"bare minus", `[-]`, "unexpected"},
		{"empty", ``, "unexpected"},
		{"34 nested arrays", deep(MaxDepth + 2), "nesting deeper"},
		{"nan", `[NaN]`, "unexpected"},
	}
	for _, c := range cases {
		_, err := ParseStrict([]byte(c.text))
		if err == nil {
			t.Errorf("%s: accepted %q", c.name, c.text)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q lacks %q", c.name, err, c.want)
		}
	}
	// Depth boundary: the reference accepts 33 nested arrays and refuses 34.
	if _, err := ParseStrict([]byte(deep(MaxDepth + 1))); err != nil {
		t.Errorf("33 nested arrays refused: %v", err)
	}
	if _, err := ParseStrict([]byte(strings.Repeat("[", MaxDepth+1) + "1" + strings.Repeat("]", MaxDepth+1))); err == nil {
		t.Error("a scalar at depth 33 was accepted")
	}
	if _, err := ParseStrict([]byte(strings.Repeat("[", 100000))); err == nil {
		t.Error("deep input accepted")
	}
}

func TestJCS(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"b":2,"a":1}`, `{"a":1,"b":2}`},
		{` { "a" : [ 1 , 2 ] } `, `{"a":[1,2]}`},
		{`[0.5,100,-0,1e-7,1.5,0.1,5e-324,0.000001,1e-6,4.5,-1.5e-9,0.30000000000000004]`,
			`[0.5,100,0,1e-7,1.5,0.1,5e-324,0.000001,0.000001,4.5,-1.5e-9,0.30000000000000004]`},
		{`{"s":"\b\f\n\r\t\u0000\u001f\u007f\u2028 \"\\/ <>&"}`, "{\"s\":\"\\b\\f\\n\\r\\t\\u0000\\u001f\u007f\u2028 \\\"\\\\/ <>&\"}"},
		// UTF-16 order: U+FF5E (one unit 0xFF5E) sorts AFTER U+1F600 (units 0xD83D 0xDE00);
		// UTF-8 byte order would put it before.
		{`{"\uff5e":1,"\ud83d\ude00":2}`, "{\"\U0001F600\":2,\"\uff5e\":1}"},
		{`{"\u00e9":1,"e":2,"E":3,"":4}`, `{"":4,"E":3,"e":2,"é":1}`},
	}
	for _, c := range cases {
		tree, err := ParseStrict([]byte(c.in))
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		got, err := JCS(tree)
		if err != nil || string(got) != c.want {
			t.Errorf("%s:\n got %q (%v)\nwant %q", c.in, got, err, c.want)
		}
	}
}

func TestJCSRefuses(t *testing.T) {
	for name, v := range map[string]any{
		"NaN":              math.NaN(),
		"Inf":              math.Inf(1),
		"unsafe float":     float64(1 << 53),
		"unsafe int64":     int64(1) << 53,
		"unsafe neg int64": -(int64(1) << 53),
		"channel":          make(chan int),
		"invalid UTF-8":    "\xff",
		"invalid key":      map[string]any{"\xff": 1},
		"typed slice":      []string{"a"},
	} {
		if b, err := JCS(v); err == nil {
			t.Errorf("%s: encoded as %s", name, b)
		}
	}
	if b, err := JCS(int64(1)<<53 - 1); err != nil || string(b) != "9007199254740991" {
		t.Errorf("max safe int64: %s %v", b, err)
	}
	var deep any = "x"
	for range MaxDepth + 2 {
		deep = []any{deep}
	}
	if _, err := JCS(deep); err == nil {
		t.Error("over-deep tree encoded")
	}
}

func TestESNumber(t *testing.T) {
	for f, want := range map[float64]string{
		0: "0", 1: "1", -1: "-1", 0.1: "0.1", 1e21: "1e+21", 1e-7: "1e-7", 1e-6: "0.000001",
		123456789: "123456789", 1.5e-10: "1.5e-10", 2e-7: "2e-7", 1.2345e25: "1.2345e+25",
		9007199254740991: "9007199254740991", 100: "100", 1e20: "100000000000000000000",
	} {
		if got := esNumber(f); got != want {
			t.Errorf("esNumber(%v) = %s, want %s", f, got, want)
		}
	}
}

// An in-memory value is held to the same I-JSON rules as a parsed document.
func TestHashRefusesWhatLoadRefuses(t *testing.T) {
	req := map[string]any{
		"spec_version": "0", "project": "p", "op": "pr.merge",
		"target": map[string]any{"adapter": "a", "ref": "r"},
		"params": map[string]any{"n": int64(9007199254740993)},
	}
	if _, err := OpHash(req); err == nil || !strings.Contains(err.Error(), "safe range") {
		t.Fatalf("OpHash accepted an unsafe integer: %v", err)
	}
	req["params"] = map[string]any{"n": 1}
	h1, err := OpHash(req)
	if err != nil {
		t.Fatal(err)
	}
	req["params"] = map[string]any{"n": 1.0}
	if h2, _ := OpHash(req); h2 != h1 {
		t.Fatal("1 and 1.0 are the same number")
	}
	delete(req, "op")
	if _, err := OpHash(req); err == nil {
		t.Fatal("OpHash accepted a request without op")
	}
	req["op"] = "pr.merge"
	req["traceparent"] = "anything"
	req["op_hash"] = "x"
	if h3, _ := OpHash(req); h3 != h1 {
		t.Fatal("members outside the hashed five must not change op_hash")
	}
}

func TestApprovalChallengeBindsDecisionAndApprover(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"approval_id": "a-1", "request_id": "q-1", "op_hash": ZeroHash, "decision": "approved",
			"nonce": "n", "expires_at": "2026-10-23T23:41:00Z", "policy_version": "p1",
			"approver": map[string]any{"id": "user"}, "shown": map[string]any{"display_sha256": ZeroHash},
		}
	}
	h0, err := ApprovalChallenge(base())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"decision": func(m map[string]any) { m["decision"] = "denied" },
		"approver": func(m map[string]any) { m["approver"] = map[string]any{"id": "other"} },
		"run_id":   func(m map[string]any) { m["run_id"] = "r-abcd" },
		"display": func(m map[string]any) {
			m["shown"] = map[string]any{"display_sha256": "sha256:" + strings.Repeat("1", 64)}
		},
		"nonce": func(m map[string]any) { m["nonce"] = "m" },
	} {
		m := base()
		mutate(m)
		if h, _ := ApprovalChallenge(m); h == h0 {
			t.Errorf("changing %s does not change the challenge", name)
		}
	}
	m := base()
	delete(m, "shown")
	if _, err := ApprovalChallenge(m); err == nil {
		t.Error("challenge without shown accepted")
	}
}

func TestTraceparent(t *testing.T) {
	good := "00-" + strings.Repeat("a", 32) + "-" + strings.Repeat("b", 16) + "-01"
	if tp, ok := ParseTraceparent(good); !ok || tp.Flags != "01" {
		t.Fatal("valid traceparent refused")
	}
	for _, bad := range []string{
		"", good + "\n", good + "x", strings.ToUpper(good), "01" + good[2:],
		"00-" + strings.Repeat("0", 32) + "-" + strings.Repeat("b", 16) + "-01",
		"00-" + strings.Repeat("a", 32) + "-" + strings.Repeat("0", 16) + "-01",
		"00-" + strings.Repeat("a", 31) + "g-" + strings.Repeat("b", 16) + "-01",
		"00_" + good[3:],
	} {
		if _, ok := ParseTraceparent(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := TraceparentFor("r-7f3a", strings.Repeat("0", 16), "01"); err == nil {
		t.Error("zero parent id accepted")
	}
}

func TestVerifyChainFindsEachTamper(t *testing.T) {
	mk := func(seq int64, prev string, run string) map[string]any {
		e := map[string]any{
			"spec_version": "0", "chain": "chaperone.host1", "seq": float64(seq), "prev_hash": prev,
			"event_name": "grant", "attributes": map[string]any{},
			"trace_id": TraceID("chaperone.host1"),
		}
		if run != "" {
			e["run_id"], e["trace_id"] = run, TraceID(run)
		}
		h, err := EventHash(e)
		if err != nil {
			t.Fatal(err)
		}
		e["hash"] = h
		return e
	}
	e0 := mk(0, ZeroHash, "")
	e1 := mk(1, e0["hash"].(string), "r-abcd")
	e2 := mk(2, e1["hash"].(string), "")
	chain := func() []map[string]any {
		return []map[string]any{clone(t, e0), clone(t, e1), clone(t, e2)}
	}
	if p := VerifyChain(chain()); len(p) != 0 {
		t.Fatalf("intact chain: %v", p)
	}
	if p := VerifyChain([]map[string]any{clone(t, e2), clone(t, e0), clone(t, e1)}); len(p) != 0 {
		t.Fatalf("order of input must not matter: %v", p)
	}
	check := func(name string, events []map[string]any, wantSub string) {
		t.Helper()
		p := VerifyChain(events)
		if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), wantSub) {
			t.Errorf("%s: problems %v lack %q", name, p, wantSub)
		}
	}
	c := chain()
	c[1]["attributes"] = map[string]any{"x": "y"}
	check("edited", c, "hash does not match the event content")
	c = chain()
	check("deleted", []map[string]any{c[0], c[2]}, "expected seq 1")
	c = chain()
	c[1]["attributes"] = map[string]any{"x": "y"}
	c[1]["hash"], _ = EventHash(c[1])
	check("forged hash", c, "chain chaperone.host1 seq 2: prev_hash does not match")
	c = chain()
	c[1]["trace_id"] = TraceID("r-other")
	c[1]["hash"], _ = EventHash(c[1])
	c[2]["prev_hash"] = c[1]["hash"]
	c[2]["hash"], _ = EventHash(c[2])
	check("foreign trace", c, "trace_id is not derived")
	c = chain()
	c[2]["chain"] = "chaperone.pc2"
	check("mixed", c, "mixed chains")
	check("duplicate seq", []map[string]any{clone(t, e0), clone(t, e0)}, "gap or duplicate")
	check("head truncated", []map[string]any{clone(t, e1), clone(t, e2)}, "expected seq 0")
	if p := VerifyChain([]map[string]any{{"seq": "zero"}}); len(p) == 0 {
		t.Error("garbage event passed")
	}
}

func clone(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	tree, err := Tree(m)
	if err != nil {
		t.Fatal(err)
	}
	return tree.(map[string]any)
}

func TestContextGateFiles(t *testing.T) {
	for path, want := range map[string]bool{
		"AGENTS.md": true, "docs/AGENTS.md": true, "agents.md": true, "Docs/ClAuDe.MD": true,
		".agents/skills/x.txt": true, ".AGENTS/x": true, "a/b/c/SKILL.md": true,
		"src/agents.mdx": false, "docs/MY-AGENTS.md": false, ".agentsx/file": false, "SKILL.md.bak": false,
		"AGENTS.md\n": false, "a\nb/AGENTS.md": false, "AGENT\u212a.md": false, "SKILL.m\u017f": false,
		"x/.agents": false,
	} {
		if got := IsContextGateFile(path); got != want {
			t.Errorf("IsContextGateFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestOpAllowedAndUsage(t *testing.T) {
	allow := []string{"pr.open", "secrets.*"}
	for op, want := range map[string]bool{"pr.open": true, "pr.merge": false, "secrets.read": true, "secrets": false, "secretsx.read": false, "pr.open.x": false} {
		if OpAllowed(op, allow) != want {
			t.Errorf("OpAllowed(%q) != %v", op, want)
		}
	}
	if _, err := NormalizeUsage("bedrock", map[string]any{"input_tokens": 1.0, "output_tokens": 1.0}); err == nil {
		t.Error("an unchecked provider was normalized")
	}
	if _, err := NormalizeUsage("anthropic", map[string]any{"output_tokens": 1.0}); err == nil {
		t.Error("usage without input_tokens accepted")
	}
	got, err := NormalizeUsage("anthropic", map[string]any{"input_tokens": 600.0, "cache_read_input_tokens": 160200.0, "cache_creation_input_tokens": 22200.0, "output_tokens": 9100.0})
	if err != nil || !reflect.DeepEqual(got["gen_ai.usage.input_tokens"], int64(183000)) {
		t.Errorf("anthropic: %v %v", got, err)
	}
}
