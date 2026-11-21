package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/keys"
	"github.com/joshua-noel/chaperone/internal/policy"
	"github.com/joshua-noel/chaperone/internal/privfile"
)

// ---- the policy: the key operations are on in the playground and off everywhere else ----

func TestQuickstartTurnsOnTheKeyOpsAndNothingElse(t *testing.T) {
	cat, shipped, err := policy.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range keyOpsOn {
		if shipped.Ops[op].Enabled {
			t.Fatalf("the shipped baseline has %s on", op)
		}
	}
	data, err := quickstartBaseline(policy.BaselineBytes())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := policy.LoadBaseline(data, cat)
	if err != nil {
		t.Fatal(err)
	}
	for op, rule := range shipped.Ops {
		want := rule.Enabled || containsStr(keyOpsOn, op)
		if got := pack.Ops[op].Enabled; got != want {
			t.Errorf("%s: enabled = %v, want %v", op, got, want)
		}
		if pack.Ops[op].RatePerMinute != rule.RatePerMinute {
			t.Errorf("%s: the rate changed", op)
		}
	}
	// The shipped bytes were not touched, and `chapd run` / the service read them.
	if got, _ := quickstartBaseline(policy.BaselineBytes()); bytes.Equal(got, policy.BaselineBytes()) {
		t.Error("the quickstart baseline is the shipped one")
	}
	if _, base, _ := policy.Default(); base.Ops["keys.issue"].Enabled || base.Ops["keys.request"].Enabled || base.Ops["keys.extend"].Enabled {
		t.Error("turning the ops on in the quickstart changed the shipped baseline")
	}
	// Fail closed: an op that is not switched off exactly once is an error, not a no-op.
	if _, err := quickstartBaseline([]byte("ops:\n  keys.issue:           { enabled: false, rate_per_minute: 3 }\n")); err == nil {
		t.Error("a baseline without keys.request was accepted")
	}
	if _, err := quickstartBaseline(data); err == nil {
		t.Error("a baseline that has them on already was accepted")
	}
}

func containsStr(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// ---- the whole flow, with the passkey stand-in ----

// qsHarness is a quickstart with the passkey stand-in as the approvals verifier, and the app it built.
type qsHarness struct {
	t      *testing.T
	mu     sync.Mutex
	off    time.Duration
	app    *App
	addr   string
	dir    string
	origin string
}

func newQSHarness(t *testing.T) *qsHarness {
	t.Helper()
	h := &qsHarness{t: t, addr: qsFreeAddr(t), dir: filepath.Join(qsTemp(t), "qs")}
	_, port, _ := strings.Cut(h.addr, ":")
	h.origin = "http://localhost:" + port
	quickstartConfigHook = func(cfg *Config) {
		cfg.approvalVerifier = &helloStandIn{}
		cfg.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return time.Now().Add(h.off) }
	}
	quickstartAppHook = func(app *App) {
		if _, err := app.DB.SQL().Exec(`INSERT OR IGNORE INTO approvers (id, user_handle, name, created_at) VALUES (1, randomblob(32), 'operator', '2026-11-20T00:00:00Z')`); err != nil {
			t.Error(err)
		}
		h.mu.Lock()
		h.app = app
		h.mu.Unlock()
	}
	t.Cleanup(func() { quickstartConfigHook, quickstartAppHook = nil, nil })
	return h
}

// run starts the quickstart on the folder and waits for its output. stop() ends it.
func (h *qsHarness) run() (*qsRun, string) {
	h.t.Helper()
	r := startQuickstart(h.t, quickstartOptions{Dir: h.dir, Addr: h.addr})
	out := r.ready()
	return r, out
}

func (h *qsHarness) setOffset(d time.Duration) { h.mu.Lock(); h.off = d; h.mu.Unlock() }

func (h *qsHarness) theApp() *App {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.app
}

func (h *qsHarness) call(method, path, token string, body any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+h.addr+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return resp.StatusCode, m
}

// sign is the operator's passkey tap on a card, as the stand-in does it.
func (h *qsHarness) sign(approvalID string) {
	h.t.Helper()
	ctx := context.Background()
	app := h.theApp()
	ch, err := app.Approvals.BeginDecision(ctx, approvals.BeginInput{ApprovalID: approvalID, Actor: operator, Origin: h.origin, Binding: []byte("browser")})
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := app.Approvals.Approve(ctx, approvals.ApproveInput{ApprovalID: approvalID, ChallengeID: ch.ID, Actor: operator,
		Origin: h.origin, Binding: []byte("browser"), Response: answerFor(ch.Raw)}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *qsHarness) waitOp(opID string) {
	h.t.Helper()
	var last string
	for range 400 {
		st, err := h.theApp().Ops.OpState(context.Background(), opID)
		if err != nil {
			h.t.Fatal(err)
		}
		if last = st; st == "succeeded" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("op %s is %s", opID, last)
}

// writeKeyFile is what `chap agent enrol --out` does: a new private file (internal/privfile), the key in it.
func (h *qsHarness) writeKeyFile(token string) {
	h.t.Helper()
	f, err := privfile.Create(filepath.Join(h.dir, quickstartKeyFile))
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		h.t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		h.t.Fatal(err)
	}
}

// replaceKeyFile is what `chap key request --wait` does when the key is granted: write a new private file next to it, rename it over.
func (h *qsHarness) replaceKeyFile(token string) {
	h.t.Helper()
	path := filepath.Join(h.dir, quickstartKeyFile)
	tmp := path + ".new"
	f, err := privfile.Create(tmp)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		h.t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		h.t.Fatal(err)
	}
}

// enrol runs the agent's enrolment: the code, the operator's card, the request-only key. It returns the key id and token.
func (h *qsHarness) enrol(label string) (keyID, token string) {
	h.t.Helper()
	ctx := context.Background()
	st, start := h.call("POST", "/v0/agents/enrolments", "", map[string]any{"project": quickstartProject, "label": label})
	if st != http.StatusCreated {
		h.t.Fatalf("start enrolment: %d %v", st, start)
	}
	card, err := h.theApp().KeyDecider.ApproveEnrol(ctx, "operator", start["user_code"].(string))
	if err != nil {
		h.t.Fatal(err)
	}
	h.sign(card.ApprovalID)
	h.waitOp(card.OpID)
	st, poll := h.call("POST", "/v0/agents/enrolments/"+start["id"].(string)+"/poll", "", map[string]any{"device_code": start["device_code"]})
	if st != 200 || poll["state"] != "claimed" {
		h.t.Fatalf("poll: %d %v", st, poll)
	}
	token, _ = poll["token"].(string)
	keyID, _ = poll["key"].(map[string]any)["id"].(string)
	if !strings.HasPrefix(token, keys.Prefix) || keyID == "" {
		h.t.Fatalf("no key in %v", poll)
	}
	h.writeKeyFile(token)
	return keyID, token
}

// grantReads is `chap key request` as the playground prints it, then the operator's answer, then the claim. It returns the new key.
func (h *qsHarness) grantReads(boot string) (keyID, token string) {
	h.t.Helper()
	ctx := context.Background()
	asked := make([]any, len(quickstartKeyOps))
	for i, op := range quickstartKeyOps {
		asked[i] = op
	}
	st, op := h.call("POST", "/v0/ops", boot, map[string]any{
		"op": "keys.request", "reason": quickstartKeyReason,
		"target": map[string]any{"adapter": "chaperone", "ref": "key-request"},
		"params": map[string]any{"ops": asked, "units": []any{playgroundOwner + "/" + playgroundRepo}, "ttl_hours": 8, "rate_per_hour": 300},
	})
	res, _ := op["result"].(map[string]any)
	if st != 200 || res["request_id"] == nil {
		h.t.Fatalf("ask: %d %v", st, op)
	}
	id := res["request_id"].(string)
	card, err := h.theApp().KeyDecider.Grant(ctx, "operator", id, nil) // "Grant as asked"
	if err != nil {
		h.t.Fatal(err)
	}
	h.sign(card.ApprovalID)
	h.waitOp(card.OpID)
	_, rq := h.call("GET", "/v0/keys/requests/"+id, boot, nil)
	keyID, _ = rq["key_id"].(string)
	if rq["state"] != "granted" || keyID == "" {
		h.t.Fatalf("the request after the card: %v", rq)
	}
	st, claimed := h.call("POST", "/v0/keys/"+keyID+"/claim", boot, nil)
	if st != 200 {
		h.t.Fatalf("claim: %d %v", st, claimed)
	}
	token, _ = claimed["token"].(string)
	h.replaceKeyFile(token)
	return keyID, token
}

func (h *qsHarness) keyFileExists() bool {
	_, err := os.Stat(filepath.Join(h.dir, quickstartKeyFile))
	return err == nil
}

func mustHave(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("the output does not say %q:\n%s", w, out)
		}
	}
}

func mustNotHave(t *testing.T, out string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(out, n) {
			t.Errorf("the output says %q:\n%s", n, out)
		}
	}
}

const enrolCmd = "chap agent enrol --label "
const requestCmd = "chap key request --ops pr.checks,pr.diff,pr.files,pr.view --repo playground/storefront --ttl 8h"

// The flow, and what a folder does with an existing key: none, request-only, valid, revoked, expired, stopped by a human, unknown.
func TestQuickstartAgentKeyFlowAndExistingKeys(t *testing.T) {
	h := newQSHarness(t)

	// ---- run 1: no key. The output teaches the real flow, and hands the agent a KEY file, not the orchestrator token.
	r1, out1 := h.run()
	_, resolved, err := resolveFolderPath(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(resolved, quickstartKeyFile)
	mustHave(t, out1,
		enrolCmd+"playground-agent --project playground --out "+keyFile,
		requestCmd, "Look up the agent", "Make the enrolment card", "Grant as asked", h.origin+"/agents", "A key can never hold pr.merge",
		"The merge demo uses the ORCHESTRATOR token")
	mcp := lineWith(out1, "claude mcp add")
	if !strings.Contains(mcp, "CHAP_KEY_FILE="+keyFile) || strings.Contains(mcp, "ORCHESTRATOR") || strings.Contains(mcp, "orchestrator.token") {
		t.Errorf("the claude mcp add line does not use the key file alone: %s", mcp)
	}
	if !strings.Contains(out1, "CHAP_ORCHESTRATOR_TOKEN_FILE") {
		t.Error("the operator's section does not set the orchestrator token file")
	}
	// The orchestrator token is in the operator's section only: no agent line sets it.
	agentPart := out1[:strings.Index(out1, "As YOU, the operator")]
	mustNotHave(t, agentPart, "CHAP_ORCHESTRATOR_TOKEN_FILE", "orchestrator.token")
	if h.keyFileExists() {
		t.Fatal("the quickstart made the key file itself: a key nobody approved")
	}

	// Enrolment: a request-only key that can only ask.
	_, boot := h.enrol("playground-agent")
	if st, body := h.call("POST", "/v0/ops", boot, h.viewBody(3)); st != http.StatusForbidden {
		t.Errorf("pr.view under a request-only key: %d %v", st, body)
	}
	// What the agent asks for, the operator grants; the key in the file is replaced.
	keyID, key := h.grantReads(boot)

	// A key reads, and can never merge: pr.merge is not in the key ceiling.
	if st, v := h.call("POST", "/v0/ops", key, h.viewBody(3)); st != 200 || v["outcome"] != "succeeded" {
		t.Fatalf("pr.view under the granted key: %d %v", st, v)
	}
	for _, op := range quickstartKeyOps[:3] {
		if st, body := h.call("POST", "/v0/ops", key, map[string]any{"op": op, "project": quickstartProject,
			"target": map[string]any{"adapter": "github", "ref": "playground/storefront#3"}, "params": map[string]any{}}); st == http.StatusForbidden {
			t.Errorf("%s was refused to a key that holds it: %v", op, body)
		}
	}
	st, body := h.call("POST", "/v0/ops", key, map[string]any{"op": "pr.merge", "project": quickstartProject, "reason": "x",
		"target": map[string]any{"adapter": "github", "ref": "playground/storefront#3"},
		"params": map[string]any{"base": "main", "head_sha": strings.Repeat("a", 40), "method": "squash"}})
	if st != http.StatusForbidden {
		t.Fatalf("a key asked for pr.merge: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_NOT_IN_TOKEN")
	// The key cannot ask for a merge card either, nor use the orchestrator's other ops.
	if st, body := h.call("POST", "/v0/approvals", key, map[string]any{"kind": "op", "op": "pr.merge", "project": quickstartProject, "reason": "x",
		"target": map[string]any{"adapter": "github", "ref": "playground/storefront#3"},
		"params": map[string]any{"base": "main", "head_sha": strings.Repeat("a", 40), "method": "squash"}}); st != http.StatusForbidden {
		t.Errorf("a key made a merge card: %d %v", st, body)
	}
	// What the key sees of the catalog: the four reads (and the ask), nothing of the orchestrator's.
	st, cat := h.call("GET", "/v0/catalog", key, nil)
	if st != 200 {
		t.Fatalf("catalog under the key: %d %v", st, cat)
	}
	raw, _ := json.Marshal(cat)
	for _, op := range quickstartKeyOps {
		if !bytes.Contains(raw, []byte(`"`+op+`"`)) {
			t.Errorf("the key's catalog lacks %s: %s", op, raw)
		}
	}
	if bytes.Contains(raw, []byte(`"pr.merge"`)) {
		t.Errorf("the key's catalog lists pr.merge: %s", raw)
	}

	// The operator's own token (orchestrator) still plays the merge: refused, then a card.
	tok := h.orchToken()
	st, body = h.call("POST", "/v0/ops", tok, h.mergeBody(out1))
	if st != http.StatusForbidden {
		t.Fatalf("direct merge: %d %v", st, body)
	}
	mustValidDenial(t, body, "OP_APPROVAL_REQUIRED")
	if err := r1.stop(); err != nil {
		t.Fatal(err)
	}

	// ---- run 2: a valid key. Nothing to do for the agent; the commands are not printed again.
	r2, out2 := h.run()
	mustHave(t, out2, "The agent already has a key of its own (playground-agent)", "It can: pr.checks, pr.diff, pr.files, pr.view", "Nothing to do here")
	mustNotHave(t, out2, enrolCmd, "chap key request --ops", "/enroll#")
	if !h.keyFileExists() {
		t.Error("a valid key's file was removed")
	}
	// The key still works after the restart (the database was reused).
	if st, v := h.call("POST", "/v0/ops", key, h.viewBody(3)); st != 200 || v["outcome"] != "succeeded" {
		t.Errorf("the key after a restart: %d %v", st, v)
	}
	// ---- revoke it (by a token, not by a human): run 3 says revoked, removes the file, and the same label enrols again.
	if _, err := h.theApp().Keys.Revoke(context.Background(), keyID, "operator", false); err != nil {
		t.Fatal(err)
	}
	if err := r2.stop(); err != nil {
		t.Fatal(err)
	}
	r3, out3 := h.run()
	mustHave(t, out3, "was revoked, so it was removed", enrolCmd+"playground-agent --project playground")
	if h.keyFileExists() {
		t.Error("the file of a revoked key was kept, so `chap agent enrol --out` would refuse it")
	}
	// ---- enrol again, to let it expire: run 4.
	_, boot2 := h.enrol("playground-agent")
	_ = boot2
	if err := r3.stop(); err != nil {
		t.Fatal(err)
	}
	h.setOffset(31 * 24 * time.Hour) // a request-only key lives 30 days: the next start finds it expired
	r4, out4 := h.run()
	mustHave(t, out4, "was expired, so it was removed", enrolCmd+"playground-agent --project playground")
	if h.keyFileExists() {
		t.Error("the file of an expired key was kept")
	}
	// ---- enrol again; the operator stops the agent for good (Agents -> Revoke): run 5 uses a new name.
	id5, _ := h.enrol("playground-agent")
	if k, err := h.theApp().KeyDecider.Revoke(context.Background(), "operator", id5); err != nil || !k.StoppedByHuman {
		t.Fatalf("stop: %+v %v", k, err)
	}
	if err := r4.stop(); err != nil {
		t.Fatal(err)
	}
	r5, out5 := h.run()
	mustHave(t, out5, "A person stopped the agent of an earlier start for good", "so this start uses a new name: playground-agent-2",
		enrolCmd+"playground-agent-2 --project playground")
	if h.keyFileExists() {
		t.Error("the file of a stopped agent's key was kept")
	}
	// The new name really can be enrolled; the old one cannot.
	if _, _ = h.enrol("playground-agent-2"); !h.keyFileExists() {
		t.Error("no key file after enrolling the new name")
	}
	if err := r5.stop(); err != nil {
		t.Fatal(err)
	}
	// ---- run 6: a request-only key is valid: only step b is printed.
	r6, out6 := h.run()
	mustHave(t, out6, "holds a key that can only ask", requestCmd)
	mustNotHave(t, out6, enrolCmd)
	if err := r6.stop(); err != nil {
		t.Fatal(err)
	}
	// ---- run 7: a file that holds something that is not this database's key.
	for _, junk := range []string{"not a key at all", keys.Prefix + strings.Repeat("A", 43)} {
		_ = os.Remove(filepath.Join(h.dir, quickstartKeyFile)) // the earlier pass removed it
		h.writeKeyFile(junk)
		r7, out7 := h.run()
		mustHave(t, out7, "so it was removed", enrolCmd)
		if h.keyFileExists() {
			t.Errorf("the file of an unknown key (%q) was kept", junk[:4])
		}
		if err := r7.stop(); err != nil {
			t.Fatal(err)
		}
	}
}

func lineWith(out, sub string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

func (h *qsHarness) viewBody(n int) map[string]any {
	return map[string]any{"op": "pr.view", "project": quickstartProject,
		"target": map[string]any{"adapter": "github", "ref": fmt.Sprintf("playground/storefront#%d", n)}, "params": map[string]any{}}
}

func (h *qsHarness) orchToken() string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.dir, quickstartTokenFile))
	if err != nil {
		h.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

var mergeHeadRE = regexp.MustCompile(`chap pr merge 3 --head ([0-9a-f]{40}) `)

func (h *qsHarness) mergeBody(out string) map[string]any {
	m := mergeHeadRE.FindStringSubmatch(out)
	if m == nil {
		h.t.Fatalf("no merge command in\n%s", out)
	}
	return map[string]any{"op": "pr.merge", "project": quickstartProject, "reason": "reword the checkout button",
		"target": map[string]any{"adapter": "github", "ref": "playground/storefront#3"},
		"params": map[string]any{"base": "main", "head_sha": m[1], "method": "squash"}}
}

// The key file is in the folder's list of known entries (and its temporary name), and is trusted like the others: another
// user's or an open one is refused on a reused folder.
func TestQuickstartKeyFileIsAKnownEntryAndMustBePrivate(t *testing.T) {
	for _, name := range []string{quickstartKeyFile, quickstartKeyFile + ".new"} {
		if !isKnownEntry(name) {
			t.Errorf("%s is not a known top-level entry", name)
		}
	}
	dir, st := madeAndPrepared(t, "127.0.0.1:55456")
	path := filepath.Join(dir, quickstartKeyFile)
	f, err := privfile.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("x\n")
	f.Close()
	if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err != nil {
		t.Fatalf("a private key file was refused: %v", err)
	}
	makeWorldWritable(t, path)
	if _, err := prepareQuickstartFolder(dir, st, "", time.Now()); err == nil || !strings.Contains(err.Error(), "will not use") || !strings.Contains(err.Error(), quickstartKeyFile) {
		t.Errorf("a key file open to others was accepted: %v", err)
	}
}

// ---- the same flow with the real chap binary (the passkey tap stays the stand-in) ----

// TestQuickstartWithTheRealChap runs the commands the quickstart prints with a real `chap`, from the CHAP_BIN environment
// variable (a built chap). It is skipped without it: the build of chap is the caller's, not this package's.
//
//	chap agent enrol (the test types the code and signs the card) -> the key file in the folder -> chap key request --wait
//	(the test grants and signs) -> chap pr view works, chap pr merge is refused -> chap manual and `chap mcp` list only what
//	the key may do.
func TestQuickstartWithTheRealChap(t *testing.T) {
	bin := os.Getenv("CHAP_BIN")
	if bin == "" {
		t.Skip("set CHAP_BIN to a built chap to run the printed commands")
	}
	h := newQSHarness(t)
	r, out := h.run()
	defer r.stop()
	_, resolved, err := resolveFolderPath(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(resolved, quickstartKeyFile)
	env := append(os.Environ(), "CHAP_URL=http://"+h.addr, "CHAP_KEY_FILE="+keyFile)
	for _, k := range []string{"CHAP_RUN_TOKEN", "CHAP_PROJECT", "CHAP_ORCHESTRATOR_TOKEN_FILE"} {
		env = append(env, k+"=")
	}
	// printed returns the arguments of the printed command that starts with prefix.
	printed := func(prefix string) []string {
		l := strings.TrimSpace(lineWith(out, prefix))
		if l == "" {
			t.Fatalf("the output has no %q line:\n%s", prefix, out)
		}
		return shellFields(strings.TrimPrefix(l, "chap "))
	}

	// 1. chap agent enrol, exactly as printed: it prints a code; the test is the operator.
	enrol := exec.Command(bin, printed("chap agent enrol")...)
	enrol.Env = env
	pipe, _ := enrol.StdoutPipe()
	var errb bytes.Buffer
	enrol.Stderr = &errb
	if err := enrol.Start(); err != nil {
		t.Fatal(err)
	}
	codeRE := regexp.MustCompile(`\b[A-Z0-9]{4}-[A-Z0-9]{4}\b`)
	var code string
	var seen bytes.Buffer
	buf := make([]byte, 4096)
	for code == "" {
		n, err := pipe.Read(buf)
		seen.Write(buf[:n])
		code = codeRE.FindString(seen.String())
		if err != nil {
			break
		}
	}
	if code == "" {
		t.Fatalf("chap agent enrol printed no code:\n%s\n%s", seen.String(), errb.String())
	}
	go io.Copy(io.Discard, pipe)
	card, err := h.theApp().KeyDecider.ApproveEnrol(context.Background(), "operator", code)
	if err != nil {
		t.Fatal(err)
	}
	h.sign(card.ApprovalID)
	if err := enrol.Wait(); err != nil {
		t.Fatalf("chap agent enrol: %v\n%s", err, errb.String())
	}
	if st, err := os.Stat(keyFile); err != nil || st.Size() == 0 {
		t.Fatalf("no key file after enrol: %v", err)
	}

	// 2. chap key request, as printed, with --wait: the test answers as the operator.
	req := exec.Command(bin, printed("chap key request")...)
	req.Env = env
	var rout, rerr bytes.Buffer
	req.Stdout, req.Stderr = &rout, &rerr
	if err := req.Start(); err != nil {
		t.Fatal(err)
	}
	var reqID string
	for range 200 {
		if l, _ := h.theApp().KeyDecider.Pending(context.Background(), "operator"); len(l) == 1 {
			reqID = l[0].ID
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatalf("chap key request made no request:\n%s\n%s", rout.String(), rerr.String())
	}
	gc, err := h.theApp().KeyDecider.Grant(context.Background(), "operator", reqID, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.sign(gc.ApprovalID)
	h.waitOp(gc.OpID)
	if err := req.Wait(); err != nil {
		t.Fatalf("chap key request: %v\n%s\n%s", err, rout.String(), rerr.String())
	}

	// 3. The agent reads, and cannot merge; what it is shown is what it may do.
	run := func(args ...string) (string, int) {
		c := exec.Command(bin, args...)
		c.Env = env
		o, err := c.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(o), code
	}
	if o, code := run("pr", "view", "3", "--repo", "playground/storefront"); code != 0 || !strings.Contains(o, "succeeded") {
		t.Errorf("chap pr view under the key: %d\n%s", code, o)
	}
	m := mergeHeadRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatal("no merge command printed")
	}
	if o, code := run("pr", "merge", "3", "--head", m[1], "--base", "main", "--repo", "playground/storefront"); code != 3 || !strings.Contains(o, "OP_NOT_IN_TOKEN") {
		t.Errorf("chap pr merge under the key: %d\n%s", code, o)
	}
	manual, rc := run("manual")
	if rc != 0 {
		t.Fatalf("chap manual under the key: %d\n%s", rc, manual)
	}
	for _, op := range quickstartKeyOps {
		if !strings.Contains(manual, op) {
			t.Errorf("chap manual under the key lacks %s:\n%s", op, manual)
		}
	}
	if strings.Contains(manual, "pr.merge") {
		t.Errorf("chap manual under the key lists pr.merge:\n%s", manual)
	}

	// 4. chap mcp, as the printed claude mcp add line starts it: CHAP_URL and CHAP_KEY_FILE only, no CHAP_PROJECT.
	mc := exec.Command(bin, "mcp")
	mc.Env = env
	mc.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	var mout, merr bytes.Buffer
	mc.Stdout, mc.Stderr = &mout, &merr
	done := make(chan error, 1)
	if err := mc.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- mc.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = mc.Process.Kill()
		<-done
	}
	tools := mout.String()
	for _, tool := range []string{"pr_view", "pr_diff", "pr_checks", "pr_files"} {
		if !strings.Contains(tools, `"`+tool+`"`) {
			t.Errorf("chap mcp under the key lacks the tool %s:\n%s\n%s", tool, tools, merr.String())
		}
	}
	for _, tool := range []string{"pr_merge", "pr_open", "deploy"} {
		if strings.Contains(tools, `"`+tool+`"`) {
			t.Errorf("chap mcp under the key shows %s", tool)
		}
	}
	if got, want := strings.Join(toolNames(tools), ","), "chaperone_manual,chaperone_op_status,keys_request,pr_checks,pr_diff,pr_files,pr_view"; got != want {
		t.Errorf("tools under the key: %s, want %s", got, want)
	}

	// The operator's own terminal: the orchestrator token lists pr_merge and has no keys_request.
	om := exec.Command(bin, "mcp")
	om.Env = append(env, "CHAP_KEY_FILE=", "CHAP_PROJECT="+quickstartProject, "CHAP_ORCHESTRATOR_TOKEN_FILE="+filepath.Join(resolved, quickstartTokenFile))
	om.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	ob, _ := om.Output()
	if got, want := strings.Join(toolNames(string(ob)), ","), "chaperone_manual,chaperone_op_status,pr_checks,pr_diff,pr_files,pr_merge,pr_view"; got != want {
		t.Errorf("tools under the orchestrator token: %s, want %s", got, want)
	}
}

// shellFields splits a printed command line the way a shell does for the one thing the quickstart prints: words, and
// double-quoted words.
func shellFields(s string) []string {
	var out []string
	var cur strings.Builder
	quoted, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted, has = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

// toolNames lists the tool names in a tools/list reply.
func toolNames(reply string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`"name":"([a-z_]+)"`).FindAllStringSubmatch(reply, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}
