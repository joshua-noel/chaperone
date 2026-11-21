package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshua-noel/chaperone/internal/keys"
)

// The two routes of agent enrolment need no credential: the agent has none yet. These tests run what bounds them,
// against the real handler: how many enrolments may wait, what a process on the machine can do with the free
// slots, the lock on wrong codes, which requests the routes take, and what they say.

// enrolRaw posts to an enrolment route with exactly the headers given (no default Content-Type).
func (e *agentE2E) enrolRaw(path, host string, header map[string]string, body string) (int, string) {
	e.t.Helper()
	req, err := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Host = host
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func (e *agentE2E) startRaw(label string) (int, map[string]any) {
	e.t.Helper()
	return e.call("POST", "/v0/agents/enrolments", "", map[string]any{"project": "storefront", "label": label})
}

func (e *agentE2E) pendingEnrolments() int {
	e.t.Helper()
	var n int
	if err := e.app.DB.SQL().QueryRow(`SELECT COUNT(*) FROM key_enrolments WHERE state = 'pending'`).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *agentE2E) advance(d time.Duration) {
	e.now.mu.Lock()
	e.now.t = e.now.t.Add(d)
	e.now.mu.Unlock()
}

// Forty callers start an enrolment at once, each with its own label: exactly the cap is admitted, the rest are
// told to wait, and the table never holds more than the cap.
func TestEnrolmentCapHoldsUnderConcurrentStarts(t *testing.T) {
	e := newAgentE2E(t)
	const callers = 40
	var wg sync.WaitGroup
	codes := make([]int, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _ = e.startRaw(fmt.Sprintf("agent%d", i))
		}()
	}
	wg.Wait()
	made, refused := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			made++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if made != keys.MaxPendingEnrolments || refused != callers-keys.MaxPendingEnrolments {
		t.Errorf("%d admitted and %d refused, want %d and %d", made, refused, keys.MaxPendingEnrolments, callers-keys.MaxPendingEnrolments)
	}
	if n := e.pendingEnrolments(); n != keys.MaxPendingEnrolments {
		t.Errorf("%d enrolments wait, the cap is %d", n, keys.MaxPendingEnrolments)
	}
	// One label waits once, however many ask at once.
	var wg2 sync.WaitGroup
	same := make([]int, 10)
	e.advance(keys.EnrolLife + time.Second)
	for i := range same {
		wg2.Add(1)
		go func() { defer wg2.Done(); same[i], _ = e.startRaw("scout") }()
	}
	wg2.Wait()
	made = 0
	for _, c := range same {
		if c == http.StatusCreated {
			made++
		}
	}
	if made != 1 {
		t.Errorf("%d enrolments for one label were made at once, want 1", made)
	}
}

// What a process on the machine can do with no credential: fill the slots, or take the one label of the agent it
// wants to block. The real agent is refused until those enrolments expire (ten minutes). Nothing can stop that (a
// per-source limit cannot work on loopback), so it is made visible: the refusal is written to the log and the ledger
// (once a minute for each label), and the waiting enrolments are listed for the operator, who can cancel them (the Agents page).
// This test pins what happens, so a change to it is a decision.
func TestAProcessOnTheMachineCanBlockEnrolmentForTenMinutesAndTheOperatorSeesIt(t *testing.T) {
	e := newAgentE2E(t)
	before := e.ledgerEvents()
	// Squat on the label the real agent will use.
	if st, _ := e.startRaw("scout"); st != http.StatusCreated {
		t.Fatalf("squat: %d", st)
	}
	st, body := e.startRaw("scout")
	if st != http.StatusConflict {
		t.Errorf("the real agent while its label is squatted: %d %v", st, body)
	}
	// Or fill every slot.
	for i := 1; i < keys.MaxPendingEnrolments; i++ {
		if st, _ := e.startRaw(fmt.Sprintf("filler%d", i)); st != http.StatusCreated {
			t.Fatalf("filler %d: %d", i, st)
		}
	}
	if st, _ := e.startRaw("other"); st != http.StatusTooManyRequests {
		t.Errorf("a different agent while the slots are full: %d", st)
	}
	// Two refusals for two labels came within a minute: each is written down (a request and a result event), because
	// the limit is per label: the squatter's refusals must not hide the real agent's.
	if after := e.ledgerEvents(); after-before != 4 {
		t.Errorf("refused enrolment starts wrote %d ledger events, want the 4 of two refusals", after-before)
	}
	var refused int
	e.app.DB.SQL().QueryRow(`SELECT count(*) FROM ledger_events WHERE event_name = 'op.result' AND event LIKE '%ENROLMENT_REFUSED%'`).Scan(&refused)
	if refused != 2 {
		t.Errorf("%d refused-enrolment results in the ledger, want 2", refused)
	}
	// The waiting enrolments are listed for the operator, with the name each one asked for.
	waiting, err := e.app.KeyDecider.WaitingEnrolments(context.Background())
	labels := map[string]bool{}
	for _, w := range waiting {
		labels[w.Label] = true
	}
	if err != nil || len(waiting) != keys.MaxPendingEnrolments || !labels["scout"] {
		t.Errorf("waiting enrolments: %+v %v", waiting, err)
	}
	// Nine minutes later it is still blocked; after the ten the real agent gets through.
	e.advance(keys.EnrolLife - time.Minute)
	if st, _ := e.startRaw("scout"); st == http.StatusCreated {
		t.Error("the squatted label was free before the enrolment expired")
	}
	e.advance(time.Minute + time.Second)
	if st, _ := e.startRaw("scout"); st != http.StatusCreated {
		t.Errorf("after the expiry the real agent is still refused: %d", st)
	}
}

func (e *agentE2E) ledgerEvents() int {
	e.t.Helper()
	var n int
	if err := e.app.DB.SQL().QueryRow(`SELECT COUNT(*) FROM ledger_events`).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// The lock on wrong codes counts the person who types them, not the enrolment: starting new enrolments, or
// letting the old ones expire, does not give the person a fresh count, and the right code is refused while locked.
func TestWrongCodeLockSurvivesNewEnrolments(t *testing.T) {
	e := newAgentE2E(t)
	ctx := context.Background()
	d := e.app.KeyDecider
	for i := range 5 {
		if _, err := d.LookupEnrol(ctx, "operator", fmt.Sprintf("AAAA-AAA%c", 'A'+i)); !errors.Is(err, keys.ErrNotFound) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	// A new enrolment, started by anyone, is not a reset.
	st, start := e.startRaw("scout")
	if st != http.StatusCreated {
		t.Fatalf("start: %d %v", st, start)
	}
	code, _ := start["user_code"].(string)
	if _, err := d.LookupEnrol(ctx, "operator", code); !errors.Is(err, keys.ErrCodeLocked) {
		t.Errorf("the right code of a new enrolment while locked: %v", err)
	}
	if _, err := d.ApproveEnrol(ctx, "operator", code); !errors.Is(err, keys.ErrCodeLocked) {
		t.Errorf("approving through the locked box: %v", err)
	}
	// A guess made through the card path counts as well: it goes through the same lookup.
	if n := e.pendingEnrolments(); n != 1 {
		t.Errorf("%d enrolments wait", n)
	}
	// Another person is not locked out by it.
	if _, err := d.LookupEnrol(ctx, "someone-else", code); err != nil {
		t.Errorf("another person: %v", err)
	}
}

// The routes take what the agent's command line sends and nothing else: the Host the rest of the API answers to,
// no Origin (a web page always sends one), a JSON body and no credential.
func TestEnrolmentRoutesRefuseWhatAWebPageOrAnotherHostSends(t *testing.T) {
	e := newAgentE2E(t)
	good := `{"project":"storefront","label":"scout"}`
	json := map[string]string{"Content-Type": "application/json"}
	for name, c := range map[string]struct {
		host   string
		header map[string]string
		want   int
	}{
		"a rebinding host":        {"evil.example:55398", json, http.StatusMisdirectedRequest},
		"another port":            {"127.0.0.1:9999", json, http.StatusMisdirectedRequest},
		"a web page":              {"127.0.0.1:55398", map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example"}, http.StatusForbidden},
		"a web page, same origin": {"127.0.0.1:55398", map[string]string{"Content-Type": "application/json", "Origin": "http://127.0.0.1:55398"}, http.StatusForbidden},
		"no content type":         {"127.0.0.1:55398", nil, http.StatusUnsupportedMediaType},
		"a text/plain post":       {"127.0.0.1:55398", map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType},
		"a form post":             {"127.0.0.1:55398", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusUnsupportedMediaType},
		"a credential":            {"127.0.0.1:55398", map[string]string{"Content-Type": "application/json", "Authorization": "Bearer x"}, http.StatusBadRequest},
		"the same call, properly": {"127.0.0.1:55398", json, http.StatusCreated},
	} {
		st, body := e.enrolRaw("/v0/agents/enrolments", c.host, c.header, good)
		if st != c.want {
			t.Errorf("%s: %d %s, want %d", name, st, body, c.want)
		}
	}
	if n := e.pendingEnrolments(); n != 1 {
		t.Errorf("%d enrolments were made by the nine calls, want only the proper one", n)
	}
	// The poll route has the same rules.
	st, start := e.startRaw("second")
	if st != http.StatusCreated {
		t.Fatal(st)
	}
	poll := fmt.Sprintf(`{"device_code":%q}`, start["device_code"])
	path := "/v0/agents/enrolments/" + start["id"].(string) + "/poll"
	if st, body := e.enrolRaw(path, "127.0.0.1:55398", map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example"}, poll); st != http.StatusForbidden {
		t.Errorf("a poll from a web page: %d %s", st, body)
	}
	if st, body := e.enrolRaw(path, "evil.example:55398", json, poll); st != http.StatusMisdirectedRequest {
		t.Errorf("a poll on another host: %d %s", st, body)
	}
	if st, body := e.enrolRaw(path, "127.0.0.1:55398", nil, poll); st != http.StatusUnsupportedMediaType {
		t.Errorf("a poll with no content type: %d %s", st, body)
	}
}

// What the routes say tells nothing about keys, approvers or other enrolments.
func TestEnrolmentRoutesLeakNothingAboutKeysOrApprovers(t *testing.T) {
	e := newAgentE2E(t)
	boot, bootTok := e.enrol("scout") // a key and an approver now exist
	st, start := e.startRaw("second")
	if st != http.StatusCreated {
		t.Fatal(st)
	}
	raw, _ := json.Marshal(start)
	for _, secret := range []string{boot, bootTok, "operator", "person:"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the start answer holds %q: %s", secret, raw)
		}
	}
	// A key id is "k-" and 16 hex digits. The bare letters "k-" can turn up by chance in the random device code
	// (base64url), which made this test fail now and then, so the whole shape is looked for.
	if m := regexp.MustCompile(`k-[0-9a-f]{16}`).FindString(string(raw)); m != "" {
		t.Errorf("the start answer holds a key id %q: %s", m, raw)
	}
	if len(start) != 5 {
		t.Errorf("the start answer has %d fields: %v", len(start), start)
	}
	id, _ := start["id"].(string)
	// An unknown enrolment, a wrong device code and a well-formed but absent id answer the same.
	answers := map[string]string{}
	for name, c := range map[string]struct{ path, device string }{
		"unknown id":  {"/v0/agents/enrolments/en-0000000000000000/poll", "x"},
		"wrong code":  {"/v0/agents/enrolments/" + id + "/poll", strings.Repeat("x", 43)},
		"malformed":   {"/v0/agents/enrolments/not-an-id/poll", "x"},
		"another one": {"/v0/agents/enrolments/" + id + "/poll", "y"},
	} {
		st, body := e.enrolRaw(c.path, "127.0.0.1:55398", map[string]string{"Content-Type": "application/json"}, fmt.Sprintf(`{"device_code":%q}`, c.device))
		if st != http.StatusNotFound {
			t.Errorf("%s: %d %s", name, st, body)
		}
		answers[name] = body
	}
	for name, body := range answers {
		if body != answers["unknown id"] {
			t.Errorf("%s answers differently from an unknown id: %s", name, body)
		}
	}
	// A project the policy has not opened for agents and one that does not exist look the same: the route says
	// whether keys.request is on for a project name, and nothing more.
	var codes []int
	for _, p := range []string{"acme-shop", "no-such-project"} {
		c, body := e.enrolRaw("/v0/agents/enrolments", "127.0.0.1:55398", map[string]string{"Content-Type": "application/json"}, fmt.Sprintf(`{"project":%q,"label":"x"}`, p))
		codes = append(codes, c)
		if strings.Contains(body, "storefront") {
			t.Errorf("the refusal names another project: %s", body)
		}
	}
	if codes[0] != codes[1] {
		t.Errorf("a real project without keys.request (%d) and an unknown one (%d) are told apart", codes[0], codes[1])
	}
}
