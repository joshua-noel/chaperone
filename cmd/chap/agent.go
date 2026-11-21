package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/localtime"
)

// "The agent asks, you tap" (ADR-008). An agent enrols once: it prints a short code, its owner types the
// code at the console and signs a card with Windows Hello, and the agent keeps a request-only key that holds no
// access. When a job needs access the agent runs `chap key request`: it says what, for how long and why, and
// waits. The owner answers at the console (Grant, Narrow or Deny); the key then arrives in the agent's key file
// and replaces the one it asked with. No command prints a key, takes one as a flag, or puts one in an error.

func agentCommands() []*command {
	return []*command{
		{path: "agent enrol", usage: "chap agent enrol --label <name> --project <p> --out <file> [--wait <s>]",
			summary: "enrol this agent: print a code for its owner to type at the console, then keep a request-only key in --out (no token needed)", run: cmdAgentEnrol},
		{path: "key request", usage: "chap key request --reason <why> (--ops <op,op> [--repo owner/name] | --same-as-me-read) [--ttl 24h|7d] [--rate <n>] [--today] [--wait <s>] | --status <kr-id> | --withdraw <kr-id>",
			summary: "ask your owner for a key: what, how long and why; wait, and the key replaces the one in CHAP_KEY_FILE (an agent's key only)", run: cmdKeyRequest},
		{path: "key extend", usage: "chap key extend --for <1h..30d> --reason <why> [--today] [--wait <s>]",
			summary: "ask your owner to make this key last longer: one tap and a Hello for them; it adds time and no access (an agent's key only)", run: cmdKeyExtend},
	}
}

var requestIDRE = regexp.MustCompile(`^kr-[0-9a-f]{16}$`)

type enrolStart struct {
	ID         string `json:"id"`
	UserCode   string `json:"user_code"`
	DeviceCode string `json:"device_code"`
	ExpiresAt  string `json:"expires_at"`
	Interval   int    `json:"interval"`
}

type enrolPoll struct {
	State string  `json:"state"`
	Token string  `json:"token"`
	Key   keyInfo `json:"key"`
}

func cmdAgentEnrol(a *app, c *command, args []string) int {
	var label, project, out string
	var wait int
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.StringVar(&label, "label", "", "this agent's name (lower case)")
	fs.StringVar(&project, "project", "", "the project the agent works in")
	fs.StringVar(&out, "out", "", "the new file the request-only key is written to (it is not printed)")
	fs.IntVar(&wait, "wait", 600, "seconds to wait for your owner, 10 to 3600")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	switch {
	case !holderRE.MatchString(label):
		return a.usageErr(c, "--label is required: a lower-case name of at most 40 characters")
	case !slugRE.MatchString(project):
		return a.usageErr(c, "--project is required")
	case wait < 10 || wait > 3600:
		return a.usageErr(c, "--wait is 10 to 3600")
	}
	if code, ok := a.checkOut(c, out); !ok {
		return code
	}
	r, err := a.callAnon("POST", "/v0/agents/enrolments", map[string]any{"project": project, "label": label})
	if err != nil {
		return a.report(err)
	}
	if r.status < 200 || r.status >= 300 {
		return a.refused(*asJSON, r)
	}
	var st enrolStart
	if err := json.Unmarshal(r.body, &st); err != nil || st.ID == "" || st.DeviceCode == "" || st.UserCode == "" {
		return a.fail(exitFail, "chap: chapd's reply cannot be read")
	}
	a.tokMu.Lock()
	a.secrets = append(a.secrets, st.DeviceCode) // the one value only this process holds
	a.tokMu.Unlock()
	if !*asJSON {
		a.out(fmt.Sprintf("agent %s asks to be enrolled for project %s.\nAsk your owner to open the console, choose Agents, and type this code:\n\n    %s\n\n"+
			"The code works until %s. Waiting for your owner's Windows Hello...\n", clean(label), clean(project), clean(st.UserCode), localtime.FromRFC3339(st.ExpiresAt)))
	}
	interval := time.Duration(max(st.Interval, 1)) * time.Second
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		pr, err := a.callAnon("POST", "/v0/agents/enrolments/"+st.ID+"/poll", map[string]any{"device_code": st.DeviceCode})
		if err != nil {
			return a.report(err)
		}
		if pr.status < 200 || pr.status >= 300 {
			return a.refused(*asJSON, pr)
		}
		var p enrolPoll
		if err := json.Unmarshal(pr.body, &p); err != nil {
			return a.fail(exitFail, "chap: chapd's reply cannot be read")
		}
		switch p.State {
		case "claimed":
			if p.Token == "" {
				return a.fail(exitFail, "chap: chapd's reply cannot be read")
			}
			a.tokMu.Lock()
			a.secrets = append(a.secrets, p.Token)
			a.tokMu.Unlock()
			if err := a.createFile(out, []byte(p.Token+"\n")); err != nil {
				return a.fail(exitFail, "the request-only key could not be written to %s (%v); it holds no access, but ask your owner to revoke key %s and enrol again", clean(out), err, clean(p.Key.ID))
			}
			if *asJSON {
				b, _ := json.Marshal(p.Key)
				a.out(indentJSON(b))
				return exitOK
			}
			a.out(fmt.Sprintf("enrolled: the request-only key %s is in %s (fingerprint %s). It is not shown anywhere, and it holds no access: it can only ask.\n"+
				"it lasts until %s.\nto ask for access: CHAP_KEY_FILE=%s chap key request --ops <op,op> --repo <owner/name> --reason \"<why>\"\n",
				clean(p.Key.ID), clean(out), clean(p.Key.Fingerprint), localtime.FromRFC3339(p.Key.ExpiresAt), clean(out)))
			return exitOK
		case "expired":
			return a.fail(exitNotOK, "the enrolment expired before your owner signed it, so nothing was made. Run chap agent enrol again.")
		}
		if !time.Now().Add(interval).Before(deadline) {
			return a.fail(exitPending, "still waiting after %d s. The code works until %s; if your owner has not signed by then, run chap agent enrol again.", wait, localtime.FromRFC3339(st.ExpiresAt))
		}
		a.pause(interval)
	}
}

// keyRequest is a key request as chapd shows it.
type keyRequest struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	State       string   `json:"state"`
	Project     string   `json:"project"`
	Owner       string   `json:"owner"`
	Holder      string   `json:"holder"`
	Ops         []string `json:"ops"`
	Units       []string `json:"units"`
	TTLHours    int      `json:"ttl_hours"`
	RatePerHour int      `json:"rate_per_hour"`
	Reason      string   `json:"reason"`
	NeededToday bool     `json:"needed_today"`
	ExpiresAt   string   `json:"expires_at"`
	DecidedBy   string   `json:"decided_by"`
	DenyReason  string   `json:"deny_reason"`
	Granted     *struct {
		Ops         []string `json:"ops"`
		Units       []string `json:"units"`
		TTLHours    int      `json:"ttl_hours"`
		RatePerHour int      `json:"rate_per_hour"`
	} `json:"granted"`
	Removed *struct {
		Ops         []string `json:"ops"`
		Units       []string `json:"units"`
		TTLHours    int      `json:"ttl_hours"`
		RatePerHour int      `json:"rate_per_hour"`
	} `json:"removed"`
	KeyID string `json:"key_id"`
}

func hoursWords(h int) string {
	switch {
	case h%24 == 0 && h/24 == 1:
		return "1 day"
	case h%24 == 0:
		return fmt.Sprintf("%d days", h/24)
	case h == 1:
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", h)
}

// renderKeyRequest says what was asked, and, once answered, what was granted and what was removed.
func renderKeyRequest(q *keyRequest) string {
	var b strings.Builder
	what := "a key"
	if q.Kind == "extend" {
		what = "more time for its key"
	}
	fmt.Fprintf(&b, "request %s (%s): agent %s asked %s for %s in project %s\n", clean(q.ID), clean(q.State), clean(q.Holder), clean(strings.TrimPrefix(q.Owner, "person:")), what, clean(q.Project))
	if q.Kind == "extend" {
		fmt.Fprintf(&b, "asked to add %s\n", hoursWords(q.TTLHours))
	} else {
		fmt.Fprintf(&b, "asked for %s", clean(strings.Join(q.Ops, ", ")))
		if len(q.Units) > 0 {
			fmt.Fprintf(&b, " on %s", clean(strings.Join(q.Units, ", ")))
		}
		fmt.Fprintf(&b, " for %s, at most %d calls an hour\n", hoursWords(q.TTLHours), q.RatePerHour)
	}
	fmt.Fprintf(&b, "your reason: %s\n", clean(q.Reason))
	switch q.State {
	case "pending":
		fmt.Fprintf(&b, "waiting for your owner until %s\n", localtime.FromRFC3339(q.ExpiresAt))
	case "granted":
		if q.Granted != nil {
			if q.Kind == "extend" {
				fmt.Fprintf(&b, "granted: %s more\n", hoursWords(q.Granted.TTLHours))
			} else {
				fmt.Fprintf(&b, "granted: %s", clean(strings.Join(q.Granted.Ops, ", ")))
				if len(q.Granted.Units) > 0 {
					fmt.Fprintf(&b, " on %s", clean(strings.Join(q.Granted.Units, ", ")))
				}
				fmt.Fprintf(&b, " for %s, at most %d calls an hour\n", hoursWords(q.Granted.TTLHours), q.Granted.RatePerHour)
			}
		}
		if rm := q.Removed; rm != nil {
			var parts []string
			if len(rm.Ops) > 0 {
				parts = append(parts, "ops "+strings.Join(rm.Ops, ", "))
			}
			if len(rm.Units) > 0 {
				parts = append(parts, "repositories "+strings.Join(rm.Units, ", "))
			}
			if rm.TTLHours > 0 {
				parts = append(parts, hoursWords(rm.TTLHours)+" of time")
			}
			if rm.RatePerHour > 0 {
				parts = append(parts, fmt.Sprintf("%d calls an hour", rm.RatePerHour))
			}
			if len(parts) > 0 {
				fmt.Fprintf(&b, "removed from your ask: %s\n", clean(strings.Join(parts, "; ")))
			} else {
				b.WriteString("nothing was removed from your ask\n")
			}
		}
	case "denied":
		fmt.Fprintf(&b, "denied by %s", clean(strings.TrimPrefix(q.DecidedBy, "person:")))
		if q.DenyReason != "" {
			fmt.Fprintf(&b, ": %s", clean(q.DenyReason))
		}
		b.WriteString("\nthe same request is refused for an hour: ask for something different, or ask your owner\n")
	default:
		fmt.Fprintf(&b, "this request is %s: nothing more will happen to it\n", clean(q.State))
	}
	return b.String()
}

func cmdKeyRequest(a *app, c *command, args []string) int {
	var opsFlag, repo, ttl, reason, status, withdraw string
	var rate, wait int
	var today, sameRead bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.StringVar(&opsFlag, "ops", "", "comma-separated ops you need")
	fs.StringVar(&repo, "repo", "", "owner/name the ops are for (needed for pull-request ops)")
	fs.BoolVar(&sameRead, "same-as-me-read", false, "ask for what your owner can read, read-only, instead of naming ops")
	fs.StringVar(&ttl, "ttl", "24h", "how long you need it: 24h by default, at most 30d (7d with a risky op)")
	fs.IntVar(&rate, "rate", defaultKeyRate, "calls an hour you need, at most 300")
	fs.StringVar(&reason, "reason", "", "why you need it, in a sentence (your owner reads it)")
	fs.BoolVar(&today, "today", false, "mark the request needed today (it changes no order and no limit)")
	fs.IntVar(&wait, "wait", 300, "seconds to wait for your owner's answer, 0 to not wait")
	fs.StringVar(&status, "status", "", "show the state of request <kr-id> instead of asking")
	fs.StringVar(&withdraw, "withdraw", "", "take back the waiting request <kr-id> instead of asking")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	switch {
	case status != "" && withdraw != "":
		return a.usageErr(c, "--status and --withdraw are two different things")
	case status != "":
		return a.showRequest(c, *asJSON, status)
	case withdraw != "":
		return a.withdrawRequest(c, *asJSON, withdraw)
	}
	params := map[string]any{}
	if sameRead {
		if opsFlag != "" || repo != "" {
			return a.usageErr(c, "--same-as-me-read stands for the ops and the repository: name it or the ops, not both")
		}
		params["preset"] = "same-as-me-read"
	} else {
		opList := splitList(opsFlag)
		if len(opList) == 0 {
			return a.usageErr(c, "--ops is required (or --same-as-me-read): the ops you need")
		}
		for _, op := range opList {
			if !opNameRE.MatchString(op) {
				return a.usageErr(c, "%q is not an op name", clean(op))
			}
		}
		sort.Strings(opList)
		params["ops"] = uniqueSorted(opList)
		if repo != "" {
			if !repoNameRE.MatchString(repo) {
				return a.usageErr(c, "--repo must be owner/name")
			}
			params["units"] = []string{strings.ToLower(repo)}
		}
	}
	hours, err := parseKeyTTL(ttl)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	if rate < 1 || rate > defaultKeyRate {
		return a.usageErr(c, "--rate is 1 to %d", defaultKeyRate)
	}
	params["ttl_hours"], params["rate_per_hour"] = hours, rate
	return a.askKey(c, *asJSON, params, reason, today, wait)
}

func cmdKeyExtend(a *app, c *command, args []string) int {
	var forFlag, reason string
	var wait int
	var today bool
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.StringVar(&forFlag, "for", "", "how much longer you need the key: 1h to 30d")
	fs.StringVar(&reason, "reason", "", "why the work runs long, in a sentence (your owner reads it)")
	fs.BoolVar(&today, "today", false, "mark the request needed today (it changes no order and no limit)")
	fs.IntVar(&wait, "wait", 300, "seconds to wait for your owner's answer, 0 to not wait")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	if forFlag == "" {
		return a.usageErr(c, "--for is required: how much longer, for example 24h or 3d")
	}
	hours, err := parseKeyTTL(forFlag)
	if err != nil {
		return a.usageErr(c, "%v", strings.ReplaceAll(err.Error(), "--ttl", "--for"))
	}
	return a.askKey(c, *asJSON, map[string]any{"kind": "extend", "key": "self", "ttl_hours": hours}, reason, today, wait)
}

// askKey sends keys.request and, unless wait is 0, waits for the owner's answer.
func (a *app) askKey(c *command, asJSON bool, params map[string]any, reason string, today bool, wait int) int {
	switch {
	case strings.TrimSpace(reason) == "":
		return a.usageErr(c, "--reason is required: say what the access is for, in a sentence")
	case len(reason) > 500:
		return a.usageErr(c, "--reason is at most 500 characters")
	case wait < 0 || wait > 3600:
		return a.usageErr(c, "--wait is 0 to 3600")
	}
	keyFile := strings.TrimSpace(a.getenv("CHAP_KEY_FILE"))
	if wait > 0 && keyFile == "" {
		return a.usageErr(c, "CHAP_KEY_FILE names the file your key is in, and the granted key is written there; set it, or pass --wait 0 and claim the key yourself")
	}
	if today {
		params["needed_today"] = true
	}
	body := map[string]any{
		"op": "keys.request", "reason": strings.TrimSpace(reason),
		"target": map[string]any{"adapter": "chaperone", "ref": "key-request"}, "params": params,
	}
	r, err := a.call("POST", "/v0/ops", nil, body)
	if err != nil {
		return a.report(err)
	}
	if r.status < 200 || r.status >= 300 {
		return a.refused(asJSON, r)
	}
	var o struct {
		State  string         `json:"state"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(r.body, &o); err != nil {
		return a.fail(exitFail, "chap: chapd's reply cannot be read")
	}
	id, _ := o.Result["request_id"].(string)
	if o.State != "succeeded" || !requestIDRE.MatchString(id) {
		why, _ := o.Result["error"].(string)
		if why == "" {
			why = "the request ended " + o.State
		}
		return a.fail(exitNotOK, "the request was not made: %s", clean(why))
	}
	if dup, _ := o.Result["deduplicated"].(bool); dup && !asJSON {
		a.out(fmt.Sprintf("you already have this request waiting (%s): it is the same one, so no second card was made.\n", clean(id)))
	}
	if wait == 0 {
		if !asJSON {
			a.out(fmt.Sprintf("asked your owner (request %s). Look with `chap key request --status %s`; when it is granted, claim the key with `chap key claim <k-id> --out <file>`.\n", clean(id), clean(id)))
		}
		return exitPending
	}
	return a.waitForRequest(asJSON, id, keyFile, wait)
}

func (a *app) getRequest(id string) (*keyRequest, *reply, error) {
	r, err := a.call("GET", "/v0/keys/requests/"+id, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if r.status < 200 || r.status >= 300 {
		return nil, r, nil
	}
	var q keyRequest
	if err := json.Unmarshal(r.body, &q); err != nil {
		return nil, nil, failure(exitFail, "chap: chapd's reply cannot be read")
	}
	return &q, r, nil
}

func (a *app) showRequest(c *command, asJSON bool, id string) int {
	if !requestIDRE.MatchString(id) {
		return a.usageErr(c, "the request id must look like kr-0123456789abcdef")
	}
	q, r, err := a.getRequest(id)
	if err != nil {
		return a.report(err)
	}
	if q == nil {
		return a.refused(asJSON, r)
	}
	if asJSON {
		a.out(indentJSON(r.body))
	} else {
		a.out(renderKeyRequest(q))
	}
	if q.State == "pending" {
		return exitPending
	}
	if q.State == "granted" {
		return exitOK
	}
	return exitNotOK
}

func (a *app) withdrawRequest(c *command, asJSON bool, id string) int {
	if !requestIDRE.MatchString(id) {
		return a.usageErr(c, "the request id must look like kr-0123456789abcdef")
	}
	return a.do(asJSON, "POST", "/v0/keys/requests/"+id+"/withdraw", nil, nil, func(r *reply) rendered {
		var q keyRequest
		if err := json.Unmarshal(r.body, &q); err != nil {
			return unreadable(err)
		}
		return rendered{human: fmt.Sprintf("request %s is withdrawn: nobody is asked about it any more.\n", clean(q.ID))}
	})
}

// waitForRequest polls the request until the owner answers. A granted key is claimed and written over the key file
// in one step; an extension needs no claim.
func (a *app) waitForRequest(asJSON bool, id, keyFile string, wait int) int {
	if !asJSON {
		a.out(fmt.Sprintf("asked your owner (request %s). Waiting for the answer; your owner taps Grant, Narrow or Deny at the console.\n", clean(id)))
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		q, r, err := a.getRequest(id)
		if err != nil {
			return a.report(err)
		}
		if q == nil {
			return a.refused(asJSON, r)
		}
		switch q.State {
		case "pending":
			if !time.Now().Add(2 * time.Second).Before(deadline) {
				return a.fail(exitPending, "still waiting after %d s; the request lasts until %s. Look with `chap key request --status %s`.", wait, localtime.FromRFC3339(q.ExpiresAt), clean(id))
			}
			a.pause(2 * time.Second)
			continue
		case "granted":
			if !asJSON {
				a.out(renderKeyRequest(q))
			}
			if q.Kind == "extend" {
				return a.finishExtend(asJSON)
			}
			return a.claimOverKeyFile(asJSON, q.KeyID, keyFile)
		}
		if asJSON {
			a.out(indentJSON(r.body))
		} else {
			a.out(renderKeyRequest(q))
		}
		return exitNotOK
	}
}

func (a *app) finishExtend(asJSON bool) int {
	return a.do(asJSON, "GET", "/v0/keys/self", nil, nil, func(r *reply) rendered {
		var k keyInfo
		if err := json.Unmarshal(r.body, &k); err != nil {
			return unreadable(err)
		}
		return rendered{human: fmt.Sprintf("your key %s now lasts until %s.\n", clean(k.ID), localtime.FromRFC3339(k.ExpiresAt))}
	})
}

// claimOverKeyFile claims the granted key and replaces the key file with it. The file is proved writable before the
// claim (the claim revokes the key it replaces), and if it cannot be written after all, the new key is revoked
// rather than left unclaimable.
func (a *app) claimOverKeyFile(asJSON bool, keyID, keyFile string) int {
	if !keyIDRE.MatchString(keyID) {
		return a.fail(exitFail, "the request was granted but chapd named no key; run `chap key show`")
	}
	old, err := a.readFile(keyFile)
	if err != nil {
		return a.fail(exitFail, "the key file %s cannot be read, so the granted key was not claimed; fix it and run `chap key claim %s --out <file>`", clean(keyFile), keyID)
	}
	if err := a.replace(keyFile, old); err != nil {
		return a.fail(exitFail, "the key file %s cannot be replaced (%v), so the granted key was not claimed; run `chap key claim %s --out <file>` somewhere you can write", clean(keyFile), err, keyID)
	}
	r, err := a.call("POST", "/v0/keys/"+keyID+"/claim", nil, nil)
	if err != nil {
		return a.report(err)
	}
	if r.status < 200 || r.status >= 300 {
		return a.refused(asJSON, r)
	}
	var v struct {
		Token string  `json:"token"`
		Key   keyInfo `json:"key"`
	}
	if err := json.Unmarshal(r.body, &v); err != nil || v.Token == "" {
		return a.fail(exitFail, "chap: chapd's reply cannot be read")
	}
	a.tokMu.Lock()
	a.secrets = append(a.secrets, v.Token) // from here on, no output can carry it
	a.tokMu.Unlock()
	if err := a.replace(keyFile, []byte(v.Token+"\n")); err != nil {
		a.call("POST", "/v0/keys/"+keyID+"/revoke", nil, nil) // best effort: a key nobody holds is revoked
		return a.fail(exitFail, "the key could not be written to %s (%v), so it was revoked; ask again", clean(keyFile), err)
	}
	a.forgetToken()
	if asJSON {
		b, _ := json.Marshal(v.Key)
		a.out(indentJSON(b))
		return exitOK
	}
	a.out(renderKeyClaimed(&v.Key, keyFile))
	return exitOK
}
