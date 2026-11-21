package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/localtime"
)

// `chap key` (ADR-008): build a key for a script or an agent, list keys, revoke one, and read the one a
// process holds. A key is made in two steps: the card (signed with Windows Hello in the console) and the claim.
// The claim hands the key to the caller that asked, once, and chap writes it to the file named by --out. No command
// prints the key, takes it as a flag, or puts it in an error: the file is the only place it is.

var (
	keyIDRE    = regexp.MustCompile(`^k-[0-9a-f]{16}$`)
	holderRE   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,39}$`) // the most an agent label or holder name may be: keys.MaxLabel
	repoNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9._-]{1,100}$`)
)

const (
	defaultKeyHours = 24
	defaultKeyRate  = 300
)

func keyCommands() []*command {
	return []*command{
		{path: "key create", usage: "chap key create --project <p> --holder <name> (--agent | --person) --ops <op,op> [--repo owner/name] [--ttl 24h|7d] [--rate <n>] --out <file> [--wait <s>] [--reason <why>]",
			summary: "build a key for a script or an agent: a card you sign in the console, then the key goes to --out (orchestrator only)", run: cmdKeyCreate},
		{path: "key claim", usage: "chap key claim <k-id> --out <file>",
			summary: "take a granted key into --out, once (only the caller that asked for it)", run: cmdKeyClaim},
		{path: "key list", usage: "chap key list",
			summary: "list the keys you own: holder, state, ops, repositories, expiry, uses (orchestrator only)", run: cmdKeyList},
		{path: "key revoke", usage: "chap key revoke <k-id>",
			summary: "revoke a key you own at once; it does not stop the agent, only its owner does that at the console (orchestrator only)", run: cmdKeyRevoke},
		{path: "key show", usage: "chap key show",
			summary: "show the key this process holds: what it can do and until when (a key only)", run: cmdKeyShow},
	}
}

type keyInfo struct {
	ID             string   `json:"id"`
	State          string   `json:"state"`
	Project        string   `json:"project"`
	Owner          string   `json:"owner"`
	HolderKind     string   `json:"holder_kind"`
	Holder         string   `json:"holder"`
	Ops            []string `json:"ops"`
	Units          []string `json:"units"`
	Sensitive      bool     `json:"sensitive"`
	RatePerHour    int      `json:"rate_per_hour"`
	ExpiresAt      string   `json:"expires_at"`
	ClaimDeadline  string   `json:"claim_deadline"`
	Fingerprint    string   `json:"fingerprint"`
	RevokedAt      string   `json:"revoked_at"`
	RevokeReason   string   `json:"revoke_reason"`
	StoppedByHuman bool     `json:"stopped_by_human"`
	LastUsedAt     string   `json:"last_used_at"`
	Uses           int      `json:"uses"`
}

// parseKeyTTL reads --ttl: whole hours ("36h") or days ("7d"). The card states the hours.
func parseKeyTTL(s string) (int, error) {
	if s == "" {
		return defaultKeyHours, nil
	}
	unit := 1
	switch {
	case strings.HasSuffix(s, "d"):
		unit, s = 24, strings.TrimSuffix(s, "d")
	case strings.HasSuffix(s, "h"):
		s = strings.TrimSuffix(s, "h")
	default:
		return 0, errors.New("--ttl is a whole number of hours or days: 24h or 7d")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 1000 {
		return 0, errors.New("--ttl is a whole number of hours or days: 24h or 7d")
	}
	return n * unit, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// writeKeyFile refuses an --out that exists before anything is asked for: the claim hands the key over once.
func (a *app) checkOut(c *command, out string) (int, bool) {
	if out == "" {
		return a.usageErr(c, "--out <file> names where the key is written; it is never printed"), false
	}
	if _, err := a.readFile(out); err == nil {
		return a.usageErr(c, "%s already exists; chap never overwrites a file, and a key is handed over once", clean(out)), false
	} else if !errors.Is(err, os.ErrNotExist) {
		return a.usageErr(c, "cannot use --out %s: %v", clean(out), err), false
	}
	return 0, true
}

func cmdKeyCreate(a *app, c *command, args []string) int {
	var project, holder, opsFlag, repo, ttl, out, reason string
	var agent, person bool
	var rate, wait int
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.StringVar(&project, "project", "", "the project the key is bound to")
	fs.StringVar(&holder, "holder", "", "the name of the script, person or agent that will hold the key")
	fs.BoolVar(&agent, "agent", false, "the holder is an agent (its owner can stop it at the console)")
	fs.BoolVar(&person, "person", false, "the holder is a person or a script")
	fs.StringVar(&opsFlag, "ops", "", "comma-separated ops the key may use; routine ops, and risky ones that still ask each time")
	fs.StringVar(&repo, "repo", "", "owner/name the key is bound to (needed for pull-request ops)")
	fs.StringVar(&ttl, "ttl", "24h", "how long it lasts: 24h by default, at most 30d, 7d for a key with a risky op")
	fs.IntVar(&rate, "rate", defaultKeyRate, "calls an hour, at most 300")
	fs.StringVar(&out, "out", "", "the new file the key is written to (it is not printed)")
	fs.IntVar(&wait, "wait", 300, "seconds to wait for the card to be signed, 0 to not wait")
	fs.StringVar(&reason, "reason", "", "why the key is needed (shown on the card)")
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	switch {
	case !slugRE.MatchString(project):
		return a.usageErr(c, "--project is required")
	case !holderRE.MatchString(holder):
		return a.usageErr(c, "--holder is required: a lower-case name of at most 40 characters")
	case agent == person:
		return a.usageErr(c, "say whether the holder is an --agent or a --person")
	case rate < 1 || rate > defaultKeyRate:
		return a.usageErr(c, "--rate is 1 to %d", defaultKeyRate)
	case wait < 0 || wait > 3600:
		return a.usageErr(c, "--wait is 0 to 3600")
	}
	hours, err := parseKeyTTL(ttl)
	if err != nil {
		return a.usageErr(c, "%v", err)
	}
	opList := splitList(opsFlag)
	for _, op := range opList {
		if !opNameRE.MatchString(op) {
			return a.usageErr(c, "%q is not an op name", clean(op))
		}
	}
	if len(opList) == 0 {
		return a.usageErr(c, "--ops is required: the ops the key may use")
	}
	var units []string
	if repo != "" {
		if !repoNameRE.MatchString(repo) {
			return a.usageErr(c, "--repo must be owner/name")
		}
		units = []string{strings.ToLower(repo)}
	}
	if code, ok := a.checkOut(c, out); !ok {
		return code
	}
	sort.Strings(opList)
	opList = uniqueSorted(opList)
	kind := "person"
	if agent {
		kind = "agent"
	}
	params := map[string]any{"holder": holder, "holder_kind": kind, "ops": opList, "ttl_hours": hours, "rate_per_hour": rate}
	if units != nil {
		params["units"] = units
	}
	if reason == "" {
		reason = "a key for " + holder
	}
	body := map[string]any{
		"kind": "op", "op": "keys.issue", "project": project, "reason": reason,
		"target": map[string]any{"adapter": "chaperone", "ref": "key:" + holder}, "params": params,
	}
	r, err := a.call("POST", "/v0/approvals", nil, body)
	if err != nil {
		return a.report(err)
	}
	if r.status < 200 || r.status >= 300 {
		return a.refused(*asJSON, r)
	}
	var o struct {
		ID       string `json:"id"`
		State    string `json:"state"`
		Approval struct {
			ID string `json:"id"`
		} `json:"approval"`
	}
	if err := json.Unmarshal(r.body, &o); err != nil || o.ID == "" {
		return a.fail(exitFail, "chap: chapd's reply cannot be read")
	}
	if !*asJSON {
		a.out(fmt.Sprintf("card %s is waiting for you: open the console, read it, and approve it with Windows Hello (op %s).\n", clean(o.Approval.ID), clean(o.ID)))
	}
	if wait == 0 {
		a.out(fmt.Sprintf("not waiting: when it is approved, run `chap op show %s` for the key id, then `chap key claim <k-id> --out %s`.\n", clean(o.ID), clean(out)))
		return exitPending
	}
	// Wait for the signature. The op moves on its own once the card is signed.
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	state, keyID := o.State, ""
	for {
		secs := int(time.Until(deadline).Seconds())
		if secs < 1 && state != "succeeded" {
			a.out(fmt.Sprintf("still waiting for the card after %d s; run `chap op show %s --wait 55` to carry on, then claim the key.\n", wait, clean(o.ID)))
			return exitPending
		}
		if state == "succeeded" || state == "failed" || state == "refused" || state == "denied" || state == "expired" || state == "cancelled" {
			break
		}
		q := url.Values{"wait": {strconv.Itoa(min(secs, 55))}, "since_state": {state}}
		pr, err := a.call("GET", "/v0/ops/"+o.ID, q, nil)
		if err != nil {
			return a.report(err)
		}
		if pr.status < 200 || pr.status >= 300 {
			return a.refused(*asJSON, pr)
		}
		var cur struct {
			State  string         `json:"state"`
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal(pr.body, &cur); err != nil {
			return a.fail(exitFail, "chap: chapd's reply cannot be read")
		}
		state = cur.State
		if id, ok := cur.Result["key_id"].(string); ok {
			keyID = id
		}
	}
	if state != "succeeded" {
		return a.fail(exitNotOK, "the key was not made: the request ended %s (the card was not approved, or it was refused). Nothing was created.", clean(state))
	}
	if !keyIDRE.MatchString(keyID) {
		pr, err := a.call("GET", "/v0/ops/"+o.ID, nil, nil)
		if err != nil {
			return a.report(err)
		}
		var cur struct {
			Result map[string]any `json:"result"`
		}
		_ = json.Unmarshal(pr.body, &cur)
		keyID, _ = cur.Result["key_id"].(string)
	}
	if !keyIDRE.MatchString(keyID) {
		return a.fail(exitFail, "the card was approved but chapd named no key; run `chap key list`")
	}
	return a.claimInto(*asJSON, keyID, out)
}

func uniqueSorted(in []string) []string {
	out := in[:0:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func cmdKeyClaim(a *app, c *command, args []string) int {
	var out string
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	fs.StringVar(&out, "out", "", "the new file the key is written to (it is not printed)")
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if !keyIDRE.MatchString(pos[0]) {
		return a.usageErr(c, "the key id must look like k-0123456789abcdef")
	}
	if code, ok := a.checkOut(c, out); !ok {
		return code
	}
	return a.claimInto(*asJSON, pos[0], out)
}

// claimInto claims the key and writes it to out. The key is in the reply and the file, nowhere else; if it cannot
// be written the key is revoked at once rather than left unclaimable.
func (a *app) claimInto(asJSON bool, id, out string) int {
	r, err := a.call("POST", "/v0/keys/"+id+"/claim", nil, nil)
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
	if err := a.createFile(out, []byte(v.Token+"\n")); err != nil {
		a.call("POST", "/v0/keys/"+id+"/revoke", nil, nil) // best effort: a key nobody holds is revoked
		return a.fail(exitFail, "the key could not be written to %s (%v), so it was revoked; ask for a new one", clean(out), err)
	}
	if asJSON {
		b, _ := json.Marshal(v.Key)
		a.out(indentJSON(b))
		return exitOK
	}
	a.out(renderKeyClaimed(&v.Key, out))
	return exitOK
}

func renderKeyClaimed(k *keyInfo, out string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "key %s for %s %s is in %s (fingerprint %s). It is not shown anywhere.\n", clean(k.ID), clean(k.HolderKind), clean(k.Holder), clean(out), clean(k.Fingerprint))
	fmt.Fprintf(&b, "it can use %s", clean(strings.Join(k.Ops, ", ")))
	if len(k.Units) > 0 {
		fmt.Fprintf(&b, " on %s", clean(strings.Join(k.Units, ", ")))
	}
	fmt.Fprintf(&b, " in project %s, at most %d calls an hour, until %s.\n", clean(k.Project), k.RatePerHour, localtime.FromRFC3339(k.ExpiresAt))
	fmt.Fprintf(&b, "to use it: CHAP_KEY_FILE=%s chap <command>\n", clean(out))
	return b.String()
}

func cmdKeyList(a *app, c *command, args []string) int {
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	return a.do(*asJSON, "GET", "/v0/keys", nil, nil, func(r *reply) rendered {
		var page struct {
			Items []keyInfo `json:"items"`
		}
		if err := json.Unmarshal(r.body, &page); err != nil {
			return unreadable(err)
		}
		if len(page.Items) == 0 {
			return rendered{human: "no keys\n"}
		}
		rows := make([][]string, len(page.Items))
		for i, k := range page.Items {
			state := k.State
			if k.StoppedByHuman {
				state += " (agent stopped)"
			}
			rows[i] = []string{k.ID, k.HolderKind + " " + k.Holder, state, strings.Join(k.Ops, ","), strings.Join(k.Units, ","),
				localtime.FromRFC3339(k.ExpiresAt), lastUsed(k.LastUsedAt), strconv.Itoa(k.Uses)}
		}
		return rendered{human: table([]string{"KEY", "HOLDER", "STATE", "OPS", "REPOSITORIES", "EXPIRES (" + localtime.Label() + ")", "LAST USED", "USES"}, rows)}
	})
}

func lastUsed(s string) string {
	if s == "" {
		return "never"
	}
	return localtime.FromRFC3339(s)
}

func cmdKeyRevoke(a *app, c *command, args []string) int {
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	pos, code, done := a.parse(c, fs, args, 1, 1)
	if done {
		return code
	}
	if !keyIDRE.MatchString(pos[0]) {
		return a.usageErr(c, "the key id must look like k-0123456789abcdef")
	}
	return a.do(*asJSON, "POST", "/v0/keys/"+pos[0]+"/revoke", nil, nil, func(r *reply) rendered {
		var k keyInfo
		if err := json.Unmarshal(r.body, &k); err != nil {
			return unreadable(err)
		}
		out := fmt.Sprintf("key %s is revoked: its next call is refused, and the cards it was waiting on are cancelled.\n", clean(k.ID))
		if k.StoppedByHuman {
			out += fmt.Sprintf("the agent %s is stopped by a human: it cannot be given a key again until its owner resumes it.\n", clean(k.Holder))
		}
		return rendered{human: out}
	})
}

func cmdKeyShow(a *app, c *command, args []string) int {
	fs := flag.NewFlagSet(c.path, flag.ContinueOnError)
	asJSON := jsonOnly(fs)
	if _, code, done := a.parse(c, fs, args, 0, 0); done {
		return code
	}
	return a.do(*asJSON, "GET", "/v0/keys/self", nil, nil, func(r *reply) rendered {
		var k keyInfo
		if err := json.Unmarshal(r.body, &k); err != nil {
			return unreadable(err)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "key %s (%s) for %s %s, acting for %s\n", clean(k.ID), clean(k.State), clean(k.HolderKind), clean(k.Holder), clean(k.Owner))
		fmt.Fprintf(&b, "project: %s\nops: %s\n", clean(k.Project), clean(strings.Join(k.Ops, ", ")))
		if len(k.Units) > 0 {
			fmt.Fprintf(&b, "repositories: %s\n", clean(strings.Join(k.Units, ", ")))
		}
		fmt.Fprintf(&b, "rate: %d calls an hour\nexpires: %s\n", k.RatePerHour, localtime.FromRFC3339(k.ExpiresAt))
		return rendered{human: b.String()}
	})
}
