package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// quickstartInfo is everything the printed text needs.
type quickstartInfo struct {
	GOOS        string
	Dir, LogDir string
	Addr        string // 127.0.0.1:PORT, the API address
	Origin      string // http://localhost:PORT, the console address a browser uses
	EnrollToken string // empty: an approver exists, offer sign-in
	Fresh       bool
	TTL         time.Duration

	TokenFile string
	KeyFile   string        // the agent's key file (made by `chap agent enrol`)
	Agent     agentKeyState // what that file says at start
	Project   string
	Repo      string // the playground's fake repository, owner/name
	Base      string
	PRs       []fakePR

	Chap       string // how to run chap: a full path, or "chap"
	ChapOnPath bool   // a bare `chap` in a new terminal runs Chap
}

// findChap looks for chap next to this chapd, then on PATH. A bare "chap" with
// onPath false means it was not found anywhere.
func findChap(goos string) (path string, onPath bool) {
	name := "chap"
	if goos == "windows" {
		name = "chap.exe"
	}
	var sibling string
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		c := filepath.Join(filepath.Dir(exe), name)
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			sibling = c
		}
	}
	onPathAt, lerr := exec.LookPath("chap")
	switch {
	case sibling != "" && lerr == nil && sameFile(onPathAt, sibling):
		return sibling, true
	case sibling != "":
		return sibling, false
	case lerr == nil:
		if abs, err := filepath.Abs(onPathAt); err == nil {
			return abs, true
		}
		return onPathAt, true
	}
	return "chap", false
}

func sameFile(a, b string) bool {
	x, err1 := os.Stat(a)
	y, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(x, y)
}

// quoteArg quotes s for a PowerShell (windows) or POSIX shell word.
func quoteArg(goos, s string) string {
	safe := s != ""
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("_@%+=:,./-", r):
		case goos == "windows" && r == '\\':
		default:
			safe = false
		}
	}
	if safe {
		return s
	}
	return forceQuote(goos, s)
}

// forceQuote always quotes (PowerShell needs a string after `$env:NAME =`).
func forceQuote(goos, s string) string {
	if goos == "windows" {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// envLine sets one variable for the rest of a terminal session.
func envLine(goos, name, value string) string {
	if goos == "windows" {
		return fmt.Sprintf("$env:%s = %s", name, forceQuote(goos, value))
	}
	return fmt.Sprintf("export %s=%s", name, forceQuote(goos, value))
}

func (i quickstartInfo) apiURL() string { return "http://" + i.Addr }

// mcpLine is the `claude mcp add` line for `chap mcp` (docs/runbooks/mcp.md): the
// address and key file go in the entry's env, because a client does
// not pass the shell's variables on.
func (i quickstartInfo) mcpLine() string {
	q := func(s string) string { return quoteArg(i.GOOS, s) }
	return strings.Join([]string{
		"claude mcp add --scope user chaperone-playground",
		"-e " + q("CHAP_URL="+i.apiURL()),
		"-e " + q("CHAP_KEY_FILE="+i.KeyFile),
		"-- " + q(i.Chap) + " mcp",
	}, " ")
}

func (i quickstartInfo) pr(kind string) (fakePR, bool) {
	for _, p := range i.PRs {
		if p.Kind == kind {
			return p, true
		}
	}
	return fakePR{}, false
}

// renderQuickstart is the text chapd quickstart prints once it is listening: the
// first-passkey address (or the sign-in address), the Claude Code line, three
// commands. Every line that names the fake GitHub says PLAYGROUND or names the
// repository "playground/...".
func renderQuickstart(i quickstartInfo) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("Chaperone quickstart: PLAYGROUND")
	w("")
	w("PLAYGROUND: the GitHub in this run is a fake one inside this program (%s). Nothing here can reach a real repository.", i.Repo)
	w("Folder: %s", i.Dir)
	w("Log:    %s", filepath.Join(i.LogDir, "chapd.log"))
	w("Leave this window open. Press Ctrl+C in it to stop.")
	w("")
	if i.EnrollToken != "" {
		w("1. Make your first passkey")
		w("   Open this address in a browser on this computer. It works once, only from this computer, for %d minutes:", int(i.TTL.Minutes()))
		w("")
		w("   %s/enroll#%s", i.Origin, i.EnrollToken)
		w("")
		w("   Press \"Create passkey\" and approve with your system's passkey prompt. Then sign in at %s/login.", i.Origin)
	} else {
		w("1. Sign in")
		w("   This folder already has your passkey. Open this address in a browser on this computer:")
		w("")
		w("   %s/login", i.Origin)
	}
	w("")
	i.renderAgentKey(w)
	w("")
	w("3. Connect Claude Code (optional)")
	w("   Run this in another terminal. It adds the PLAYGROUND tools, and gives Claude Code the AGENT'S KEY, never the orchestrator token:")
	w("")
	w("   %s", i.mcpLine())
	if i.Agent.Kind != "ready" && i.Agent.Kind != "request-only" {
		w("")
		w("   Run it after step 2: the key file does not exist until the agent has been enrolled. Claude Code sees tools only for what the key may do: the four pull-request reads, and keys_request, with which it can ask you for access itself (you still answer at Agents).")
	}
	if i.Chap == "chap" && !i.ChapOnPath {
		w("")
		w("   chap was not found next to chapd or on your PATH: put the full path of chap in place of \"chap\" above.")
	}
	w("")
	w("   When you stop using the quickstart, remove it:")
	w("")
	w("   %s", i.mcpRemoveLine())
	w("")
	w("   Why: the entry stays in Claude Code's user settings and keeps pointing at port %s and the key file. Once the quickstart is stopped, another program could listen on that port and receive the key on the next tool call.", i.port())
	w("")
	w("4. Try it (PLAYGROUND repository %s)", i.Repo)
	med, haveMed := i.pr("medium")
	if haveMed {
		w("   As the AGENT, in the terminal that has CHAP_URL and CHAP_KEY_FILE set (step 2):")
		w("")
		w("   a. Read pull request %d. This works once the key can read, and needs no approval:", med.Number)
		w("      chap pr view %d --repo %s", med.Number, i.Repo)
		w("   b. Try to merge it. A key can never hold pr.merge, so this is refused, whatever you approve:")
		w("      chap pr merge %d --head %s --base %s --repo %s", med.Number, med.Head, i.Base, i.Repo)
		w("")
	}
	w("   As YOU, the operator, in a second terminal. The merge demo uses the ORCHESTRATOR token, because a key cannot ask for a")
	w("   merge: the orchestrator is the role that holds pr.merge, and here you play it. Do not give this token to an agent.")
	w("")
	w("   %s", envLine(i.GOOS, "CHAP_URL", i.apiURL()))
	w("   %s", envLine(i.GOOS, "CHAP_PROJECT", i.Project))
	w("   %s", envLine(i.GOOS, "CHAP_ORCHESTRATOR_TOKEN_FILE", i.TokenFile))
	if !i.ChapOnPath && i.Chap != "chap" {
		dir := dirOf(i.GOOS, i.Chap)
		if i.GOOS == "windows" {
			w("   $env:PATH = %s + ';' + $env:PATH", forceQuote(i.GOOS, dir))
		} else {
			w("   export PATH=%s:\"$PATH\"", forceQuote(i.GOOS, dir))
		}
	}
	if haveMed {
		merge := fmt.Sprintf("chap pr merge %d --head %s --base %s --repo %s", med.Number, med.Head, i.Base, i.Repo)
		w("")
		w("   c. Ask to merge it. It changes code, so Chaperone refuses: it needs your approval.")
		w("      %s", merge)
		w("   d. Ask again for an approval card:")
		w("      %s --request --reason \"reword the checkout button\"", merge)
		w("")
		w("   Then open %s/approvals, read the card and approve it with your passkey. Run (a) again, as the agent: it shows the pull request merged.", i.Origin)
		if red, ok := i.pr("red"); ok {
			w("")
			w("   Extra: pull request %d has failing checks, so Chaperone refuses to merge it:", red.Number)
			w("      chap pr merge %d --head %s --base %s --repo %s", red.Number, red.Head, i.Base, i.Repo)
		}
	}
	return b.String()
}

// renderAgentKey prints step 2 for the state the agent's key file is in at start.
func (i quickstartInfo) renderAgentKey(w func(string, ...any)) {
	a := i.Agent
	until := a.Expires.Local().Format("2006-01-02 15:04 MST")
	w("2. The agent's own key")
	switch a.Kind {
	case "ready":
		w("   The agent already has a key of its own (%s), good until %s. It can: %s. It can ask you for more, and nothing else.", a.Label, until, strings.Join(a.Ops, ", "))
		w("   Nothing to do here. In the agent's terminal:")
		w("")
		w("   %s", envLine(i.GOOS, "CHAP_URL", i.apiURL()))
		w("   %s", envLine(i.GOOS, "CHAP_KEY_FILE", i.KeyFile))
		return
	case "request-only":
		w("   The agent is enrolled (%s) and holds a key that can only ask, good until %s. Step b gives it access.", a.Label, until)
	default:
		w("   The agent gets a key of its own, not your orchestrator token. It can read the playground pull requests and ask you for more, and")
		w("   nothing else. Making it takes two taps of your passkey, the same two a real agent needs. Sign in first (step 1).")
		switch a.Why {
		case "":
		case "stopped":
			w("   (A person stopped the agent of an earlier start for good, at Agents, so this start uses a new name: %s.)", a.Label)
		default:
			w("   (The key file of an earlier start was %s, so it was removed and a new key can be made.)", map[string]string{
				"expired": "expired", "revoked": "revoked", "unknown": "not a key this folder's database knows", "unreadable": "unreadable",
			}[a.Why])
		}
	}
	w("   In a terminal for the agent, tell chap where chapd is and where the key goes:")
	w("")
	w("   %s", envLine(i.GOOS, "CHAP_URL", i.apiURL()))
	w("   %s", envLine(i.GOOS, "CHAP_KEY_FILE", i.KeyFile))
	if a.Kind != "request-only" {
		w("")
		w("   a. Enrol the agent. It prints a short code and waits for you:")
		w("      chap agent enrol --label %s --project %s --out %s", a.Label, i.Project, quoteArg(i.GOOS, i.KeyFile))
		w("      Open %s/agents, type the code, press \"Look up the agent\", then \"Make the enrolment card\". The Approvals page opens with the", i.Origin)
		w("      card. It says the agent gets no access at all. Approve it with your passkey. The agent now holds a key that can only ask.")
	}
	w("")
	w("   b. The agent asks for what it needs, and waits for you:")
	w("      chap key request --ops %s --repo %s --ttl %s --reason \"%s\" --wait 600", strings.Join(quickstartKeyOps, ","), i.Repo, quickstartKeyTTL, quickstartKeyReason)
	w("      Open %s/agents. Under \"Waiting for your answer\" press Answer, read what it asks for, press \"Grant as asked\", and approve the second", i.Origin)
	w("      card with your passkey. The key in the file is then replaced by one that can read the four pull-request operations.")
}

// dirOf is the folder part of a path in the separator style of goos.
func dirOf(goos, p string) string {
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	if i := strings.LastIndex(p, sep); i > 0 {
		return p[:i]
	}
	return "."
}

// mcpRemoveLine undoes mcpLine.
func (i quickstartInfo) mcpRemoveLine() string {
	return "claude mcp remove chaperone-playground --scope user"
}

func (i quickstartInfo) port() string {
	_, p, _ := net.SplitHostPort(i.Addr)
	return p
}
