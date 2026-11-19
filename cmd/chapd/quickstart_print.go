package main

import (
	"fmt"
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
// address, project and token file go in the entry's env, because a client does
// not pass the shell's variables on.
func (i quickstartInfo) mcpLine() string {
	q := func(s string) string { return quoteArg(i.GOOS, s) }
	return strings.Join([]string{
		"claude mcp add --scope user chaperone-playground",
		"-e " + q("CHAP_URL="+i.apiURL()),
		"-e " + q("CHAP_PROJECT="+i.Project),
		"-e " + q("CHAP_ORCHESTRATOR_TOKEN_FILE="+i.TokenFile),
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
	w("2. Connect Claude Code (optional)")
	w("   Run this in another terminal. It adds the PLAYGROUND tools. Undo it with: claude mcp remove chaperone-playground --scope user")
	w("")
	w("   %s", i.mcpLine())
	if i.Chap == "chap" && !i.ChapOnPath {
		w("")
		w("   chap was not found next to chapd or on your PATH: put the full path of chap in place of \"chap\" above.")
	}
	w("")
	w("3. Three commands to try (PLAYGROUND repository %s)", i.Repo)
	w("   Open another terminal. Tell chap where this chapd is:")
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
	if med, ok := i.pr("medium"); ok {
		merge := fmt.Sprintf("chap pr merge %d --head %s --base %s --repo %s", med.Number, med.Head, i.Base, i.Repo)
		w("")
		w("   a. Read pull request %d:", med.Number)
		w("      chap pr view %d --repo %s", med.Number, i.Repo)
		w("   b. Ask to merge it. It changes code, so Chaperone refuses: it needs your approval.")
		w("      %s", merge)
		w("   c. Ask again for an approval card:")
		w("      %s --request --reason \"reword the checkout button\"", merge)
		w("")
		w("   Then open %s/approvals, read the card and approve it with your passkey. Run (a) again: it is merged.", i.Origin)
		if red, ok := i.pr("red"); ok {
			w("")
			w("   Extra: pull request %d has failing checks, so Chaperone refuses to merge it:", red.Number)
			w("      chap pr merge %d --head %s --base %s --repo %s", red.Number, red.Head, i.Base, i.Repo)
		}
	}
	return b.String()
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
