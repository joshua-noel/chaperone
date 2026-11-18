package main

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/version"
)

// The welcome banner. A person who runs chap for the first time and reaches
// chapd sees it once, on stderr. Agents and scripts never see it: it needs a
// terminal on stderr, no --json, no CI and no CHAP_RUN_TOKEN (which is how an
// agent is given its credential). `chap logo` shows it on demand.
//
// Plain ASCII on purpose: it renders in Windows Terminal and conhost, needs no
// escape codes (so NO_COLOR has nothing to switch off), and costs an agent
// nothing because an agent never gets it.

const tagline = "the threshold between agents and the world"

const art = `  ##       #######  ##     ##  #######  ##   ##    ###    ##
  ##         ###    ###   ###    ###    ###  ##   ## ##   ##
  ##         ###    #### ####    ###    #### ##  ##   ##  ##
  ##         ###    ## ### ##    ###    ## ####  #######  ##
  ##         ###    ##  #  ##    ###    ##  ###  ##   ##  ##
  ##         ###    ##     ##    ###    ##   ##  ##   ##  ##
  #######  #######  ##     ##  #######  ##   ##  ##   ##  #######

  =============================[  ]==============================
`

// logo returns the banner. connectedTo is chapd's URL; empty (for `chap logo`)
// leaves the connection out.
func logo(connectedTo string) string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(art)
	b.WriteString("  " + tagline + "\n")
	b.WriteString("  chap " + version.Version)
	if connectedTo != "" {
		b.WriteString(" | connected to " + connectedTo)
	}
	b.WriteString("\n\n")
	return b.String()
}

// welcome prints the banner on the first successful reply from chapd, once
// per user. The marker file is created before the banner is printed and with
// O_EXCL, so a second process or a failed write never shows it twice; if the
// marker cannot be created the banner is skipped, not repeated.
func (a *app) welcome(asJSON bool, chapdURL string) {
	if asJSON || a.stderrTTY == nil || a.configDir == nil || a.mkdirAll == nil || !a.stderrTTY() {
		return
	}
	if a.getenv("CI") != "" || strings.TrimSpace(a.getenv("CHAP_RUN_TOKEN")) != "" {
		return
	}
	dir, err := a.configDir()
	if err != nil || dir == "" {
		return
	}
	dir = filepath.Join(dir, "chaperone")
	if a.mkdirAll(dir) != nil {
		return
	}
	marker := filepath.Join(dir, "first-connect")
	if a.createFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+" "+chapdURL+"\n")) != nil {
		return
	}
	a.err(logo(chapdURL))
}
