// Command chap is the agent- and orchestrator-facing CLI of Chaperone (ticket
// L1-08). It speaks the chapd HTTP contract in api/openapi.yaml and nothing
// else: every command is one or two calls to chapd, rendered as text or JSON.
//
// The rules that shape the code:
//
//   - The credential comes from CHAP_RUN_TOKEN, else the orchestrator token
//     file (ADR-007). No flag accepts a token or any other secret.
//   - chap never prints a secret. Every byte written to stdout or stderr goes
//     through a scrubber that masks the token in use and anything shaped like
//     an orchestrator token or a JWT.
//   - A refusal is a structured denial; chap prints its why and the exact
//     `chap request ...` line (or says asking is not possible).
//   - The exit code says what happened (see the exit constants).
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/joshua-noel/chaperone/internal/privfile"
	"github.com/joshua-noel/chaperone/internal/version"
)

// Exit codes. Scripts and agents branch on these, so they are part of the
// interface: add, never renumber.
const (
	exitOK          = 0 // done
	exitFail        = 1 // chap itself failed (bad reply, local I/O)
	exitUsage       = 2 // bad command line
	exitDenied      = 3 // chapd refused: the denial was printed
	exitAuth        = 4 // no usable token, or chapd does not accept it
	exitNotOK       = 5 // the op ended without success (failed, refused, expired, cancelled); ledger verify not ok
	exitUnavailable = 6 // chapd unreachable or failed closed; nothing ran
	exitPending     = 7 // not finished: waiting for approval, still executing, unconfirmed, or a dry run that needs approval
	exitMissing     = 8 // no such object for this caller, or a conflict with its state
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// app is one invocation's environment; tests replace every field.
type app struct {
	stdout, stderr io.Writer
	stdin          io.Reader
	getenv         func(string) string
	readFile       func(path string) ([]byte, error)
	// createFile writes data to a new file only the user can read; it refuses
	// to overwrite.
	createFile func(path string, data []byte) error
	// replaceFile writes data over an existing private file in one step (a temporary file, then a rename), so a
	// reader never sees half a key. Nil means [replacePrivateFile].
	replaceFile func(path string, data []byte) error
	// sleep waits between polls. Nil means time.Sleep.
	sleep func(time.Duration)
	// git runs `git <args>` in the working directory and returns trimmed stdout.
	git    func(args ...string) (string, error)
	client *http.Client

	// For the one-time welcome logo (logo.go). A nil member means no logo.
	stderrTTY func() bool
	configDir func() (string, error)
	mkdirAll  func(path string) error

	tokMu   sync.Mutex // guards token and secrets (`chap mcp` serves calls concurrently)
	token   string     // loaded on first call
	secrets []string   // exact values to mask in output
}

func osApp(stdout, stderr io.Writer) *app {
	return &app{
		stdout:     stdout,
		stderr:     stderr,
		stdin:      os.Stdin,
		getenv:     os.Getenv,
		readFile:   os.ReadFile,
		createFile: createPrivateFile,
		git: func(args ...string) (string, error) {
			out, err := exec.Command("git", args...).Output()
			return strings.TrimSpace(string(out)), err
		},
		client: &http.Client{
			// A wait=55 call holds for 55 s; a redirect would carry the
			// bearer token somewhere else, so none is followed.
			Timeout:       70 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		stderrTTY: func() bool {
			f, ok := stderr.(*os.File)
			return ok && isTerminal(f)
		},
		configDir: os.UserConfigDir,
		mkdirAll:  func(p string) error { return os.MkdirAll(p, 0o700) },
	}
}

// createPrivateFile writes data to a NEW file that only the current user can open: mode 0600 on Unix, and on Windows
// (where the mode means nothing) a protected, user-only access list given at creation, so the key file does not
// take its folder's. It fails if anything exists at path (a link included).
func createPrivateFile(path string, data []byte) error {
	f, err := privfile.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// run executes one invocation and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	return osApp(stdout, stderr).run(args)
}

// command is one leaf of the command tree.
type command struct {
	path    string // "pr merge"
	usage   string
	summary string
	run     func(a *app, c *command, args []string) int
}

func commands() []*command {
	var all []*command
	all = append(all, opCommands()...)
	all = append(all, kitCommands(declaredOps())...)
	all = append(all, otherCommands()...)
	all = append(all, keyCommands()...)
	all = append(all, agentCommands()...)
	sort.Slice(all, func(i, j int) bool { return all[i].path < all[j].path })
	return all
}

func (a *app) run(args []string) int {
	if len(args) == 0 {
		a.usage(a.stderr)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		a.usage(a.stdout)
		return exitOK
	case "logo":
		if len(args) != 1 {
			return a.fail(exitUsage, "usage: chap logo")
		}
		a.out(logo(""))
		return exitOK
	case "mcp":
		return a.mcp(args[1:])
	case "version":
		if len(args) != 1 {
			return a.fail(exitUsage, "usage: chap version")
		}
		if err := version.Fprint(a.stdout, "chap"); err != nil {
			return a.fail(exitFail, "%v", err)
		}
		return exitOK
	}
	table := commands()
	// Longest path first: "pr merge" before "pr".
	for n := 2; n >= 1; n-- {
		if len(args) < n {
			continue
		}
		path := strings.Join(args[:n], " ")
		for _, c := range table {
			if c.path == path {
				return c.run(a, c, args[n:])
			}
		}
	}
	// A known group with a missing or unknown verb gets the group's verbs.
	var verbs []string
	for _, c := range table {
		if g, v, ok := strings.Cut(c.path, " "); ok && g == args[0] {
			verbs = append(verbs, v)
		}
	}
	if len(verbs) > 0 {
		return a.fail(exitUsage, "%s needs a verb: %s", args[0], strings.Join(verbs, "|"))
	}
	return a.fail(exitUsage, "unknown command %q (chap help lists the commands)", args[0])
}

func (a *app) usage(w io.Writer) {
	var b strings.Builder
	b.WriteString("usage: chap <command> [flags]\n\ncommands:\n")
	b.WriteString("  logo               show the CHAPERONE banner\n  mcp                serve the ops as MCP tools over stdio (Claude Code, Codex, Cursor)\n  version\n")
	for _, c := range commands() {
		fmt.Fprintf(&b, "  %-18s %s\n", c.path, c.summary)
	}
	b.WriteString("\ncommands that call chapd take --json (the server's JSON, nothing else on stdout).\n")
	b.WriteString("token: CHAP_RUN_TOKEN, else the key file CHAP_KEY_FILE, else the orchestrator token file. chapd: CHAP_URL (default http://127.0.0.1:55398).\n")
	b.WriteString("exit: 0 ok, 2 usage, 3 denied, 4 auth, 5 op not ok, 6 chapd unavailable, 7 pending, 8 not found or conflict, 1 other.\n")
	io.WriteString(w, a.scrub(b.String()))
}

// fail prints "chap: <message>" to stderr and returns code.
func (a *app) fail(code int, format string, args ...any) int {
	io.WriteString(a.stderr, a.scrub("chap: "+fmt.Sprintf(format, args...)+"\n"))
	return code
}

// out writes to stdout through the scrubber.
func (a *app) out(s string) { io.WriteString(a.stdout, a.scrub(s)) }

// err writes to stderr through the scrubber.
func (a *app) err(s string) { io.WriteString(a.stderr, a.scrub(s)) }

// replacePrivateFile writes data to a new temporary file next to path (private, exclusive) and renames it over
// path, so the key file is the old key or the new one and never a mix.
func replacePrivateFile(path string, data []byte) error {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	if err := createPrivateFile(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (a *app) replace(path string, data []byte) error {
	if a.replaceFile != nil {
		return a.replaceFile(path, data)
	}
	return replacePrivateFile(path, data)
}

func (a *app) pause(d time.Duration) {
	if a.sleep != nil {
		a.sleep(d)
		return
	}
	time.Sleep(d)
}
