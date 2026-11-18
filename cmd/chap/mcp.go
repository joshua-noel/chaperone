package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/joshua-noel/chaperone/internal/mcpfront"
	"github.com/joshua-noel/chaperone/internal/version"
)

// mcpUsage follows the layout of every `-h` (usage, summary, flags) so the
// manual generator can read it. The credential, the chapd address and the
// project are those of every other chap command; docs/runbooks/mcp.md has the
// rest.
const mcpUsage = "usage: chap mcp\n" +
	"serve the ops as MCP tools over stdio to the client that starts it (listens on nothing; same credential and checks as chap)\n"

// mcp is `chap mcp` (ADR-009).
func (a *app) mcp(args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		a.out(mcpUsage)
		return exitOK
	}
	if len(args) != 0 {
		return a.fail(exitUsage, "usage: chap mcp (it takes no arguments; the client starts it)")
	}
	base, err := a.baseURL()
	if err != nil {
		return a.report(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := mcpfront.Config{
		Backend:        mcpBackend{a},
		Project:        strings.TrimSpace(a.getenv("CHAP_PROJECT")),
		Version:        version.Version,
		DefaultTargets: map[string]mcpfront.Target{},
		RenderDenial: func(body []byte) string {
			var d denial
			if json.Unmarshal(body, &d) != nil {
				return "DENIED\n"
			}
			return renderDenial(&d)
		},
		Scrub: a.scrub,
		Log:   a.stderr,
	}
	for op, t := range defaultTargets {
		cfg.DefaultTargets[op] = mcpfront.Target{Adapter: t.Adapter, Ref: t.Ref}
	}
	a.err("chap mcp: serving on stdio; chapd at " + base + "\n")
	if err := mcpfront.Serve(ctx, cfg, a.stdin, a.stdout); err != nil {
		return a.fail(exitFail, "mcp: %v", err)
	}
	return exitOK
}

// mcpBackend sends an MCP front end's calls through the same code `chap` uses:
// the loopback rule, the credential loading, no redirects.
type mcpBackend struct{ a *app }

func (b mcpBackend) Call(ctx context.Context, method, path string, q url.Values, body any) (*mcpfront.Reply, error) {
	for attempt := 0; ; attempt++ {
		r, err := b.a.callCtx(ctx, method, path, q, body)
		if err != nil {
			var ce *cliError
			if errors.As(err, &ce) {
				kind := mcpfront.ErrOther
				switch ce.code {
				case exitAuth:
					kind = mcpfront.ErrAuth
				case exitUnavailable:
					kind = mcpfront.ErrUnavailable
				}
				return nil, &mcpfront.CallError{Kind: kind, Message: ce.msg}
			}
			return nil, err
		}
		if r.status == http.StatusUnauthorized && attempt == 0 && strings.TrimSpace(b.a.getenv("CHAP_RUN_TOKEN")) == "" {
			// The credential came from the orchestrator token file, which
			// is rewritten when the orchestrator's token is reissued, and this process
			// outlives that: read it again once. A CHAP_RUN_TOKEN cannot
			// change while the process runs, so a 401 there is final.
			// Chapd records every 401 as a denial and counts it toward
			// thrash, so the retry is not free: it is made at most once.
			b.a.forgetToken()
			continue
		}
		return &mcpfront.Reply{Status: r.status, RetryAfter: r.header.Get("Retry-After"), Body: r.body}, nil
	}
}
