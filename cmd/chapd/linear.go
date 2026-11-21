package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/joshua-noel/chaperone/internal/connectors/linear"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// This file wires the Linear operator-board intake: the
// `intake.list`, `intake.comment`, `intake.move` and `intake.states` adapters
// and the board poller inside `chapd run`. All four ops are on in the
// baseline policy (policy PR of 31 Oct 2026) but refuse a project with no `linear:` block. The operator's steps
// (the OAuth app, the two vault secrets, the project's `linear:` block, the
// policy PR) are in docs/runbooks/linear-intake.md.

// linearConfig holds `chapd run`'s Linear flags.
type linearConfig struct {
	// PollInterval is how often the poller refreshes the cached board. 0 turns
	// the poller off: every `intake.list` then reads Linear on demand.
	PollInterval time.Duration
	// HourlyBudget is the most Linear API calls chapd makes in any 60 minutes.
	HourlyBudget int
}

func (c *linearConfig) register(fs *flag.FlagSet) {
	fs.DurationVar(&c.PollInterval, "linear-poll-interval", linear.DefaultPollInterval,
		"how often chapd re-reads the operator board for intake.list (at least 1m; 0 turns the poller off and reads Linear on demand)")
	fs.IntVar(&c.HourlyBudget, "linear-hourly-budget", linear.DefaultHourlyBudget,
		"the most Linear API calls chapd makes in any 60 minutes")
}

func (c linearConfig) validate() error {
	if c.PollInterval < 0 || (c.PollInterval > 0 && c.PollInterval < linear.MinPollInterval) {
		return fmt.Errorf("chapd: -linear-poll-interval %s is not 0 (off) or at least %s", c.PollInterval, linear.MinPollInterval)
	}
	if c.HourlyBudget < 0 {
		return fmt.Errorf("chapd: -linear-hourly-budget %d must not be negative", c.HourlyBudget)
	}
	return nil
}

// installLinear adds the four intake adapters when the vault is open. They
// refuse every request until the op is enabled, the project's policy file has a
// `linear:` block and the vault holds the app's two secrets.
func (a *App) installLinear(ads map[string]ops.Adapter) error {
	cfg := a.cfg.Linear
	if err := cfg.validate(); err != nil {
		return err
	}
	if a.vault == nil {
		return nil
	}
	ep := linear.DefaultEndpoints()
	if a.cfg.linearEndpoints != nil {
		ep = *a.cfg.linearEndpoints
	}
	toks, err := linear.NewTokenSource(linear.TokenConfig{Secrets: a.vault, Registry: a.Reg, Endpoints: ep, Now: a.cfg.now})
	if err != nil {
		return err
	}
	cl, err := linear.NewClient(linear.ClientConfig{Endpoints: ep, Tokens: toks, HourlyBudget: cfg.HourlyBudget, Now: a.cfg.now})
	if err != nil {
		return err
	}
	board := linear.NewBoard(linear.BoardConfig{Client: cl, Interval: cfg.PollInterval, Now: a.cfg.now, Log: a.log})
	pol := func(project string) *policy.Linear {
		eff := a.Policy.For(project)
		if eff.Invalid != nil {
			return nil
		}
		return eff.Linear
	}
	set, err := linear.Adapters(linear.Config{Client: cl, Board: board, Policy: pol, Redactor: a.Reg, Now: a.cfg.now})
	if err != nil {
		return err
	}
	for op, ad := range set {
		prev, taken := ads[op]
		switch {
		case !taken:
			ads[op] = ad
		case op == linear.OpIssueComment:
			// One name, two connectors: GitHub's issue.comment (the error watcher) and
			// Linear's. The target's adapter picks; Linear's refuses a project with no
			// `linear.issues` block, which keeps it off while the baseline has the name on.
			ads[op] = ops.ByTarget{"github": prev, linear.AdapterName: ad}
		default:
			return fmt.Errorf("chapd: op %s already has an adapter; the Linear connector would replace it", op)
		}
	}
	a.linearBoard = board
	return nil
}
