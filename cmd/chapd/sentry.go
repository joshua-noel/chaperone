package main

import (
	"fmt"

	"github.com/joshua-noel/chaperone/internal/connectors/sentry"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// This file wires the Sentry connector: the six `errors.*` adapters. All six
// ops are off in the baseline. Each refuses a project whose policy file has no
// valid `sentry:` block, and acts on the Sentry projects that block lists. The
// operator's steps (the auth token in the vault, the project's `sentry:` block,
// the policy change) are in docs/runbooks/sentry.md.

// installSentry adds the six adapters when the vault is open. They refuse every
// request until the op is enabled, the project's policy file has a `sentry:`
// block and the vault holds the auth token.
func (a *App) installSentry(ads map[string]ops.Adapter) error {
	if a.vault == nil {
		return nil
	}
	cl, err := sentry.NewClient(sentry.ClientConfig{
		Credential: sentry.VaultCredential(a.vault),
		Registry:   a.Reg,
		HTTP:       a.cfg.sentryHTTP,
	})
	if err != nil {
		return err
	}
	pol := func(project string) *policy.Sentry {
		eff := a.Policy.For(project)
		if eff.Invalid != nil {
			return nil
		}
		return eff.Sentry
	}
	set, err := sentry.Adapters(sentry.Config{Client: cl, Policy: pol, Redactor: a.Reg})
	if err != nil {
		return err
	}
	for op, ad := range set {
		if _, taken := ads[op]; taken {
			return fmt.Errorf("chapd: op %s already has an adapter; the Sentry connector would replace it", op)
		}
		ads[op] = ad
	}
	return nil
}
