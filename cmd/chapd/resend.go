package main

import (
	"fmt"

	"github.com/joshua-noel/chaperone/internal/connectors/google"
	"github.com/joshua-noel/chaperone/internal/connectors/resend"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// This file wires the Resend connector: the Resend side of `mail.send` and the
// `mail.status` adapter. Both ops are off in the baseline. mail.send is the
// operation the Google connector already serves, so the two adapters go behind one
// ops.ByTarget and the request's target.adapter (`google` or `resend`) picks. The
// Resend side refuses a project whose policy file has no valid `resend:` block, so
// turning the name on does not turn Resend on. The operator's steps (the API key in
// the vault, the project's `resend:` block, the policy change) are in
// docs/runbooks/resend.md.

// installResend adds the Resend adapters when the vault is open. It must run after
// installGoogle: mail.send is then the Gmail adapter, and the Resend one joins it.
func (a *App) installResend(ads map[string]ops.Adapter) error {
	if a.vault == nil {
		return nil
	}
	cfg := resend.ClientConfig{
		SendKey:   resend.VaultCredential(a.vault, resend.SecretSendKey),
		StatusKey: resend.VaultCredential(a.vault, resend.SecretStatusKey),
		Registry:  a.Reg,
		HTTP:      a.cfg.resendHTTP,
	}
	cl, err := resend.NewClient(cfg)
	if err != nil {
		return err
	}
	pol := func(project string) *policy.Resend {
		eff := a.Policy.For(project)
		if eff.Invalid != nil {
			return nil
		}
		return eff.Resend
	}
	set, err := resend.Adapters(resend.Config{Client: cl, Policy: pol, Redactor: a.Reg})
	if err != nil {
		return err
	}
	for op, ad := range set {
		prev, taken := ads[op]
		switch {
		case op == resend.OpSend:
			// One name, two connectors: Gmail's mail.send (target google) and Resend's
			// (target resend). The request's target.adapter picks. A name that another
			// adapter holds that is not Gmail's is a wiring mistake, and chapd stops.
			by := ops.ByTarget{resend.AdapterName: ad}
			if taken {
				if _, isGmail := prev.(*google.Gmail); !isGmail {
					return fmt.Errorf("chapd: op %s already has an adapter that is not Gmail's; the Resend connector would replace it", op)
				}
				by["google"] = prev
			}
			ads[op] = by
		case taken:
			return fmt.Errorf("chapd: op %s already has an adapter; the Resend connector would replace it", op)
		default:
			ads[op] = ad
		}
	}
	return nil
}
