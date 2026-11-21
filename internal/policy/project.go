package policy

import (
	"fmt"
	"slices"
)

// narrowOp is one op in a project file. A nil member is "not mentioned".
type narrowOp struct {
	Enabled       *bool `yaml:"enabled"`
	RatePerMinute *int  `yaml:"rate_per_minute"`
	RatePerHour   *int  `yaml:"rate_per_hour"`
}

type narrowFile struct {
	Project string              `yaml:"project"`
	Ops     map[string]narrowOp `yaml:"ops"`
	Profile map[string][]string `yaml:"profiles"`
	Limits  struct {
		Thrash struct {
			Threshold     *int `yaml:"threshold"`
			WindowSeconds *int `yaml:"window_seconds"`
		} `yaml:"thrash"`
		Pending struct {
			PerRun     *int `yaml:"per_run"`
			PerProject *int `yaml:"per_project"`
			Total      *int `yaml:"total"`
		} `yaml:"pending"`
		RequestTTLMinutes *int `yaml:"request_ttl_minutes"`
		DeployTTLMinutes  *int `yaml:"deploy_ttl_minutes"`
	} `yaml:"limits"`
	// PR is the merge policy of the project (ADR-002). It is the only part of a
	// project file that adds something instead of narrowing, and it adds only
	// requirements: a merge base, more required checks, more paths in a tier.
	// It never turns an op on; without a `pr:` block pr.merge and pr.update
	// refuse the project (the adapter checks).
	PR *struct {
		Repo        string   `yaml:"repo"`
		Base        string   `yaml:"base"`
		ExtraChecks []string `yaml:"extra_checks"`
		Tiers       struct {
			High   []string `yaml:"high"`
			Medium []string `yaml:"medium"`
			Low    []string `yaml:"low"`
		} `yaml:"tiers"`
		// LocalCI accepts a local CI result as a required check (ADR-002 amendment 10).
		LocalCI *struct {
			Mode  string `yaml:"mode"`
			Check string `yaml:"check"`
		} `yaml:"local_ci"`
	} `yaml:"pr"`
	// Google is the connector policy of the project (L1-16): who mail and
	// Drive shares may go to. Like `pr:` it only adds data; it never turns an
	// op on.
	Google *struct {
		Mail struct {
			AllowRecipients []string `yaml:"allow_recipients"`
		} `yaml:"mail"`
		Drive struct {
			AllowRecipients []string `yaml:"allow_recipients"`
			MaxRole         string   `yaml:"max_role"`
		} `yaml:"drive"`
	} `yaml:"google"`
	// Linear is the operator-board intake of the project: the one
	// team, the one label and the states intake.move may set. Like `google:`
	// it only adds data; it never turns an op on.
	Linear *struct {
		Team   string   `yaml:"team"`
		Label  string   `yaml:"label"`
		States []string `yaml:"states"`
		// Issues is the optional block of the generic issue ops (never the
		// operator board; see LinearIssues).
		Issues *struct {
			Team        string   `yaml:"team"`
			Label       string   `yaml:"label"`
			States      []string `yaml:"states"`
			Labels      []string `yaml:"labels"`
			LinkHosts   []string `yaml:"link_hosts"`
			MaxMentions int      `yaml:"max_mentions"`
			Comment     bool     `yaml:"comment"`
		} `yaml:"issues"`
	} `yaml:"linear"`
	// Sentry is the connector policy of the project: the Sentry server and
	// organisation, the project slugs the errors.* ops may touch and the members
	// errors.assign may assign to. Like `linear:` it only adds data; it never turns
	// an op on. A mistake in it turns off the Sentry ops only (see Sentry.Invalid).
	Sentry *struct {
		BaseURL      string   `yaml:"base_url"`
		Organization string   `yaml:"organization"`
		Projects     []string `yaml:"projects"`
		Assignees    []string `yaml:"assignees"`
	} `yaml:"sentry"`
	// Resend is the connector policy of the project for mail.send and mail.status when the target adapter is
	// `resend`: the sender addresses, who may receive mail and the cap on recipients. Like `sentry:` it only adds
	// data; it never turns an op on. A mistake in it turns off the Resend side only (see Resend.Invalid).
	Resend *struct {
		Senders         []string `yaml:"senders"`
		AllowRecipients []string `yaml:"allow_recipients"`
		MaxRecipients   *int     `yaml:"max_recipients"`
	} `yaml:"resend"`
}

// LoadProject applies a project file to the baseline. The file may only
// narrow: turn an op off, lower a rate, lower a cap or TTL, raise the thrash
// window, lower the thrash threshold, shrink a profile ceiling. Anything else
// (turning an op on, raising a number, an unknown op or key, a project name
// that differs from the one asked for) refuses the whole file.
func (p *Pack) LoadProject(project string, data []byte, cat *Catalog) (*Effective, error) {
	var f narrowFile
	if err := strictYAML(data, &f); err != nil {
		return nil, fmt.Errorf("policy: project %s: %w", project, err)
	}
	if !projectRe.MatchString(project) {
		return nil, fmt.Errorf("policy: project %q is not a project slug", project)
	}
	if f.Project != project {
		return nil, fmt.Errorf("policy: project %s: file says project %q", project, f.Project)
	}
	eff := p.ForProject(project)
	eff.Version = p.version(data)

	for op, n := range f.Ops {
		base, ok := p.Ops[op]
		if !ok {
			return nil, fmt.Errorf("policy: project %s: unknown op %s", project, op)
		}
		cur := eff.Ops[op]
		if n.Enabled != nil {
			if *n.Enabled && !base.Enabled {
				return nil, fmt.Errorf("policy: project %s: %s: a project file cannot enable an op (the baseline has it off)", project, op)
			}
			cur.Enabled = *n.Enabled && base.Enabled
		}
		if n.RatePerMinute != nil {
			if *n.RatePerMinute < 1 || *n.RatePerMinute > base.RatePerMinute {
				return nil, fmt.Errorf("policy: project %s: %s: rate_per_minute %d is outside 1..%d", project, op, *n.RatePerMinute, base.RatePerMinute)
			}
			cur.RatePerMinute = *n.RatePerMinute
		}
		if n.RatePerHour != nil {
			// A project may add an hourly cap or lower one; it never lifts one.
			if *n.RatePerHour < 1 || base.RatePerHour > 0 && *n.RatePerHour > base.RatePerHour {
				return nil, fmt.Errorf("policy: project %s: %s: rate_per_hour %d is outside 1..%d", project, op, *n.RatePerHour, base.RatePerHour)
			}
			cur.RatePerHour = *n.RatePerHour
		}
		eff.Ops[op] = cur
	}

	for name, allow := range f.Profile {
		baseAllow, ok := p.Profiles[name]
		if !ok {
			return nil, fmt.Errorf("policy: project %s: unknown profile %s", project, name)
		}
		for _, op := range allow {
			if !slices.Contains(baseAllow, op) {
				return nil, fmt.Errorf("policy: project %s: profile %s cannot gain %s", project, name, op)
			}
		}
		eff.Profiles[name] = slices.Clone(allow)
	}

	l := &eff.Limits
	if err := lowerOnly(project, "limits.thrash.threshold", f.Limits.Thrash.Threshold, &l.Thrash.Threshold); err != nil {
		return nil, err
	}
	if v := f.Limits.Thrash.WindowSeconds; v != nil {
		if *v < l.Thrash.WindowSeconds {
			return nil, fmt.Errorf("policy: project %s: limits.thrash.window_seconds %d is below the baseline %d (a shorter window is looser)", project, *v, l.Thrash.WindowSeconds)
		}
		l.Thrash.WindowSeconds = *v
	}
	for _, c := range []struct {
		name string
		in   *int
		out  *int
	}{
		{"limits.pending.per_run", f.Limits.Pending.PerRun, &l.Pending.PerRun},
		{"limits.pending.per_project", f.Limits.Pending.PerProject, &l.Pending.PerProject},
		{"limits.pending.total", f.Limits.Pending.Total, &l.Pending.Total},
		{"limits.request_ttl_minutes", f.Limits.RequestTTLMinutes, &l.RequestTTLMinutes},
		{"limits.deploy_ttl_minutes", f.Limits.DeployTTLMinutes, &l.DeployTTLMinutes},
	} {
		if err := lowerOnly(project, c.name, c.in, c.out); err != nil {
			return nil, err
		}
	}

	if f.PR != nil {
		pr := &PR{Repo: f.PR.Repo, Base: f.PR.Base, ExtraChecks: slices.Clone(f.PR.ExtraChecks)}
		if l := f.PR.LocalCI; l != nil {
			pr.LocalCI = &LocalCI{Mode: l.Mode, Check: l.Check}
			if pr.LocalCI.Check == "" {
				pr.LocalCI.Check = DefaultLocalCICheck
			}
		}
		pr.Tiers.High, pr.Tiers.Medium, pr.Tiers.Low = slices.Clone(f.PR.Tiers.High), slices.Clone(f.PR.Tiers.Medium), slices.Clone(f.PR.Tiers.Low)
		if err := pr.validate(); err != nil {
			return nil, fmt.Errorf("policy: project %s: pr: %w", project, err)
		}
		// A bad tier glob turns off the merge ops only, not the project: the rest of the file is fine.
		pr.Invalid = pr.tierProblem(project)
		eff.PR = pr
	}
	if f.Google != nil {
		g := &Google{}
		g.Mail.AllowRecipients = slices.Clone(f.Google.Mail.AllowRecipients)
		g.Drive.AllowRecipients = slices.Clone(f.Google.Drive.AllowRecipients)
		g.Drive.MaxRole = f.Google.Drive.MaxRole
		if err := g.validate(); err != nil {
			return nil, fmt.Errorf("policy: project %s: google: %w", project, err)
		}
		eff.Google = g
	}
	if f.Linear != nil {
		l := &Linear{Team: f.Linear.Team, Label: f.Linear.Label, States: slices.Clone(f.Linear.States)}
		if in := f.Linear.Issues; in != nil {
			l.Issues = &LinearIssues{
				Team: in.Team, Label: in.Label, States: slices.Clone(in.States), Labels: slices.Clone(in.Labels),
				LinkHosts: slices.Clone(in.LinkHosts), MaxMentions: in.MaxMentions, Comment: in.Comment,
			}
		}
		if err := l.validate(); err != nil {
			return nil, fmt.Errorf("policy: project %s: linear: %w", project, err)
		}
		// A bad issues block turns off the Linear issue operations only, not the project and not the intake.
		if l.IssuesInvalid = l.issuesProblem(project); l.IssuesInvalid != nil {
			l.Issues = nil
		}
		eff.Linear = l
	}
	if f.Sentry != nil {
		s := &Sentry{
			BaseURL: f.Sentry.BaseURL, Organization: f.Sentry.Organization,
			Projects: slices.Clone(f.Sentry.Projects), Assignees: slices.Clone(f.Sentry.Assignees),
		}
		// A bad block turns off the Sentry operations only, not the project: the rest of the file is fine. The fields
		// are cleared, so a block that cannot be used is never half usable.
		if err := s.problem(project); err != nil {
			s = &Sentry{Invalid: err}
		}
		eff.Sentry = s
	}
	if f.Resend != nil {
		r := &Resend{
			Senders: slices.Clone(f.Resend.Senders), AllowRecipients: slices.Clone(f.Resend.AllowRecipients),
			MaxRecipients: ResendDefaultMaxRecipients,
		}
		if f.Resend.MaxRecipients != nil {
			r.MaxRecipients = *f.Resend.MaxRecipients
		}
		// A bad block turns off the Resend side only, not the project and not mail through Gmail. The fields are
		// cleared, so a block that cannot be used is never half usable.
		if err := r.problem(project); err != nil {
			r = &Resend{Invalid: err}
		}
		eff.Resend = r
	}
	return eff, nil
}

func lowerOnly(project, name string, in, out *int) error {
	if in == nil {
		return nil
	}
	if *in < 1 || *in > *out {
		return fmt.Errorf("policy: project %s: %s %d is outside 1..%d", project, name, *in, *out)
	}
	*out = *in
	return nil
}
