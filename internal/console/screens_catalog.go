package console

import (
	"context"
	"net/http"

	"github.com/joshua-noel/chaperone/internal/policy"
)

// Operations catalog: read-only. Which ops exist, their class, whether each is
// enabled in the baseline and in each project's policy, the policy version in
// force, and how often each was asked for. Enabling an op is a policy change
// in the repository (ADR-001), never a click here, so the page has no form.

type catalogCell struct {
	Label   string // the column name: Baseline or a project, shown beside the value on a phone
	Text    string // enabled, disabled or refused
	Enabled bool
	Rate    int
}

type catalogRow struct {
	Op, Class, Reversibility, Surface, Summary, Usage string
	NeedsApproval                                     bool
	Cells                                             []catalogCell // baseline first, then one per project
	Requests                                          int64
	Last                                              string
}

type catalogProject struct {
	Name, Version, Invalid string
}

type catalogView struct {
	shell
	BaselineVersion string
	Projects        []catalogProject
	Rows            []catalogRow
}

type opUsage struct {
	count int64
	last  int64
}

func (s *screens) opUsage(ctx context.Context) (map[string]opUsage, error) {
	rows, err := s.c.db.SQL().QueryContext(ctx, `SELECT op, COUNT(*), COALESCE(MAX(requested_at), 0) FROM ops GROUP BY op`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]opUsage{}
	for rows.Next() {
		var op string
		var u opUsage
		if err := rows.Scan(&op, &u.count, &u.last); err != nil {
			return nil, err
		}
		out[op] = u
	}
	return out, rows.Err()
}

// catalogPage is GET /catalog.
func (s *screens) catalogPage(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	usage, err := s.opUsage(ctx)
	if err != nil {
		s.fail(w, "catalog usage", err)
		return
	}
	projects, err := s.knownProjects(ctx)
	if err != nil {
		s.fail(w, "catalog projects", err)
		return
	}
	base := s.cfg.Policy.Baseline()
	v := catalogView{shell: s.shell(st, "Operations"), BaselineVersion: base.BaselineVersion()}
	effective := make([]*catalogEff, 0, len(projects))
	for _, p := range projects {
		e := s.cfg.Policy.For(p)
		cp := catalogProject{Name: p, Version: e.Version}
		if e.Invalid != nil {
			cp.Invalid = "invalid policy file: every op of this project is refused"
		}
		v.Projects = append(v.Projects, cp)
		effective = append(effective, &catalogEff{invalid: e.Invalid != nil, ops: e.Ops})
	}
	cat := s.cfg.Policy.Catalog()
	for _, op := range cat.Ops() {
		ent, _ := cat.Lookup(op)
		row := catalogRow{
			Op: op, Class: string(ent.Class), Reversibility: ent.Reversibility, Surface: ent.Surface,
			Summary: ent.Summary, Usage: ent.Usage, NeedsApproval: ent.Class.NeedsApproval(),
		}
		rule := base.Ops[op]
		row.Cells = append(row.Cells, cell("Baseline", rule.Enabled, false, rule.RatePerMinute))
		for i, e := range effective {
			r := e.ops[op]
			row.Cells = append(row.Cells, cell(v.Projects[i].Name, r.Enabled, e.invalid, r.RatePerMinute))
		}
		if u, ok := usage[op]; ok {
			row.Requests, row.Last = u.count, unixStamp(u.last)
		}
		v.Rows = append(v.Rows, row)
	}
	s.page(w, http.StatusOK, "catalog", v)
}

type catalogEff struct {
	invalid bool
	ops     map[string]policy.OpRule
}

func cell(label string, enabled, invalid bool, rate int) catalogCell {
	switch {
	case invalid:
		return catalogCell{Label: label, Text: "refused"}
	case enabled:
		return catalogCell{Label: label, Text: "enabled", Enabled: true, Rate: rate}
	}
	return catalogCell{Label: label, Text: "disabled"}
}
