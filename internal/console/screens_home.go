package console

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/joshua-noel/chaperone/internal/approvals"
	"github.com/joshua-noel/chaperone/internal/denialtext"
	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// Home: what needs the operator now (pending approvals), what went wrong
// lately (recent denials), whether chapd is healthy, and Stop all.

type healthItem struct {
	Name, State, Detail string // State is OK, WARN or FAIL: words, never colour alone
}

// Variant is the Basecoat badge variant of the state.
func (h healthItem) Variant() string {
	switch h.State {
	case "FAIL":
		return "destructive"
	case "WARN":
		return "outline"
	}
	return "secondary"
}

type pendingRow struct {
	ID, Op, Project, Requester, Expires string
	// Who, What and Risk are read from the card text, as on the Approvals screen.
	Who, What, Risk string
	Critical        bool
	// Stale is why this merge would be refused now, or "" (see stale.go); chrome, not part of the card.
	Stale string
}

// RiskTone is the badge colour for the risk word; the word stays on the badge.
func (p pendingRow) RiskTone() string { return cardView{Risk: p.Risk}.RiskTone() }

type denialRow struct {
	When, Code, Surface, Who, Project, Text string
	// Plain says what the cause code means and Next what to do, from the table the chap command line prints too
	// (internal/denialtext). Neither is in the signed ledger: they are read from the code when the page is drawn.
	Plain, Next string
}

type homeView struct {
	shell
	Version       string
	Health        []healthItem
	Pending       []pendingRow
	Denials       []denialRow
	ActiveRuns    string
	ActiveRunsNum int
	Credentials   []credView
}

const runListMax = 500 // the largest page runtoken.Runs.List returns

// activeRuns counts active runs; more is true when there are more than the
// largest page.
func (s *screens) activeRuns(ctx context.Context) (n int, more bool, err error) {
	runs, next, err := s.cfg.Runs.List(ctx, "active", runListMax, "")
	return len(runs), next != "", err
}

func (s *screens) healthItems(ctx context.Context, active string, pending int) []healthItem {
	var out []healthItem
	add := func(name, state, detail string) { out = append(out, healthItem{name, state, detail}) }

	if err := s.c.db.SQL().PingContext(ctx); err != nil {
		s.c.log.Error("health: database", "err", err)
		add("Database", "FAIL", "the state database does not answer")
	} else {
		add("Database", "OK", "answers")
	}

	if seq, hash, err := s.cfg.Ledger.Head(ctx); err != nil {
		s.c.log.Error("health: ledger head", "err", err)
		add("Ledger", "FAIL", "the ledger cannot be read; ops fail closed until it can (see the log)")
	} else {
		add("Ledger", "OK", fmt.Sprintf("chain %s, head seq %d, %s", s.cfg.Ledger.Chain(), seq, clip(hash, 23)))
	}

	add("Active runs", "OK", active)
	add("Pending approvals", "OK", fmt.Sprintf("%d waiting", pending))

	if orchs, err := s.cfg.Orch.List(ctx); err != nil {
		s.c.log.Error("health: orchestrators", "err", err)
		add("Orchestrator token", "FAIL", "cannot list orchestrator tokens (see the log)")
	} else {
		live := 0
		now := s.c.now()
		for _, o := range orchs {
			if o.Live(now) {
				live++
			}
		}
		if live == 0 {
			add("Orchestrator token", "WARN", "no live token: the orchestrator cannot ask for anything (chapd orch issue)")
		} else {
			add("Orchestrator token", "OK", fmt.Sprintf("%d live", live))
		}
	}

	if s.cfg.Vault == nil {
		add("Vault", "WARN", "not configured")
	} else if secrets, err := s.cfg.Vault.List(ctx); err != nil {
		s.c.log.Error("health: vault", "err", err)
		add("Vault", "FAIL", "cannot list secrets (see the log)")
	} else {
		add("Vault", "OK", fmt.Sprintf("%d secrets", len(secrets)))
	}

	projects, err := s.knownProjects(ctx)
	if err != nil {
		s.c.log.Error("health: projects", "err", err)
		add("Policy", "FAIL", "cannot list projects (see the log)")
	} else {
		var bad []string
		for _, p := range projects {
			if s.cfg.Policy.For(p).Invalid != nil {
				bad = append(bad, p)
			}
		}
		if len(bad) > 0 {
			add("Policy", "FAIL", "the policy file of "+strings.Join(bad, ", ")+" is invalid: every op of it is refused")
		} else {
			add("Policy", "OK", "baseline "+s.cfg.Policy.Baseline().BaselineVersion())
		}
	}

	if s.cfg.Version != "" {
		add("chapd", "OK", "version "+s.cfg.Version)
	}
	return out
}

func (s *screens) recentDenials(ctx context.Context, n int) ([]denialRow, error) {
	evs, _, err := s.newestEvents(ctx, ledger.QueryParams{EventName: "denial"}, n, nil)
	if err != nil {
		return nil, err
	}
	var out []denialRow
	for _, e := range evs {
		body := bodyOf(e)
		who := "orchestrator"
		if e.RunID != "" {
			who = "run " + e.RunID
		} else if id := attrString(e, "factory.orchestrator.id"); id != "" {
			who = "orchestrator " + id
		}
		code := attrString(e, "factory.cause_code")
		out = append(out, denialRow{
			When: stamp(eventTime(e)), Code: code, Surface: attrString(e, "factory.surface"),
			Who: who, Project: e.Project, Text: clip(strings.TrimSuffix(body, ": "+code), 200),
			Plain: denialtext.Plain(code), Next: denialtext.NextStep(code, "", attrString(e, "factory.orchestrator.id")),
		})
	}
	return out, nil
}

func (s *screens) pendingRows(ctx context.Context) ([]pendingRow, error) {
	pending, err := s.c.appr.Pending(ctx)
	if err != nil {
		return nil, err
	}
	var out []pendingRow
	sort.SliceStable(pending, func(i, j int) bool { return pending[i].RequestExpires.Before(pending[j].RequestExpires) })
	stale := s.c.staleFlags(ctx, pending)
	for _, a := range pending {
		who, what, _, _ := askOf(a)
		out = append(out, pendingRow{Stale: stale[a.ID].Why, ID: a.ID, Op: a.Op, Project: a.Project, Requester: requesterLabel(a),
			Expires: stamp(a.RequestExpires), Critical: a.Critical(), Who: who, What: what, Risk: approvals.Risk(a)})
	}
	return out, nil
}

// home is GET /.
func (s *screens) home(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	creds, err := s.c.credentialsOf(ctx, st.user.ID)
	if err != nil {
		s.fail(w, "list credentials", err)
		return
	}
	pending, err := s.pendingRows(ctx)
	if err != nil {
		s.fail(w, "list pending approvals", err)
		return
	}
	denials, err := s.recentDenials(ctx, 10)
	if err != nil {
		s.fail(w, "list recent denials", err)
		return
	}
	n, more, err := s.activeRuns(ctx)
	if err != nil {
		s.fail(w, "count active runs", err)
		return
	}
	active := fmt.Sprintf("%d", n)
	if more {
		active += " or more"
	}
	v := homeView{
		shell: s.shell(st, "Console"), Version: s.cfg.Version, Pending: pending, Denials: denials,
		ActiveRuns: active, ActiveRunsNum: n,
		Health: s.healthItems(ctx, active, len(pending)),
	}
	for _, cr := range creds {
		v.Credentials = append(v.Credentials, credView{cr.Label, cr.RPID, cr.Origin, cr.Created, cr.LastUsed})
	}
	s.page(w, http.StatusOK, "dashboard", v)
}

// stopAll is POST /stop-all: revoke every active run (OPERATOR_STOP_ALL). The
// orchestrator's token is not touched; the runs' pending approvals are
// cancelled by the registry's end hook, as for any run end.
func (s *screens) stopAll(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.user(w, r); !ok {
		return
	}
	n, err := s.cfg.Runs.RevokeAll(r.Context(), runtoken.StopOperatorStopAll)
	if err != nil {
		s.c.log.Error("stop all", "revoked", n, "err", err)
		s.say(w, http.StatusInternalServerError, "Stop all failed",
			fmt.Sprintf("%d run(s) were revoked before an error. Some runs may still be active: check Runs and try again. The log has the detail.", n))
		return
	}
	s.c.log.Warn("operator stop all", "revoked", n, "code", runtoken.StopOperatorStopAll)
	switch n {
	case 0:
		s.say(w, http.StatusOK, "Nothing to stop", "No run was active.")
	default:
		s.say(w, http.StatusOK, "All runs stopped",
			fmt.Sprintf("%d run(s) revoked (%s). Their tokens are refused from the next request. The orchestrator token is unchanged.", n, runtoken.StopOperatorStopAll))
	}
}
