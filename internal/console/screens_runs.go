package console

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// Runs: the active runs with a Revoke button each, the last few that ended,
// and the orchestrator tokens with "Revoke orchestrator" (ADR-007 item 7).
// Revoking takes authority away, so the session is enough; the browser asks
// first. The page shows a token's fingerprint, never the token.

type runRow struct {
	RunID, Project, Profile, Registered, Expires string
	Ended, EndReason, EndCause                   string
	Active, Interim                              bool
	Framed                                       bool // shown in a frame: no Revoke button
	Restricted                                   bool // a restricted load: no Revoke button and no link at all, only "Re-open to revoke"
}

type orchRow struct {
	ID, Fingerprint, Projects, Ops, Issued, Expires, Status, RevokedBy string
	MintInterim, Live                                                  bool
	Framed                                                             bool // shown in a frame: no Revoke button
	Restricted                                                         bool // a restricted load: no Revoke button and no link at all
}

type runsView struct {
	shell
	Active     []runRow
	ActiveMore bool
	Ended      []runRow
	Orchs      []orchRow
}

var (
	runIDPat  = regexp.MustCompile(`^r-[0-9a-z]{4,32}$`)
	orchIDPat = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
)

const endedRunsShown = 10

func runRowOf(r runtoken.RunRecord) runRow {
	return runRow{
		RunID: r.RunID, Project: r.Project, Profile: r.Claims.Profile.Name + "@" + r.Claims.Profile.Version,
		Registered: stamp(r.RegisteredAt), Expires: unixStamp(r.Exp), Ended: stamp(r.EndedAt),
		EndReason: r.EndReason, EndCause: r.EndCauseCode, Active: r.State == "active", Interim: r.Interim,
	}
}

func (s *screens) orchRowOf(o runtoken.OrchInfo) orchRow {
	row := orchRow{
		ID: o.ID, Fingerprint: o.Fingerprint, Projects: join(o.Scope.Projects), Ops: join(o.Scope.Ops),
		MintInterim: o.Scope.MintInterim, Issued: stamp(o.IssuedAt), Expires: stamp(o.ExpiresAt),
		Live: o.Live(s.c.now()), RevokedBy: o.RevokedBy,
	}
	switch {
	case !o.RevokedAt.IsZero():
		row.Status = "revoked " + stamp(o.RevokedAt)
	case !row.Live:
		row.Status = "expired"
	default:
		row.Status = "live"
	}
	return row
}

// runsPage is GET /runs.
func (s *screens) runsPage(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	// In a frame there is no Revoke at all (it is a session and CSRF action, not Hello-signed): the row says it opens
	// in Chaperone's own window instead. The frame is known from the request, never from the page. A restricted load (see
	// Console.restricted) gets the same page: no Revoke button until the operator re-opens it.
	framed := s.c.framable(r) || st.restricted
	v := runsView{shell: s.shell(st, "Runs")}
	active, next, err := s.cfg.Runs.List(ctx, "active", runListMax, "")
	if err != nil {
		s.fail(w, "list active runs", err)
		return
	}
	v.ActiveMore = next != ""
	for _, rec := range active {
		row := runRowOf(rec)
		row.Framed = framed
		row.Restricted = st.restricted
		v.Active = append(v.Active, row)
	}
	ended, _, err := s.cfg.Runs.List(ctx, "ended", endedRunsShown, "")
	if err != nil {
		s.fail(w, "list ended runs", err)
		return
	}
	for _, rec := range ended {
		v.Ended = append(v.Ended, runRowOf(rec))
	}
	orchs, err := s.cfg.Orch.List(ctx)
	if err != nil {
		s.fail(w, "list orchestrators", err)
		return
	}
	for _, o := range orchs {
		row := s.orchRowOf(o)
		row.Framed = framed
		row.Restricted = st.restricted
		v.Orchs = append(v.Orchs, row)
	}
	s.page(w, http.StatusOK, "runs", v)
}

// sayAt answers an htmx call with a notice that is swapped into target rather
// than into the clicked element (an error must not replace a table row).
func (s *screens) sayAt(w http.ResponseWriter, status int, target, title, text string) {
	w.Header().Set("HX-Retarget", target)
	w.Header().Set("HX-Reswap", "innerHTML")
	s.say(w, status, title, text)
}

// runRevoke is POST /runs/{id}/revoke.
func (s *screens) runRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.user(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if !runIDPat.MatchString(id) {
		s.sayAt(w, http.StatusBadRequest, "#runs-status", "Not a run id", "The run id is malformed.")
		return
	}
	switch err := s.cfg.Runs.Revoke(r.Context(), id, runtoken.StopOperatorStopRun); {
	case errors.Is(err, runtoken.ErrNotFound):
		s.sayAt(w, http.StatusNotFound, "#runs-status", "No such run", "Run "+id+" is not registered.")
		return
	case err != nil:
		s.c.log.Error("revoke run", "run", id, "err", err)
		s.sayAt(w, http.StatusInternalServerError, "#runs-status", "Revoke failed",
			"Run "+id+" may still be active. Reload and try again; the log has the detail.")
		return
	}
	s.c.log.Warn("operator revoked a run", "run", id, "code", runtoken.StopOperatorStopRun)
	rec, err := s.cfg.Runs.Get(r.Context(), id)
	if err != nil {
		s.fail(w, "get revoked run", err)
		return
	}
	s.fragment(w, http.StatusOK, "run-row", runRowOf(rec))
}

// orchRevoke is POST /orchestrators/{id}/revoke: "Revoke orchestrator".
func (s *screens) orchRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.user(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	if !orchIDPat.MatchString(id) {
		s.sayAt(w, http.StatusBadRequest, "#runs-status", "Not an orchestrator id", "The orchestrator id is malformed.")
		return
	}
	switch err := s.cfg.Orch.Revoke(r.Context(), id, "console"); {
	case errors.Is(err, runtoken.ErrNotFound):
		s.sayAt(w, http.StatusNotFound, "#runs-status", "Nothing to revoke", "The orchestrator "+id+" has no live token.")
		return
	case err != nil:
		s.c.log.Error("revoke orchestrator", "id", id, "err", err)
		s.sayAt(w, http.StatusInternalServerError, "#runs-status", "Revoke failed",
			"The token of "+id+" may still be live. Reload and try again; the log has the detail.")
		return
	}
	s.c.log.Warn("operator revoked the orchestrator token", "id", id)
	orchs, err := s.cfg.Orch.List(r.Context())
	if err != nil {
		s.fail(w, "list orchestrators", err)
		return
	}
	for _, o := range orchs { // newest first: the first row of this id is the one just revoked
		if strings.EqualFold(o.ID, id) {
			s.fragment(w, http.StatusOK, "orch-row", s.orchRowOf(o))
			return
		}
	}
	s.say(w, http.StatusOK, "Orchestrator revoked", "The token of "+id+" is revoked.")
}
