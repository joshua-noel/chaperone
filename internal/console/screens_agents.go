package console

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/joshua-noel/chaperone/internal/keys"
	"github.com/joshua-noel/chaperone/internal/ops"
)

// Agents (ADR-008): "the agent asks, you tap". Your own agents ask for keys; here
// you enrol an agent, answer what it asks (Grant as asked, Narrow, or Deny), and make a live key last longer with
// one tap. Every tap that would make or change a key only starts a card: the key is made, or its life changed,
// when you sign that card with Windows Hello on the approvals page. A form post alone never makes one.
//
// The pages are never framed (they are not in framablePaths), and an agent's words (its reason) are shown as text
// with a label that says the agent wrote them.

// KeyDecisions is what these screens need from the keys package: the person's own agents, and nothing else.
type KeyDecisions = keys.Decider

type reqView struct {
	ID, Holder, Project, Kind, State string
	Ops, Units, For, Reason          string
	Rate                             int
	Needed                           bool
	Created, Expires                 string
	DenyReason, Granted, Removed     string
	KeyID                            string
}

func hoursText(h int) string {
	switch {
	case h%24 == 0 && h/24 == 1:
		return "1 day"
	case h%24 == 0:
		return fmt.Sprintf("%d days", h/24)
	case h == 1:
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", h)
}

func listText(l []string) string {
	if len(l) == 0 {
		return "(none)"
	}
	return strings.Join(l, ", ")
}

func viewOfRequest(r ops.KeyRequestInfo) reqView {
	v := reqView{
		ID: r.ID, Holder: r.Holder, Project: r.Project, Kind: r.Kind, State: r.State,
		Ops: listText(r.Ops), Units: listText(r.Units), For: hoursText(r.TTLHours), Reason: r.Reason,
		Rate: r.RatePerHour, Needed: r.NeededToday, Created: r.CreatedAt, Expires: r.ExpiresAt,
		DenyReason: r.DenyReason, KeyID: r.KeyID,
	}
	if r.Granted != nil {
		v.Granted = fmt.Sprintf("%s for %s at most %d calls an hour", listText(r.Granted.Ops), hoursText(r.Granted.TTLHours), r.Granted.RatePerHour)
	}
	if r.Removed != nil {
		var parts []string
		if len(r.Removed.Ops) > 0 {
			parts = append(parts, "ops "+strings.Join(r.Removed.Ops, ", "))
		}
		if len(r.Removed.Units) > 0 {
			parts = append(parts, "repositories "+strings.Join(r.Removed.Units, ", "))
		}
		if r.Removed.TTLHours > 0 {
			parts = append(parts, hoursText(r.Removed.TTLHours)+" of time")
		}
		if r.Removed.RatePerHour > 0 {
			parts = append(parts, fmt.Sprintf("%d calls an hour", r.Removed.RatePerHour))
		}
		v.Removed = strings.Join(parts, "; ")
	}
	return v
}

type agentKeyView struct {
	ID, Holder, Project, State, Ops, Units, Expires, LastUsed string
	Uses                                                      int
	CanExtend                                                 bool
}

type agentsView struct {
	shell
	On      bool
	Pending []reqView
	Recent  []reqView
	Keys    []agentKeyView
}

type agentRequestView struct {
	shell
	Request reqView
	Ops     []string
	Units   []string
	Hours   []hourChoice
	Rate    int
}

type hourChoice struct {
	Hours    int
	Label    string
	Selected bool
}

type agentEnrolView struct {
	shell
	Code, Label, Project string
	Expires              string
}

// keysOn answers a call when chapd runs without agent keys.
func (s *screens) keysOn() bool { return s.cfg.Keys != nil }

func (s *screens) agentsPage(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok {
		return
	}
	v := agentsView{shell: s.shell(st, "Agents"), On: s.keysOn()}
	if !v.On {
		s.page(w, http.StatusOK, "agents", v)
		return
	}
	ctx, me := r.Context(), approverSpecID(st.user)
	pending, err := s.cfg.Keys.Pending(ctx, me)
	if err != nil {
		s.fail(w, "list agent requests", err)
		return
	}
	for _, p := range pending {
		v.Pending = append(v.Pending, viewOfRequest(p))
	}
	recent, err := s.cfg.Keys.Recent(ctx, me)
	if err != nil {
		s.fail(w, "list answered agent requests", err)
		return
	}
	for _, p := range recent {
		v.Recent = append(v.Recent, viewOfRequest(p))
	}
	agentKeys, err := s.cfg.Keys.AgentKeys(ctx, me)
	if err != nil {
		s.fail(w, "list agent keys", err)
		return
	}
	for _, k := range agentKeys {
		last := k.LastUsedAt
		v.Keys = append(v.Keys, agentKeyView{
			ID: k.ID, Holder: k.Holder, Project: k.Project, State: k.State, Ops: listText(k.Ops), Units: listText(k.Units),
			Expires: k.ExpiresAt, LastUsed: last, Uses: k.Uses, CanExtend: k.State == "live" && k.GrantKind == keys.GrantSelf,
		})
	}
	s.page(w, http.StatusOK, "agents", v)
}

// keyRefusal answers a call with what the keys package says about it.
func (s *screens) keyRefusal(w http.ResponseWriter, target, title string, err error) {
	var re *keys.RuleError
	switch {
	case errors.Is(err, keys.ErrNotFound):
		s.sayAt(w, http.StatusNotFound, target, title, "There is no such request, enrolment or key for you.")
	case errors.Is(err, keys.ErrCodeLocked):
		s.sayAt(w, http.StatusTooManyRequests, target, title, "Too many wrong codes. Wait ten minutes, then try again.")
	case errors.As(err, &re):
		s.sayAt(w, http.StatusConflict, target, title, re.Why)
	default:
		s.c.log.Error("agent keys", "what", title, "err", err)
		s.sayAt(w, http.StatusServiceUnavailable, target, title, "chapd could not do that now; nothing was changed.")
	}
}

// toApprovals sends the browser to the card that was just made.
func toApprovals(w http.ResponseWriter) {
	w.Header().Set("HX-Redirect", "/approvals")
	w.WriteHeader(http.StatusNoContent)
}

// agentEnrolLookup is POST /agents/enrol/lookup: the owner typed the code the agent printed.
func (s *screens) agentEnrolLookup(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok || !s.needKeys(w, "#enrol-status") {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.sayAt(w, http.StatusBadRequest, "#enrol-status", "Not enrolled", "The form could not be read.")
		return
	}
	code := strings.TrimSpace(r.PostForm.Get("code"))
	e, err := s.cfg.Keys.LookupEnrol(r.Context(), approverSpecID(st.user), code)
	if errors.Is(err, keys.ErrNotFound) {
		s.sayAt(w, http.StatusNotFound, "#enrol-status", "No such code", "No enrolment is waiting for that code. Check the code the agent printed (it lasts 10 minutes), and type it again.")
		return
	}
	if err != nil {
		s.keyRefusal(w, "#enrol-status", "Not enrolled", err)
		return
	}
	v := agentEnrolView{shell: s.shell(st, "Enrol an agent"), Code: code, Label: e.Label, Project: e.Project, Expires: stamp(e.ExpiresAt)}
	s.fragment(w, http.StatusOK, "agent-enrol-confirm", v)
}

// agentEnrolApprove is POST /agents/enrol/approve: start the card that enrols the agent.
func (s *screens) agentEnrolApprove(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok || !s.needKeys(w, "#enrol-status") {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.sayAt(w, http.StatusBadRequest, "#enrol-status", "Not enrolled", "The form could not be read.")
		return
	}
	if _, err := s.cfg.Keys.ApproveEnrol(r.Context(), approverSpecID(st.user), r.PostForm.Get("code")); err != nil {
		s.keyRefusal(w, "#enrol-status", "Not enrolled", err)
		return
	}
	toApprovals(w)
}

func (s *screens) needKeys(w http.ResponseWriter, target string) bool {
	if s.keysOn() {
		return true
	}
	s.sayAt(w, http.StatusNotFound, target, "Agent keys are off", "This chapd runs without agent keys.")
	return false
}

var hourOptions = []int{1, 4, 8, 24, 72, 168, 336, 720}

func hourChoices(asked int) []hourChoice {
	var out []hourChoice
	have := false
	for _, h := range hourOptions {
		if h <= asked {
			out = append(out, hourChoice{Hours: h, Label: hoursText(h), Selected: h == asked})
			have = have || h == asked
		}
	}
	if !have {
		out = append(out, hourChoice{Hours: asked, Label: hoursText(asked), Selected: true})
	}
	return out
}

// agentRequestPage is GET /agents/requests/{id}: what the agent asked for, and the three answers.
func (s *screens) agentRequestPage(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok {
		return
	}
	if !s.keysOn() {
		s.page(w, http.StatusOK, "agents", agentsView{shell: s.shell(st, "Agents")})
		return
	}
	req, err := s.cfg.Keys.Request(r.Context(), approverSpecID(st.user), r.PathValue("id"))
	if errors.Is(err, keys.ErrNotFound) {
		s.c.render(w, r, http.StatusNotFound, "error", page{Title: "Page not found", Message: "There is no such request for you.", Approver: st.user.Name})
		return
	}
	if err != nil {
		s.fail(w, "read agent request", err)
		return
	}
	s.page(w, http.StatusOK, "agent_request", agentRequestView{
		shell: s.shell(st, "Answer a request"), Request: viewOfRequest(req), Ops: req.Ops, Units: req.Units,
		Hours: hourChoices(req.TTLHours), Rate: req.RatePerHour,
	})
}

// formNarrowing reads the narrowing form. It only reads: whether it is narrower than the ask is for the keys
// package to say, again, whatever the form claims.
func formNarrowing(r *http.Request) *keys.Narrowing {
	if r.PostForm.Get("mode") != "narrow" {
		return nil
	}
	n := &keys.Narrowing{Ops: r.PostForm["op"], Units: r.PostForm["unit"]}
	if n.Ops == nil {
		n.Ops = []string{}
	}
	if n.Units == nil {
		n.Units = []string{}
	}
	n.TTLHours, _ = strconv.Atoi(r.PostForm.Get("ttl"))
	n.Rate, _ = strconv.Atoi(r.PostForm.Get("rate"))
	return n
}

// agentRequestGrant is POST /agents/requests/{id}/grant.
func (s *screens) agentRequestGrant(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok || !s.needKeys(w, "#decision-status") {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.sayAt(w, http.StatusBadRequest, "#decision-status", "Not granted", "The form could not be read.")
		return
	}
	if _, err := s.cfg.Keys.Grant(r.Context(), approverSpecID(st.user), r.PathValue("id"), formNarrowing(r)); err != nil {
		s.keyRefusal(w, "#decision-status", "Not granted", err)
		return
	}
	toApprovals(w)
}

// agentRequestDeny is POST /agents/requests/{id}/deny.
func (s *screens) agentRequestDeny(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok || !s.needKeys(w, "#decision-status") {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.sayAt(w, http.StatusBadRequest, "#decision-status", "Not denied", "The form could not be read.")
		return
	}
	if _, err := s.cfg.Keys.Deny(r.Context(), approverSpecID(st.user), r.PathValue("id"), r.PostForm.Get("reason")); err != nil {
		s.keyRefusal(w, "#decision-status", "Not denied", err)
		return
	}
	w.Header().Set("HX-Redirect", "/agents")
	w.WriteHeader(http.StatusNoContent)
}

// agentKeyExtend is POST /agents/keys/{id}/extend: one tap, then the card.
func (s *screens) agentKeyExtend(w http.ResponseWriter, r *http.Request) {
	st, ok := s.user(w, r)
	if !ok || !s.needKeys(w, "#agents-status") {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.sayAt(w, http.StatusBadRequest, "#agents-status", "Not extended", "The form could not be read.")
		return
	}
	hours, _ := strconv.Atoi(r.PostForm.Get("hours"))
	if hours == 0 {
		hours = 24
	}
	if _, err := s.cfg.Keys.Extend(r.Context(), approverSpecID(st.user), r.PathValue("id"), hours); err != nil {
		s.keyRefusal(w, "#agents-status", "Not extended", err)
		return
	}
	toApprovals(w)
}
