// Package lineartest is a fake Linear for the connector's tests: the OAuth
// client_credentials token endpoint (HTTP Basic client authentication, a
// token that ends) and a GraphQL endpoint that answers the connector's fixed
// operations (the five intake documents and the seven of the generic issue
// ops), by `operationName` and variables. It never talks to the
// network. Tests build the connector's Endpoints from [Server.URL]:
//
//	API: URL+"/graphql", Token: URL+"/oauth/token"
//
// The fake keeps a record of every GraphQL request (name, query text,
// variables) so a test can show which documents were sent and with which
// input fields. A mutation whose input has a field the connector is not meant
// to send is answered with a GraphQL error and recorded as such.
//
// (The package does not import the connector, so the connector's own tests can
// import it without a cycle.)
package lineartest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixed credentials of the fake OAuth app.
const (
	ClientID     = "lin-client-id-0123456789abcdef"
	ClientSecret = "lin-client-secret-0123456789abcdef0123456789abcdef"
)

// State is a workflow state of a team.
type State struct {
	ID, Name, Type string
}

// Team is a team of the fake workspace.
type Team struct {
	Key, Name string
	States    []State
}

// Comment is a comment on an issue.
type Comment struct {
	ID, Body, Author string
	CreatedAt        time.Time
}

// Link is an attachment on an issue.
type Link struct{ URL, Title, Source string }

// Issue is an issue of the fake workspace.
type Issue struct {
	ID          string // Linear's UUID
	Identifier  string
	Aliases     []string // identifiers the issue had before it moved
	Title       string
	Description string
	TeamKey     string
	State       string // state name
	Labels      []string
	Assignee    string
	Comments    []Comment
	Links       []Link
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// MoreLabels makes the fake report that the issue has more labels than one page.
	MoreLabels bool
}

// Request is one GraphQL request the fake received.
type Request struct {
	Name   string
	Query  string
	Vars   map[string]any
	Token  string
	Errors bool // the fake answered with a GraphQL error
}

// Server is the fake. Exported fields are set before use; the rest is behind
// mu and reached through methods.
type Server struct {
	*httptest.Server
	// Now is the clock of token expiry; default time.Now.
	Now func() time.Time
	// TokenTTL is the lifetime the token endpoint reports; default 30 days.
	TokenTTL time.Duration
	// OnGuard, when set, runs at the start of every IntakeGuard read with the
	// number of that read (1-based), before the fake answers. A test uses it to
	// change the world between two reads: to take a label off an issue after
	// Check and before Execute.
	OnGuard func(s *Server, n int)

	mu       sync.Mutex
	teams    map[string]*Team
	issues   []*Issue
	tokens   map[string]time.Time
	mints    int
	scopes   []string
	reqs     []Request
	guards   int
	rate429  int // answer the next n GraphQL calls with HTTP 429
	remain   string
	commentN int
	drop     map[string]bool   // operation names whose answer is cut after the work was done
	secret   string            // the client secret the token endpoint accepts
	echo     bool              // error answers repeat the credential they received
	labels   map[string]string // label name -> team key ("" for a workspace label), set by DefineLabel
	noops    int               // accepted mutations that changed nothing (a link that was already there)
	cursor   string            // when set, the end cursor every page reports (a careless service)
}

// New starts a fake with two teams: SHOP (Operations) and ENG (Engineering).
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{Now: time.Now, TokenTTL: 30 * 24 * time.Hour, teams: map[string]*Team{}, tokens: map[string]time.Time{}, secret: ClientSecret}
	s.teams["SHOP"] = &Team{Key: "SHOP", Name: "Operations", States: []State{
		{"st-ops-backlog", "Backlog", "backlog"}, {"st-ops-todo", "Todo", "unstarted"},
		{"st-ops-handed", "Handed to engineering", "started"}, {"st-ops-progress", "In Progress", "started"},
		{"st-ops-blocked", "Blocked", "started"}, {"st-ops-done", "Completed", "completed"}, {"st-ops-cancel", "Canceled", "canceled"},
	}}
	s.teams["ENG"] = &Team{Key: "ENG", Name: "Engineering", States: []State{
		{"st-eng-todo", "Todo", "unstarted"}, {"st-eng-done", "Done", "completed"},
	}}
	s.teams["AGT"] = &Team{Key: "AGT", Name: "Agents", States: []State{
		{"st-agt-backlog", "Backlog", "backlog"}, {"st-agt-todo", "Todo", "unstarted"},
		{"st-agt-progress", "In Progress", "started"}, {"st-agt-done", "Done", "completed"}, {"st-agt-cancel", "Canceled", "canceled"},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", s.token)
	mux.HandleFunc("/graphql", s.graphql)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// ---- state the tests read and set ------------------------------------------

// AddIssue adds an issue; zero fields get defaults. It returns the stored issue.
func (s *Server) AddIssue(i Issue) *Issue {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i.ID == "" {
		i.ID = fmt.Sprintf("00000000-0000-4000-8000-%012d", len(s.issues)+1)
	}
	if i.TeamKey == "" {
		i.TeamKey = "SHOP"
	}
	if i.State == "" {
		i.State = "Todo"
	}
	if i.CreatedAt.IsZero() {
		i.CreatedAt = time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	}
	if i.UpdatedAt.IsZero() {
		i.UpdatedAt = i.CreatedAt.Add(time.Duration(len(s.issues)) * time.Minute)
	}
	p := &i
	s.issues = append(s.issues, p)
	return p
}

// Issue returns a copy of the issue with the identifier.
func (s *Server) Issue(ident string) Issue {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, i := range s.issues {
		if i.Identifier == ident {
			c := *i
			c.Labels = append([]string(nil), i.Labels...)
			c.Comments = append([]Comment(nil), i.Comments...)
			return c
		}
	}
	return Issue{}
}

// SetLabels replaces the labels of an issue.
func (s *Server) SetLabels(ident string, labels ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, i := range s.issues {
		if i.Identifier == ident {
			i.Labels = labels
		}
	}
}

// MoveToTeam moves an issue to another team; its old identifier stays an alias.
func (s *Server) MoveToTeam(ident, team, newIdent string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, i := range s.issues {
		if i.Identifier == ident {
			i.Aliases = append(i.Aliases, ident)
			i.Identifier, i.TeamKey = newIdent, team
		}
	}
}

// Requests returns every GraphQL request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Count returns how many GraphQL requests had this operation name.
func (s *Server) Count(name string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Name == name {
			n++
		}
	}
	return n
}

// Mints is how many tokens the token endpoint issued.
func (s *Server) Mints() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mints
}

// Scopes returns the scope string of every token request, in order.
func (s *Server) Scopes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.scopes...)
}

// RevokeTokens makes every token issued so far invalid (Linear does this when a
// client secret is rotated), without waiting for expiry.
func (s *Server) RevokeTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = map[string]time.Time{}
}

// RateLimitNext answers the next n GraphQL calls with HTTP 429 and Retry-After 120.
func (s *Server) RateLimitNext(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rate429 = n
}

// DropAnswer makes the fake carry out the operation with this name and then cut
// the connection without answering: the caller cannot tell whether it happened.
func (s *Server) DropAnswer(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.drop == nil {
		s.drop = map[string]bool{}
	}
	s.drop[name] = true
}

// RenameTeam changes a team's name (a team called Engineering under another key).
func (s *Server) RenameTeam(key, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.teams[key].Name = name
}

// SetRemaining sets the X-RateLimit-Requests-Remaining header of every answer.
func (s *Server) SetRemaining(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remain = strconv.Itoa(n)
}

// ---- token endpoint ---------------------------------------------------------

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	form := parseForm(string(body))
	id, secret, ok := r.BasicAuth()
	if !ok { // the other documented form: client_id and client_secret in the body
		id, secret = form["client_id"], form["client_secret"]
	}
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	s.mu.Lock()
	want, echo := s.secret, s.echo
	s.mu.Unlock()
	if id != ClientID || secret != want {
		desc := "Client authentication failed"
		if echo {
			desc += " for the secret " + secret
		}
		reply(http.StatusUnauthorized, map[string]string{"error": "invalid_client", "error_description": desc})
		return
	}
	if form["grant_type"] != "client_credentials" {
		reply(http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type", "error_description": "grant_type must be client_credentials"})
		return
	}
	s.mu.Lock()
	s.mints++
	s.scopes = append(s.scopes, form["scope"])
	tok := fmt.Sprintf("lin_oauth_%02d_%s", s.mints, strings.Repeat("a1b2c3d4", 6))
	s.tokens[tok] = s.Now().Add(s.TokenTTL)
	ttl := s.TokenTTL
	s.mu.Unlock()
	reply(http.StatusOK, map[string]any{
		"access_token": tok, "token_type": "Bearer", "expires_in": int64(ttl / time.Second), "scope": strings.ReplaceAll(form["scope"], ",", " "),
	})
}

func parseForm(raw string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(raw, "&") {
		k, v, _ := strings.Cut(kv, "=")
		k, v = unesc(k), unesc(v)
		out[k] = v
	}
	return out
}

func unesc(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// ---- GraphQL endpoint -------------------------------------------------------

type gqlError struct {
	Message    string         `json:"message"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

func (s *Server) graphql(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		OperationName string         `json:"operationName"`
		Query         string         `json:"query"`
		Variables     map[string]any `json:"variables"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	s.mu.Lock()
	rec := Request{Name: in.OperationName, Query: in.Query, Vars: in.Variables, Token: bearer}
	if s.remain != "" {
		w.Header().Set("X-RateLimit-Requests-Remaining", s.remain)
	}
	if exp, ok := s.tokens[bearer]; !ok || !s.Now().Before(exp) {
		rec.Errors = true
		s.reqs = append(s.reqs, rec)
		msg := "Authentication required, not authenticated"
		if s.echo {
			msg += " (token " + bearer + ")"
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]any{"errors": []gqlError{{
			Message: msg, Extensions: map[string]any{"type": "authentication error", "code": "AUTHENTICATION_ERROR"}}}})
		return
	}
	if s.rate429 > 0 {
		s.rate429--
		rec.Errors = true
		s.reqs = append(s.reqs, rec)
		s.mu.Unlock()
		w.Header().Set("Retry-After", "120")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"errors": []gqlError{{
			Message: "Rate limit exceeded", Extensions: map[string]any{"code": "RATELIMITED"}}}})
		return
	}
	s.reqs = append(s.reqs, rec)
	idx := len(s.reqs) - 1
	var guardN int
	if in.OperationName == "IntakeGuard" || in.OperationName == "IssueGuard" {
		s.guards++
		guardN = s.guards
	}
	hook := s.OnGuard
	s.mu.Unlock()

	if guardN > 0 && hook != nil {
		hook(s, guardN)
	}

	s.mu.Lock()
	var data any
	var errs []gqlError
	switch in.OperationName {
	case "IntakeList":
		data, errs = s.list(in.Variables)
	case "IntakeGuard":
		data, errs = s.guard(in.Variables)
	case "IntakeTeam":
		data, errs = s.team(in.Variables)
	case "IntakeComment":
		data, errs = s.comment(in.Variables)
	case "IntakeSetState":
		data, errs = s.setState(in.Variables)
	case "IssueGet":
		data, errs = s.issueGet(in.Variables)
	case "IssueList":
		data, errs = s.list(in.Variables)
	case "IssueGuard":
		data, errs = s.issueGuard(in.Variables)
	case "IssueLabelLookup":
		data, errs = s.labelLookup(in.Variables)
	case "IssueAddLabel":
		data, errs = s.changeLabel(in.Variables, true)
	case "IssueRemoveLabel":
		data, errs = s.changeLabel(in.Variables, false)
	case "IssueLink":
		data, errs = s.link(in.Variables)
	default:
		errs = []gqlError{{Message: "Cannot query field: unknown operation " + in.OperationName, Extensions: map[string]any{"code": "GRAPHQL_VALIDATION_FAILED"}}}
	}
	if errs != nil {
		s.reqs[idx].Errors = true
	}
	cut := s.drop[in.OperationName]
	s.mu.Unlock()
	if cut {
		panic(http.ErrAbortHandler)
	}
	if errs != nil {
		writeJSON(w, http.StatusOK, map[string]any{"errors": errs, "data": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func invalid(msg string) []gqlError {
	return []gqlError{{Message: msg, Extensions: map[string]any{"type": "invalid input", "code": "INVALID_INPUT"}}}
}

func (s *Server) stateOf(i *Issue) State {
	for _, st := range s.teams[i.TeamKey].States {
		if st.Name == i.State {
			return st
		}
	}
	return State{Name: i.State}
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func (s *Server) list(v map[string]any) (any, []gqlError) {
	team, _ := dig(v, "filter", "team", "key", "eq").(string)
	label, _ := dig(v, "filter", "labels", "some", "name", "eq").(string)
	eqType, _ := dig(v, "filter", "state", "type", "eq").(string)
	var notIn []string
	if l, ok := dig(v, "filter", "state", "type", "nin").([]any); ok {
		for _, x := range l {
			notIn = append(notIn, fmt.Sprint(x))
		}
	}
	first := 50
	if f, ok := v["first"].(float64); ok {
		first = int(f)
	}
	var match []*Issue
	for _, i := range s.issues {
		if team != "" && i.TeamKey != team {
			continue
		}
		if label != "" && !has(i.Labels, label) {
			continue
		}
		if eqType != "" && s.stateOf(i).Type != eqType {
			continue
		}
		if has(notIn, s.stateOf(i).Type) {
			continue
		}
		match = append(match, i)
	}
	sort.SliceStable(match, func(a, b int) bool { return match[a].UpdatedAt.After(match[b].UpdatedAt) })
	start := 0
	if after, ok := v["after"].(string); ok && after != "" {
		start, _ = strconv.Atoi(after)
	}
	end := min(start+first, len(match))
	nodes := make([]any, 0)
	for _, i := range match[min(start, len(match)):end] {
		nodes = append(nodes, s.node(i))
	}
	page := map[string]any{"hasNextPage": end < len(match), "endCursor": strconv.Itoa(end)}
	if s.cursor != "" {
		page["endCursor"] = s.cursor
	}
	return map[string]any{"issues": map[string]any{"nodes": nodes, "pageInfo": page}}, nil
}

func (s *Server) node(i *Issue) map[string]any {
	t := s.teams[i.TeamKey]
	labels := []any{}
	for _, l := range i.Labels {
		labels = append(labels, map[string]any{"id": labelID(l), "name": l})
	}
	comments := []any{}
	for k := len(i.Comments) - 1; k >= 0 && len(comments) < 8; k-- {
		c := i.Comments[k]
		comments = append(comments, map[string]any{"body": c.Body, "createdAt": c.CreatedAt.Format(time.RFC3339), "user": map[string]any{"name": c.Author}})
	}
	links := []any{}
	for _, l := range i.Links {
		links = append(links, map[string]any{"url": l.URL, "title": l.Title, "sourceType": l.Source})
	}
	n := map[string]any{
		"id": i.ID, "identifier": i.Identifier, "title": i.Title, "description": i.Description,
		"url":       "https://linear.app/fake/issue/" + i.Identifier,
		"createdAt": i.CreatedAt.Format(time.RFC3339), "updatedAt": i.UpdatedAt.Format(time.RFC3339),
		"team":        map[string]any{"key": t.Key, "name": t.Name},
		"state":       map[string]any{"name": s.stateOf(i).Name, "type": s.stateOf(i).Type},
		"labels":      map[string]any{"nodes": labels, "pageInfo": map[string]any{"hasNextPage": i.MoreLabels}},
		"comments":    map[string]any{"nodes": comments},
		"attachments": map[string]any{"nodes": links},
	}
	if i.Assignee != "" {
		n["assignee"] = map[string]any{"name": i.Assignee}
	}
	return n
}

func (s *Server) find(id string) *Issue {
	for _, i := range s.issues {
		if i.ID == id || i.Identifier == id || has(i.Aliases, id) {
			return i
		}
	}
	return nil
}

func stateNodes(t *Team) []any {
	out := []any{}
	for _, st := range t.States {
		out = append(out, map[string]any{"id": st.ID, "name": st.Name, "type": st.Type})
	}
	return out
}

func (s *Server) guard(v map[string]any) (any, []gqlError) {
	id, _ := v["id"].(string)
	label, _ := v["label"].(string)
	i := s.find(id)
	if i == nil {
		return nil, invalid("Entity not found: Issue - Could not find referenced Issue.")
	}
	t := s.teams[i.TeamKey]
	labels := []any{}
	for _, l := range i.Labels {
		if l == label {
			labels = append(labels, map[string]any{"name": l})
		}
	}
	return map[string]any{"issue": map[string]any{
		"id": i.ID, "identifier": i.Identifier, "title": i.Title, "url": "https://linear.app/fake/issue/" + i.Identifier,
		"team":   map[string]any{"key": t.Key, "name": t.Name, "states": map[string]any{"nodes": stateNodes(t)}},
		"state":  map[string]any{"id": s.stateOf(i).ID, "name": s.stateOf(i).Name, "type": s.stateOf(i).Type},
		"labels": map[string]any{"nodes": labels},
	}}, nil
}

func (s *Server) team(v map[string]any) (any, []gqlError) {
	key, _ := v["key"].(string)
	nodes := []any{}
	if t := s.teams[key]; t != nil {
		nodes = append(nodes, map[string]any{"key": t.Key, "name": t.Name, "states": map[string]any{"nodes": stateNodes(t)}})
	}
	return map[string]any{"teams": map[string]any{"nodes": nodes}}, nil
}

// onlyKeys reports an input with a field outside allowed: the fake refuses it
// the way Linear would refuse an unknown input field.
func onlyKeys(in map[string]any, allowed ...string) []gqlError {
	for k := range in {
		if !has(allowed, k) {
			return []gqlError{{Message: "Variable \"$input\" got invalid value: unexpected field " + k, Extensions: map[string]any{"code": "GRAPHQL_VALIDATION_FAILED"}}}
		}
	}
	return nil
}

func (s *Server) comment(v map[string]any) (any, []gqlError) {
	in, _ := v["input"].(map[string]any)
	if errs := onlyKeys(in, "id", "issueId", "body"); errs != nil {
		return nil, errs
	}
	issueID, _ := in["issueId"].(string)
	id, _ := in["id"].(string)
	body, _ := in["body"].(string)
	var target *Issue
	for _, i := range s.issues {
		if i.ID == issueID {
			target = i
		}
	}
	if target == nil {
		return nil, invalid("Entity not found: Issue")
	}
	for _, i := range s.issues {
		for _, c := range i.Comments {
			if c.ID == id {
				return nil, invalid("a comment with this id exists")
			}
		}
	}
	s.commentN++
	target.Comments = append(target.Comments, Comment{ID: id, Body: body, Author: "Board Intake", CreatedAt: s.Now()})
	return map[string]any{"commentCreate": map[string]any{
		"success": true, "comment": map[string]any{"id": id, "url": "https://linear.app/fake/issue/" + target.Identifier + "#comment-" + id[:8]},
	}}, nil
}

func (s *Server) setState(v map[string]any) (any, []gqlError) {
	in, _ := v["input"].(map[string]any)
	if errs := onlyKeys(in, "stateId"); errs != nil {
		return nil, errs
	}
	id, _ := v["id"].(string)
	stateID, _ := in["stateId"].(string)
	var target *Issue
	for _, i := range s.issues {
		if i.ID == id {
			target = i
		}
	}
	if target == nil {
		return nil, invalid("Entity not found: Issue")
	}
	for _, st := range s.teams[target.TeamKey].States {
		if st.ID == stateID {
			target.State = st.Name
			target.UpdatedAt = s.Now()
			return map[string]any{"issueUpdate": map[string]any{
				"success": true, "issue": map[string]any{"identifier": target.Identifier, "state": map[string]any{"name": st.Name}},
			}}, nil
		}
	}
	return nil, invalid("the state does not belong to the issue's team")
}

// BasicHeader returns the Authorization header the connector must send to the
// token endpoint (for tests that call it directly).
func BasicHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(ClientID+":"+ClientSecret))
}

// SetClientSecret changes the client secret the token endpoint accepts (the
// default is [ClientSecret]). The conformance suite uses it to make its canary
// the credential.
func (s *Server) SetClientSecret(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secret = v
}

// Hostile makes the fake behave like a careless service: it stops accepting the
// client secret it had (newSecret is the one it accepts now) and every
// authentication error repeats the credential it received, in the text of the
// error.
func (s *Server) Hostile(newSecret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secret, s.echo = newSecret, true
}

// Tokens returns every access token the token endpoint has issued.
func (s *Server) Tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.tokens))
	for t := range s.tokens {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Edit changes the issue with the identifier under the fake's lock. It does
// nothing when there is no such issue.
func (s *Server) Edit(ident string, f func(i *Issue)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, i := range s.issues {
		if i.Identifier == ident {
			f(i)
		}
	}
}

// AddState adds a workflow state to a team.
func (s *Server) AddState(team string, st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.teams[team].States = append(s.teams[team].States, st)
}

// ---- the generic issue documents ---------------------------------------------

func labelID(name string) string { return "lbl-" + name }

// DefineLabel makes a label exist: a workspace label (teamKey empty) or the
// own label of one team. A label that an issue carries and that was never
// defined counts as a workspace label.
func (s *Server) DefineLabel(name, teamKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.labels == nil {
		s.labels = map[string]string{}
	}
	s.labels[name] = teamKey
}

// SetCursor makes every page report v as its end cursor, whatever it was.
func (s *Server) SetCursor(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cursor = v
}

// NoOps is how many accepted mutations changed nothing: a link that the issue
// already had, with the same title. The conformance rig subtracts them from the
// writes it counts as applied.
func (s *Server) NoOps() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.noops
}

// Attachments returns the links of the issue.
func (s *Server) Attachments(ident string) []Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, i := range s.issues {
		if i.Identifier == ident {
			return append([]Link(nil), i.Links...)
		}
	}
	return nil
}

func (s *Server) issueGet(v map[string]any) (any, []gqlError) {
	id, _ := v["id"].(string)
	i := s.find(id)
	if i == nil {
		return nil, invalid("Entity not found: Issue - Could not find referenced Issue.")
	}
	return map[string]any{"issue": s.node(i)}, nil
}

func (s *Server) issueGuard(v map[string]any) (any, []gqlError) {
	id, _ := v["id"].(string)
	i := s.find(id)
	if i == nil {
		return nil, invalid("Entity not found: Issue - Could not find referenced Issue.")
	}
	t := s.teams[i.TeamKey]
	labels := []any{}
	for _, l := range i.Labels {
		labels = append(labels, map[string]any{"id": labelID(l), "name": l})
	}
	return map[string]any{"issue": map[string]any{
		"id": i.ID, "identifier": i.Identifier, "title": i.Title, "url": "https://linear.app/fake/issue/" + i.Identifier,
		"team":   map[string]any{"key": t.Key, "name": t.Name, "states": map[string]any{"nodes": stateNodes(t)}},
		"state":  map[string]any{"id": s.stateOf(i).ID, "name": s.stateOf(i).Name, "type": s.stateOf(i).Type},
		"labels": map[string]any{"nodes": labels, "pageInfo": map[string]any{"hasNextPage": i.MoreLabels}},
	}}, nil
}

func (s *Server) labelLookup(v map[string]any) (any, []gqlError) {
	name, _ := v["name"].(string)
	nodes := []any{}
	team, defined := s.labels[name]
	if !defined {
		for _, i := range s.issues {
			if has(i.Labels, name) {
				defined = true
			}
		}
	}
	if defined {
		n := map[string]any{"id": labelID(name), "name": name, "team": nil}
		if team != "" {
			n["team"] = map[string]any{"key": team}
		}
		nodes = append(nodes, n)
	}
	return map[string]any{"issueLabels": map[string]any{"nodes": nodes}}, nil
}

func (s *Server) changeLabel(v map[string]any, add bool) (any, []gqlError) {
	id, _ := v["id"].(string)
	labelId, _ := v["labelId"].(string)
	if len(v) != 2 {
		return nil, invalid("unexpected variables")
	}
	var target *Issue
	for _, i := range s.issues {
		if i.ID == id {
			target = i
		}
	}
	if target == nil {
		return nil, invalid("Entity not found: Issue")
	}
	name := strings.TrimPrefix(labelId, "lbl-")
	if name == labelId || name == "" {
		return nil, invalid("Entity not found: IssueLabel")
	}
	var kept []string
	found := false
	for _, l := range target.Labels {
		if l == name {
			found = true
			if !add {
				continue
			}
		}
		kept = append(kept, l)
	}
	switch {
	case add && found:
		return nil, invalid("Label already added to the issue")
	case add:
		kept = append(kept, name)
	case !found:
		return nil, invalid("Label is not on the issue")
	}
	target.Labels = kept
	target.UpdatedAt = s.Now()
	field := "issueRemoveLabel"
	if add {
		field = "issueAddLabel"
	}
	return map[string]any{field: map[string]any{"success": true, "issue": map[string]any{"identifier": target.Identifier}}}, nil
}

func (s *Server) link(v map[string]any) (any, []gqlError) {
	in, _ := v["input"].(map[string]any)
	if errs := onlyKeys(in, "issueId", "url", "title"); errs != nil {
		return nil, errs
	}
	issueID, _ := in["issueId"].(string)
	url, _ := in["url"].(string)
	title, _ := in["title"].(string)
	var target *Issue
	for _, i := range s.issues {
		if i.ID == issueID {
			target = i
		}
	}
	if target == nil || url == "" {
		return nil, invalid("Entity not found: Issue")
	}
	for k, l := range target.Links {
		if l.URL == url {
			if title != "" && title != l.Title {
				target.Links[k].Title = title
			} else {
				s.noops++
			}
			return map[string]any{"attachmentCreate": map[string]any{"success": true, "attachment": map[string]any{"id": "att-1", "url": url}}}, nil
		}
	}
	target.Links = append(target.Links, Link{URL: url, Title: title, Source: "api"})
	target.UpdatedAt = s.Now()
	return map[string]any{"attachmentCreate": map[string]any{"success": true, "attachment": map[string]any{"id": "att-1", "url": url}}}, nil
}
