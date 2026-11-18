package ghtest

import (
	"net/http"
	"strconv"
	"strings"
)

// IssueOptions describes an issue to plant.
type IssueOptions struct {
	Title  string
	Labels []string
	Closed bool
	// IsPull makes the issues API answer for it as it does for a pull request
	// (a `pull_request` member), which the issue ops must refuse.
	IsPull bool
}

// Comment is one comment on an issue.
type Comment struct {
	ID   int64
	Body string
}

// IssueView is a copy of an issue as the fake holds it.
type IssueView struct {
	Number   int
	Title    string
	Body     string
	Labels   []string
	State    string
	Reason   string // state_reason of the last state change
	Comments []Comment
}

type issue struct {
	number   int
	title    string
	body     string
	labels   []string
	state    string
	reason   string
	isPull   bool
	comments []Comment
}

// nextIssue returns the next free number, skipping the pull requests held now
// (issues and pull requests share one number space on GitHub).
func (r *Repo) nextIssue() int {
	n := len(r.issues) + len(r.pulls) + 1
	for r.issues[n] != nil || r.pulls[n] != nil {
		n++
	}
	return n
}

// AddIssue plants an issue and returns its number.
func (r *Repo) AddIssue(o IssueOptions) int {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	n := r.nextIssue()
	st := "open"
	if o.Closed {
		st = "closed"
	}
	r.issues[n] = &issue{number: n, title: o.Title, labels: append([]string(nil), o.Labels...), state: st, isPull: o.IsPull}
	return n
}

// Issue returns a copy of issue n (ok is false when there is none).
func (r *Repo) Issue(n int) (IssueView, bool) {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	i := r.issues[n]
	if i == nil {
		return IssueView{}, false
	}
	return IssueView{Number: i.number, Title: i.title, Body: i.body, Labels: append([]string(nil), i.labels...),
		State: i.state, Reason: i.reason, Comments: append([]Comment(nil), i.comments...)}, true
}

// IssueCount is the number of issues the fake holds.
func (r *Repo) IssueCount() int {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(r.issues)
}

// CloseIssue closes issue n.
func (r *Repo) CloseIssue(n int) {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := r.issues[n]; i != nil {
		i.state, i.reason = "closed", "completed"
	} else {
		s.fail(s.t, "CloseIssue: no issue %d", n)
	}
}

func (r *Repo) issueJSON(i *issue) map[string]any {
	labels := make([]map[string]any, 0, len(i.labels))
	for _, l := range i.labels {
		labels = append(labels, map[string]any{"name": l})
	}
	out := map[string]any{
		"number": i.number, "state": i.state, "title": i.title, "body": i.body, "labels": labels,
		"html_url": "https://github.test/" + r.FullName() + "/issues/" + strconv.Itoa(i.number),
	}
	if i.reason != "" {
		out["state_reason"] = i.reason
	}
	if i.isPull {
		out["pull_request"] = map[string]any{"url": "https://github.test/" + r.FullName() + "/pulls/" + strconv.Itoa(i.number)}
	}
	return out
}

func (r *Repo) issueOf(req *http.Request) *issue {
	n, _ := strconv.Atoi(req.PathValue("n"))
	return r.issues[n]
}

func issueInvalid(w http.ResponseWriter, field, code string) {
	jsonOut(w, 422, map[string]any{"message": "Validation Failed",
		"errors": []map[string]any{{"resource": "Issue", "field": field, "code": code}}})
}

func (s *Server) getIssue(w http.ResponseWriter, req *http.Request, r *Repo) {
	i := r.issueOf(req)
	if i == nil {
		refuse(w, 404, "Not Found")
		return
	}
	jsonOut(w, 200, r.issueJSON(i))
}

func (s *Server) createIssue(w http.ResponseWriter, req *http.Request, r *Repo) {
	var b struct {
		Title  string   `json:"title"`
		Body   string   `json:"body"`
		Labels []string `json:"labels"`
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	if strings.TrimSpace(b.Title) == "" {
		issueInvalid(w, "title", "missing_field")
		return
	}
	n := r.nextIssue()
	r.issues[n] = &issue{number: n, title: b.Title, body: b.Body, labels: b.Labels, state: "open"}
	jsonOut(w, 201, r.issueJSON(r.issues[n]))
}

func (s *Server) createComment(w http.ResponseWriter, req *http.Request, r *Repo) {
	i := r.issueOf(req)
	if i == nil {
		refuse(w, 404, "Not Found")
		return
	}
	var b struct {
		Body string `json:"body"`
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	if strings.TrimSpace(b.Body) == "" {
		issueInvalid(w, "body", "missing_field")
		return
	}
	c := Comment{ID: s.nextID(), Body: b.Body}
	i.comments = append(i.comments, c)
	jsonOut(w, 201, map[string]any{"id": c.ID, "body": c.Body,
		"html_url": "https://github.test/" + r.FullName() + "/issues/" + strconv.Itoa(i.number) + "#issuecomment-" + strconv.FormatInt(c.ID, 10)})
}

func (s *Server) updateIssue(w http.ResponseWriter, req *http.Request, r *Repo) {
	i := r.issueOf(req)
	if i == nil {
		refuse(w, 404, "Not Found")
		return
	}
	var b struct {
		State       string `json:"state"`
		StateReason string `json:"state_reason"`
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	if b.State != "open" && b.State != "closed" {
		issueInvalid(w, "state", "invalid")
		return
	}
	i.state, i.reason = b.State, b.StateReason
	jsonOut(w, 200, r.issueJSON(i))
}

// SetIssueLabels replaces the labels of issue n (a person removing a label).
func (r *Repo) SetIssueLabels(n int, labels ...string) {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := r.issues[n]; i != nil {
		i.labels = append([]string(nil), labels...)
	} else {
		s.fail(s.t, "SetIssueLabels: no issue %d", n)
	}
}
