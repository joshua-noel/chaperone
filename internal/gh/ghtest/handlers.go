package ghtest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// need is a permission a route requires. A token without it gets 403 "Resource
// not accessible by integration", except where refs is set: GitHub then answers
// 422 "not all refs are readable" (it validates head and base with the token, and
// a token without contents:read cannot read them).
type need struct {
	perm  string
	level string
	refs  bool
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, fn http.HandlerFunc) { mux.HandleFunc(pattern, s.wrap(fn)) }
	rp := func(pattern string, fn repoFn, needs ...need) { h(pattern, s.repoHandler(fn, needs...)) }

	h("POST /app/installations/{id}/access_tokens", s.mint)
	h("GET /repos/{owner}/{repo}/installation", s.findInstallation)
	h("DELETE /installation/token", s.revoke)
	rp("GET /repos/{owner}/{repo}/pulls/{n}", (*Server).getPull, need{"pull_requests", "read", false})
	rp("GET /repos/{owner}/{repo}/pulls/{n}/files", (*Server).listFiles, need{"pull_requests", "read", false})
	rp("POST /repos/{owner}/{repo}/pulls", (*Server).createPull, need{"pull_requests", "write", false}, need{"contents", "read", true})
	rp("PUT /repos/{owner}/{repo}/pulls/{n}/merge", (*Server).mergePull, need{"contents", "write", false}, need{"pull_requests", "write", false})
	rp("PUT /repos/{owner}/{repo}/pulls/{n}/update-branch", (*Server).updateBranch, need{"contents", "write", false}, need{"pull_requests", "write", false})
	rp("GET /repos/{owner}/{repo}/commits/{sha}/check-runs", (*Server).listCheckRuns, need{"checks", "read", false})
	rp("POST /repos/{owner}/{repo}/check-runs", (*Server).createCheckRun, need{"checks", "write", false})
	rp("GET /repos/{owner}/{repo}/compare/{basehead...}", (*Server).compare, need{"contents", "read", false})
	rp("POST /repos/{owner}/{repo}/deployments", (*Server).createDeployment, need{"deployments", "write", false})
	rp("POST /repos/{owner}/{repo}/deployments/{id}/statuses", (*Server).createDeploymentStatus, need{"deployments", "write", false})
	rp("GET /repos/{owner}/{repo}/issues/{n}", (*Server).getIssue, need{"issues", "read", false})
	rp("POST /repos/{owner}/{repo}/issues", (*Server).createIssue, need{"issues", "write", false})
	rp("POST /repos/{owner}/{repo}/issues/{n}/comments", (*Server).createComment, need{"issues", "write", false})
	rp("PATCH /repos/{owner}/{repo}/issues/{n}", (*Server).updateIssue, need{"issues", "write", false})
	mux.HandleFunc("/", s.wrap(func(w http.ResponseWriter, r *http.Request) { refuse(w, 404, "Not Found") }))
	return mux
}

// wrap logs the request, runs Before hooks and faults, then the handler.
func (s *Server) wrap(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(bytes.NewReader(body))

		s.mu.Lock()
		s.record(r.Method, r.URL.Path, r.URL.RawQuery, body)
		var run []func()
		keep := s.before[:0]
		for _, hk := range s.before {
			if hk.method == r.Method && strings.Contains(r.URL.Path, hk.sub) {
				run = append(run, hk.fn)
			} else {
				keep = append(keep, hk)
			}
		}
		s.before = keep
		var hit *Fault
		for _, f := range s.faults {
			if f.method == r.Method && strings.Contains(r.URL.Path, f.sub) && (f.f.Times == 0 || f.used < f.f.Times) {
				f.used++
				ff := f.f
				hit = &ff
				break
			}
		}
		s.mu.Unlock()

		for _, fn := range run {
			fn()
		}
		if hit != nil {
			for k, v := range hit.Header {
				w.Header()[k] = v
			}
			refuse(w, hit.Status, hit.Message)
			return
		}
		next(w, r)
	}
}

type repoFn func(s *Server, w http.ResponseWriter, r *http.Request, repo *Repo)

// repoHandler authenticates an installation token, finds the repository the
// token covers (404 otherwise), checks permissions (403), then runs fn with s.mu held.
func (s *Server) repoHandler(fn repoFn, needs ...need) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tr, _, msg := s.tokenFor(r)
		if tr == nil {
			refuse(w, 401, msg)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		name := r.PathValue("repo")
		repo := tr.install.repos[name]
		if repo == nil || tr.install.Account != r.PathValue("owner") || !tr.repos[name] {
			refuse(w, 404, "Not Found")
			return
		}
		for _, n := range needs {
			if permLevel(tr.perms[n.perm]) < permLevel(n.level) {
				if n.refs {
					jsonOut(w, 422, map[string]any{"message": "Validation Failed", "documentation_url": "https://docs.github.com/rest/pulls/pulls#create-a-pull-request",
						"errors": []map[string]any{{"resource": "PullRequest", "code": "custom", "message": "not all refs are readable"}}})
					return
				}
				refuse(w, 403, "Resource not accessible by integration")
				return
			}
		}
		fn(s, w, r, repo)
	}
}

func decode(r *http.Request, v any) bool {
	b, _ := io.ReadAll(r.Body)
	return len(bytes.TrimSpace(b)) == 0 || json.Unmarshal(b, v) == nil
}

func page(r *http.Request, n int) (int, int) {
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if per <= 0 || per > 100 {
		per = 30
	}
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pg <= 0 {
		pg = 1
	}
	lo := min((pg-1)*per, n)
	return lo, min(lo+per, n)
}

// ---- App endpoints ----

func (s *Server) findInstallation(w http.ResponseWriter, r *http.Request) {
	if msg := s.verifyJWT(bearer(r)); msg != "" {
		refuse(w, 401, msg)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, in := range s.installs {
		if in.Account == r.PathValue("owner") && in.repos[r.PathValue("repo")] != nil {
			jsonOut(w, 200, map[string]any{"id": in.ID, "app_id": OwnAppID, "account": map[string]any{"login": in.Account}})
			return
		}
	}
	refuse(w, 404, "Not Found")
}

func (s *Server) mint(w http.ResponseWriter, r *http.Request) {
	if msg := s.verifyJWT(bearer(r)); msg != "" {
		refuse(w, 401, msg)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var body struct {
		Repositories []string          `json:"repositories"`
		Permissions  map[string]string `json:"permissions"`
	}
	if !decode(r, &body) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in := s.installs[id]
	if in == nil {
		refuse(w, 404, "Not Found")
		return
	}
	tr := &tokenRec{install: in, repos: map[string]bool{}, perms: map[string]string{}, expires: s.now.Add(time.Hour)}
	selection := "selected"
	if s.mintAll || len(body.Repositories) == 0 {
		selection = "all"
		for n := range in.repos {
			tr.repos[n] = true
		}
	} else {
		for _, n := range body.Repositories {
			if in.repos[n] == nil {
				refuse(w, 422, "There is at least one repository that does not exist or is not accessible to the parent installation.")
				return
			}
			tr.repos[n] = true
		}
	}
	if s.mintAll || len(body.Permissions) == 0 {
		for k, v := range in.Granted {
			tr.perms[k] = v
		}
	} else {
		for k, v := range body.Permissions {
			if permLevel(v) == 0 || permLevel(in.Granted[k]) < permLevel(v) {
				refuse(w, 422, "The permissions requested are not granted to this installation.")
				return
			}
			tr.perms[k] = v
		}
	}
	s.mintAll = false
	if tr.perms["metadata"] == "" {
		tr.perms["metadata"] = "read"
	}
	value := s.newTokenValue()
	s.tokens[value] = tr
	repos := []map[string]any{}
	names := make([]string, 0, len(tr.repos))
	for n := range tr.repos {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		repos = append(repos, map[string]any{"name": n, "full_name": in.Account + "/" + n})
	}
	jsonOut(w, 201, map[string]any{
		"token": value, "expires_at": tr.expires.UTC().Format("2006-01-02T15:04:05Z"),
		"permissions": tr.perms, "repository_selection": selection, "repositories": repos,
	})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	tr, _, msg := s.tokenFor(r)
	if tr == nil {
		refuse(w, 401, msg)
		return
	}
	s.mu.Lock()
	tr.revoked = true
	s.mu.Unlock()
	w.WriteHeader(204)
}

// ---- repository endpoints (s.mu held) ----

func (r *Repo) pullJSON(p *pull) map[string]any {
	head, base := r.branches[p.head], r.branches[p.base]
	behind := r.ahead(base, head)
	state := "clean"
	switch {
	case p.draft:
		state = "draft"
	case p.conflict:
		state = "dirty"
	case behind > 0:
		state = "behind"
	}
	headRepo := r.FullName()
	if p.fork {
		headRepo = "someone-else/" + r.Name
	}
	out := map[string]any{
		"number": p.number, "state": p.state, "draft": p.draft, "merged": p.merged,
		"mergeable": !p.conflict, "mergeable_state": state, "title": p.title,
		"html_url":         "https://github.test/" + r.FullName() + "/pull/" + strconv.Itoa(p.number),
		"merge_commit_sha": p.mergeSHA,
		"base":             map[string]any{"ref": p.base, "sha": base, "repo": map[string]any{"full_name": r.FullName()}},
		"head":             map[string]any{"ref": p.head, "sha": head, "repo": map[string]any{"full_name": headRepo}},
		"body":             p.body, "created_at": "2026-10-30T09:00:00Z", "updated_at": "2026-10-31T09:00:00Z", "closed_at": nil, "merged_at": nil,
		"commits": r.ahead(head, base), "changed_files": len(p.files),
	}
	adds, dels := 0, 0
	for _, f := range p.files {
		adds, dels = adds+f.Additions, dels+f.Deletions
	}
	out["additions"], out["deletions"] = adds, dels
	labels := []map[string]any{}
	for _, l := range p.labels {
		labels = append(labels, map[string]any{"name": l})
	}
	out["labels"] = labels
	if p.author != "" {
		out["user"] = map[string]any{"login": p.author}
	} else {
		out["user"] = nil
	}
	if p.unknown {
		out["mergeable"] = nil
		out["mergeable_state"] = "unknown"
	}
	if p.mergeSHA == "" {
		out["merge_commit_sha"] = nil
	}
	return out
}

func (r *Repo) pullOf(req *http.Request) *pull {
	n, _ := strconv.Atoi(req.PathValue("n"))
	return r.pulls[n]
}

func (s *Server) getPull(w http.ResponseWriter, req *http.Request, r *Repo) {
	p := r.pullOf(req)
	if p == nil {
		refuse(w, 404, "Not Found")
		return
	}
	if strings.Contains(req.Header.Get("Accept"), "application/vnd.github.diff") {
		w.Header().Set("Content-Type", "application/vnd.github.diff; charset=utf-8")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(r.diffOf(p)))
		return
	}
	jsonOut(w, 200, r.pullJSON(p))
}

// diffOf is the unified diff GitHub would send for the pull request: one block per file, from the patches planted
// with SetFiles. A file with no patch is a binary or very large one.
func (r *Repo) diffOf(p *pull) string {
	var b strings.Builder
	for _, f := range p.files {
		from := f.Filename
		if f.PreviousFilename != "" {
			from = f.PreviousFilename
		}
		b.WriteString("diff --git a/" + from + " b/" + f.Filename + "\n")
		if f.Patch == "" {
			b.WriteString("Binary files a/" + from + " and b/" + f.Filename + " differ\n")
			continue
		}
		b.WriteString("--- a/" + from + "\n+++ b/" + f.Filename + "\n" + f.Patch)
		if !strings.HasSuffix(f.Patch, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (s *Server) listFiles(w http.ResponseWriter, req *http.Request, r *Repo) {
	p := r.pullOf(req)
	if p == nil {
		refuse(w, 404, "Not Found")
		return
	}
	lo, hi := page(req, len(p.files))
	out := []map[string]any{}
	for _, f := range p.files[lo:hi] {
		st := f.Status
		if st == "" {
			st = "modified"
		}
		m := map[string]any{"filename": f.Filename, "status": st, "additions": f.Additions, "deletions": f.Deletions, "changes": f.Additions + f.Deletions}
		if f.PreviousFilename != "" {
			m["previous_filename"] = f.PreviousFilename
		}
		if f.Patch != "" {
			m["patch"] = f.Patch
		}
		out = append(out, m)
	}
	jsonOut(w, 200, out)
}

func validation(w http.ResponseWriter, field, code, msg string) {
	jsonOut(w, 422, map[string]any{"message": "Validation Failed",
		"errors": []map[string]any{{"resource": "PullRequest", "field": field, "code": code, "message": msg}}})
}

func (s *Server) createPull(w http.ResponseWriter, req *http.Request, r *Repo) {
	var b struct {
		Title, Head, Base string
		Draft             bool
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	if strings.TrimSpace(b.Title) == "" {
		validation(w, "title", "missing_field", "")
		return
	}
	head := strings.TrimPrefix(b.Head, r.in.Account+":")
	if strings.Contains(head, ":") || r.branches[head] == "" {
		validation(w, "head", "invalid", "")
		return
	}
	if r.branches[b.Base] == "" {
		validation(w, "base", "invalid", "")
		return
	}
	for _, p := range r.pulls {
		if p.state == "open" && p.head == head && p.base == b.Base {
			validation(w, "", "custom", "A pull request already exists for "+r.in.Account+":"+head+".")
			return
		}
	}
	if r.ahead(r.branches[head], r.branches[b.Base]) == 0 {
		validation(w, "", "custom", "No commits between "+b.Base+" and "+head)
		return
	}
	n := r.openPR(PROptions{Title: b.Title, Head: head, Base: b.Base, Draft: b.Draft})
	jsonOut(w, 201, r.pullJSON(r.pulls[n]))
}

func (r *Repo) requiredCheckOK(sha string) bool {
	if r.prot.RequiredCheck == "" {
		return true
	}
	var latest *checkRun
	for _, c := range r.checks {
		if c.sha == sha && c.Name == r.prot.RequiredCheck && (r.prot.RequiredAppID == 0 || c.AppID == r.prot.RequiredAppID) {
			if latest == nil || c.id > latest.id {
				latest = c
			}
		}
	}
	return latest != nil && latest.Status == "completed" && latest.Conclusion == "success"
}

func (s *Server) mergePull(w http.ResponseWriter, req *http.Request, r *Repo) {
	p := r.pullOf(req)
	if p == nil {
		refuse(w, 404, "Not Found")
		return
	}
	var b struct {
		SHA         string `json:"sha"`
		MergeMethod string `json:"merge_method"`
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	method := b.MergeMethod
	if method == "" {
		method = "merge"
	}
	if method != "merge" && method != "squash" && method != "rebase" {
		validation(w, "merge_method", "invalid", "")
		return
	}
	head, base := r.branches[p.head], r.branches[p.base]
	switch {
	case p.state != "open", p.draft, p.conflict:
		refuse(w, 405, "Pull Request is not mergeable")
	case r.denied[method]:
		refuse(w, 405, "Merge method "+method+" is not allowed for this repository.")
	case b.SHA != "" && b.SHA != head:
		refuse(w, 409, "Head branch was modified. Review and try the merge again.")
	case p.base == r.Default && !r.requiredCheckOK(head):
		refuse(w, 405, "Required status check \""+r.prot.RequiredCheck+"\" is expected.")
	case p.base == r.Default && r.prot.StrictUpToDate && r.ahead(base, head) > 0:
		refuse(w, 405, "Base branch was modified. Review and try the merge again.")
	default:
		parents := []string{base}
		if method == "merge" {
			parents = append(parents, head)
		}
		sha := r.newCommit(parents...)
		r.branches[p.base] = sha
		p.merged, p.state, p.mergeSHA = true, "closed", sha
		jsonOut(w, 200, map[string]any{"sha": sha, "merged": true, "message": "Pull Request successfully merged"})
	}
}

func (s *Server) updateBranch(w http.ResponseWriter, req *http.Request, r *Repo) {
	p := r.pullOf(req)
	if p == nil {
		refuse(w, 404, "Not Found")
		return
	}
	var b struct {
		ExpectedHeadSHA string `json:"expected_head_sha"`
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	head, base := r.branches[p.head], r.branches[p.base]
	switch {
	case b.ExpectedHeadSHA != "" && b.ExpectedHeadSHA != head:
		refuse(w, 422, "expected head sha didn't match current head ref.")
	case p.conflict:
		refuse(w, 422, "merge conflict between base and head")
	case r.ahead(base, head) == 0:
		refuse(w, 422, "There are no new commits on the base branch.")
	default:
		r.branches[p.head] = r.newCommit(head, base) // GitHub does this asynchronously; the fake does it now
		jsonOut(w, 202, map[string]any{"message": "Updating pull request branch.", "url": "https://github.test/" + r.FullName() + "/pull/" + strconv.Itoa(p.number)})
	}
}

func (s *Server) listCheckRuns(w http.ResponseWriter, req *http.Request, r *Repo) {
	sha := req.PathValue("sha")
	if r.commits[sha] == nil {
		refuse(w, 422, "No commit found for SHA: "+sha)
		return
	}
	q := req.URL.Query()
	name, filter := q.Get("check_name"), q.Get("filter")
	app, _ := strconv.ParseInt(q.Get("app_id"), 10, 64)
	if filter != "" && filter != "latest" && filter != "all" {
		refuse(w, 422, "Invalid filter")
		return
	}
	type key struct {
		name string
		app  int64
	}
	latest := map[key]*checkRun{}
	var match []*checkRun
	for _, c := range r.checks {
		if c.sha != sha || (name != "" && c.Name != name) || (app != 0 && c.AppID != app) {
			continue
		}
		match = append(match, c)
		if k := (key{c.Name, c.AppID}); latest[k] == nil || c.id > latest[k].id {
			latest[k] = c
		}
	}
	if filter != "all" {
		match = match[:0]
		for _, c := range latest {
			match = append(match, c)
		}
	}
	sort.Slice(match, func(i, j int) bool { return match[i].id > match[j].id })
	lo, hi := page(req, len(match))
	runs := []map[string]any{}
	for _, c := range match[lo:hi] {
		started := c.StartedAt
		if started.IsZero() {
			started = s.now.Add(time.Duration(c.id) * time.Second) // later runs start later
		}
		m := map[string]any{"id": c.id, "name": c.Name, "head_sha": c.sha, "status": c.Status,
			"started_at": started.UTC().Format(time.RFC3339),
			"html_url":   "https://github.test/" + r.FullName() + "/runs/" + strconv.FormatInt(c.id, 10)}
		if c.Conclusion != "" {
			m["conclusion"] = c.Conclusion
		} else {
			m["conclusion"] = nil
		}
		if c.AppID != 0 {
			m["app"] = map[string]any{"id": c.AppID}
		} else {
			m["app"] = nil
		}
		runs = append(runs, m)
	}
	jsonOut(w, 200, map[string]any{"total_count": len(match), "check_runs": runs})
}

func (s *Server) compare(w http.ResponseWriter, req *http.Request, r *Repo) {
	baseRef, headRef, ok := strings.Cut(req.PathValue("basehead"), "...")
	base, head := r.resolve(baseRef), r.resolve(headRef)
	if !ok || base == "" || head == "" {
		refuse(w, 404, "Not Found")
		return
	}
	ahead, behind := r.ahead(head, base), r.ahead(base, head)
	status := "diverged"
	switch {
	case ahead == 0 && behind == 0:
		status = "identical"
	case behind == 0:
		status = "ahead"
	case ahead == 0:
		status = "behind"
	}
	jsonOut(w, 200, map[string]any{
		"status": status, "ahead_by": ahead, "behind_by": behind, "total_commits": ahead,
		"base_commit":       map[string]any{"sha": base},
		"merge_base_commit": map[string]any{"sha": r.mergeBase(base, head)},
	})
}

// createCheckRun is POST /check-runs. As on GitHub, the run belongs to the App whose installation token made it
// (the fake has one App, [OwnAppID]); a body without head_sha, status or a valid conclusion is a 422.
func (s *Server) createCheckRun(w http.ResponseWriter, req *http.Request, r *Repo) {
	var b struct {
		Name       string `json:"name"`
		HeadSHA    string `json:"head_sha"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		Output     struct {
			Title   string `json:"title"`
			Summary string `json:"summary"`
		} `json:"output"`
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	if r.commits[b.HeadSHA] == nil {
		refuse(w, 422, "No commit found for SHA: "+b.HeadSHA)
		return
	}
	if b.Name == "" || b.Status != "completed" || (b.Conclusion != "success" && b.Conclusion != "failure") {
		refuse(w, 422, "Validation Failed")
		return
	}
	c := &checkRun{id: s.nextID(), Check: Check{Name: b.Name, AppID: OwnAppID, Status: "completed", Conclusion: b.Conclusion, Title: b.Output.Title, Summary: b.Output.Summary}, sha: b.HeadSHA}
	r.checks = append(r.checks, c)
	jsonOut(w, 201, map[string]any{"id": c.id, "name": c.Name, "head_sha": c.sha, "status": c.Status, "conclusion": c.Conclusion,
		"html_url": "https://github.test/" + r.FullName() + "/runs/" + strconv.FormatInt(c.id, 10), "app": map[string]any{"id": OwnAppID}})
}

func (s *Server) createDeployment(w http.ResponseWriter, req *http.Request, r *Repo) {
	var b struct {
		Ref              string    `json:"ref"`
		Environment      string    `json:"environment"`
		Description      string    `json:"description"`
		AutoMerge        *bool     `json:"auto_merge"`
		RequiredContexts *[]string `json:"required_contexts"`
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	sha := r.resolve(b.Ref)
	if sha == "" {
		refuse(w, 422, "No ref found for: "+b.Ref)
		return
	}
	if b.RequiredContexts == nil {
		for _, c := range r.checks {
			if c.sha == sha && c.Conclusion == "failure" {
				refuse(w, 409, "Conflict: Commit status checks failed for "+b.Ref+".")
				return
			}
		}
	}
	env := b.Environment
	if env == "" {
		env = "production"
	}
	d := &Deployment{ID: s.nextID(), SHA: sha, Ref: b.Ref, Environment: env, Description: b.Description}
	r.deploys = append(r.deploys, d)
	jsonOut(w, 201, map[string]any{"id": d.ID, "sha": sha, "ref": b.Ref, "environment": env, "description": b.Description})
}

func (s *Server) createDeploymentStatus(w http.ResponseWriter, req *http.Request, r *Repo) {
	id, _ := strconv.ParseInt(req.PathValue("id"), 10, 64)
	var b struct {
		State string `json:"state"`
	}
	if !decode(req, &b) {
		refuse(w, 400, "Problems parsing JSON")
		return
	}
	for _, d := range r.deploys {
		if d.ID != id {
			continue
		}
		switch b.State {
		case "error", "failure", "inactive", "in_progress", "queued", "pending", "success":
			d.Statuses = append(d.Statuses, b.State)
			jsonOut(w, 201, map[string]any{"id": s.nextID(), "state": b.State})
		default:
			validation(w, "state", "invalid", "")
		}
		return
	}
	refuse(w, 404, "Not Found")
}
