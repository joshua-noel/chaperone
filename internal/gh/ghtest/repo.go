package ghtest

import (
	"fmt"
	"time"
)

type commit struct {
	sha     string
	parents []string
}

// OwnAppID is the numeric ID of the fake's own App (the one the installation belongs to): check runs created through
// POST /check-runs belong to it, and GET /repos/{o}/{r}/installation reports it as `app_id`.
const OwnAppID int64 = 424242

// OwnChecks returns the check runs created through POST /check-runs (by the App itself) on a commit, oldest first.
func (r *Repo) OwnChecks(sha string) []Check {
	r.in.s.mu.Lock()
	defer r.in.s.mu.Unlock()
	var out []Check
	for _, c := range r.checks {
		if c.sha == sha && c.AppID == OwnAppID {
			out = append(out, c.Check)
		}
	}
	return out
}

// Check describes a check run to plant on a commit.
type Check struct {
	Name       string
	AppID      int64 // 15368 is GitHub Actions
	Status     string
	Conclusion string
	// StartedAt is the run start time; zero means "after every earlier run".
	StartedAt time.Time
	// Title and Summary are the output a check run created through POST /check-runs carries.
	Title, Summary string
	// ExternalID is the `external_id` a check run created through POST /check-runs carried; empty if none.
	ExternalID string
}

type checkRun struct {
	id int64
	Check
	sha string
}

// File is a changed file of a PR.
type File struct {
	Filename         string
	Status           string // defaults to "modified"
	PreviousFilename string
	Additions        int
	Deletions        int
	Patch            string // unified diff; empty is omitted, as GitHub omits it for a large file
}

// PROptions describes a pull request to open.
type PROptions struct {
	Title string
	Head  string // existing branch
	Base  string // existing branch
	Draft bool
	// Fork makes head.repo.full_name another repository.
	Fork bool
	// Body, Author and Labels are what GET /pulls/{n} reports besides the title.
	Body   string
	Author string
	Labels []string
}

type pull struct {
	number   int
	title    string
	head     string
	base     string
	draft    bool
	fork     bool
	state    string
	merged   bool
	mergeSHA string
	conflict bool
	files    []File
	body     string
	author   string
	labels   []string
	unknown  bool // GitHub has not computed `mergeable` yet: it answers null
}

// Protection models Team-plan branch protection on the default branch. Free-plan
// repositories (the default here, and Storefront's) have none.
type Protection struct {
	// RequiredCheck: merge is refused with 405 unless the latest check run of
	// this name on the exact head is completed/success.
	RequiredCheck string
	// RequiredAppID pins the check to one App (0 = any source).
	RequiredAppID int64
	// StrictUpToDate: merge is refused with 405 if the head is behind the base.
	StrictUpToDate bool
}

// Deployment is a recorded deployment.
type Deployment struct {
	ID          int64
	SHA, Ref    string
	Environment string
	Description string
	Statuses    []string
}

// Repo is a fake repository. Methods are safe for concurrent use.
type Repo struct {
	in       *Installation
	Name     string
	Default  string
	commits  map[string]*commit
	branches map[string]string
	pulls    map[int]*pull
	issues   map[int]*issue
	checks   []*checkRun
	prot     Protection
	denied   map[string]bool
	deploys  []*Deployment
}

// AddRepo creates a repository with one root commit on defaultBranch.
func (in *Installation) AddRepo(name, defaultBranch string) *Repo {
	s := in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	r := &Repo{in: in, Name: name, Default: defaultBranch,
		commits: map[string]*commit{}, branches: map[string]string{}, pulls: map[int]*pull{}, issues: map[int]*issue{}, denied: map[string]bool{}}
	root := r.newCommit()
	r.branches[defaultBranch] = root
	in.repos[name] = r
	return r
}

// FullName is "account/name".
func (r *Repo) FullName() string { return r.in.Account + "/" + r.Name }

// newCommit adds a commit; the caller holds s.mu.
func (r *Repo) newCommit(parents ...string) string {
	n := r.in.s.nextID()
	c := &commit{sha: hexSHA(n, r.FullName()), parents: parents}
	r.commits[c.sha] = c
	return c.sha
}

// Commit adds a commit to an existing branch and returns its SHA.
func (r *Repo) Commit(branch string) string {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	head, ok := r.branches[branch]
	if !ok {
		s.fail(s.t, "Commit: no branch %q", branch)
		return ""
	}
	sha := r.newCommit(head)
	r.branches[branch] = sha
	return sha
}

// Branch creates branch at the current head of from.
func (r *Repo) Branch(name, from string) string {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	head, ok := r.branches[from]
	if !ok {
		s.fail(s.t, "Branch: no branch %q", from)
		return ""
	}
	r.branches[name] = head
	return head
}

// Head is the current SHA of a branch ("" if missing).
func (r *Repo) Head(branch string) string {
	r.in.s.mu.Lock()
	defer r.in.s.mu.Unlock()
	return r.branches[branch]
}

// OpenPR opens a pull request and returns its number.
func (r *Repo) OpenPR(o PROptions) int {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	return r.openPR(o)
}

func (r *Repo) openPR(o PROptions) int {
	s := r.in.s
	if r.branches[o.Head] == "" || r.branches[o.Base] == "" {
		s.fail(s.t, "OpenPR: head %q or base %q is missing", o.Head, o.Base)
		return 0
	}
	n := len(r.pulls) + 1
	r.pulls[n] = &pull{number: n, title: o.Title, head: o.Head, base: o.Base, draft: o.Draft, fork: o.Fork, state: "open",
		body: o.Body, author: o.Author, labels: o.Labels}
	return n
}

// SetFiles sets the changed files of a PR.
func (r *Repo) SetFiles(number int, files ...File) {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := r.pulls[number]; p != nil {
		p.files = files
	} else {
		s.fail(s.t, "SetFiles: no PR %d", number)
	}
}

// SetTitle edits the title of a PR, as its author can at any time.
func (r *Repo) SetTitle(number int, title string) {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := r.pulls[number]; p != nil {
		p.title = title
	} else {
		s.fail(s.t, "SetTitle: no PR %d", number)
	}
}

// SetConflict marks a PR as having (or not having) a merge conflict.
func (r *Repo) SetConflict(number int, conflict bool) {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := r.pulls[number]; p != nil {
		p.conflict = conflict
	} else {
		s.fail(s.t, "SetConflict: no PR %d", number)
	}
}

// SetMergeableUnknown makes GitHub answer `mergeable: null` for a PR, as it does while it computes mergeability.
func (r *Repo) SetMergeableUnknown(number int, unknown bool) {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := r.pulls[number]; p != nil {
		p.unknown = unknown
	} else {
		s.fail(s.t, "SetMergeableUnknown: no PR %d", number)
	}
}

// SetCheck plants a check run on a commit and returns its id. Later runs of the
// same name and App supersede earlier ones under filter=latest.
func (r *Repo) SetCheck(sha string, c Check) int64 {
	s := r.in.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.commits[sha] == nil {
		s.fail(s.t, "SetCheck: unknown commit %s", sha)
		return 0
	}
	cr := &checkRun{id: s.nextID(), Check: c, sha: sha}
	r.checks = append(r.checks, cr)
	return cr.id
}

// Protect turns branch protection on the default branch on or off.
func (r *Repo) Protect(p Protection) {
	r.in.s.mu.Lock()
	r.prot = p
	r.in.s.mu.Unlock()
}

// DisallowMergeMethod makes merges with the method answer 405.
func (r *Repo) DisallowMergeMethod(method string) {
	r.in.s.mu.Lock()
	r.denied[method] = true
	r.in.s.mu.Unlock()
}

// PRHead is the current head SHA of a PR's branch.
func (r *Repo) PRHead(number int) string {
	r.in.s.mu.Lock()
	defer r.in.s.mu.Unlock()
	if p := r.pulls[number]; p != nil {
		return r.branches[p.head]
	}
	return ""
}

// Merged reports whether a PR was merged and the merge commit.
func (r *Repo) Merged(number int) (bool, string) {
	r.in.s.mu.Lock()
	defer r.in.s.mu.Unlock()
	if p := r.pulls[number]; p != nil {
		return p.merged, p.mergeSHA
	}
	return false, ""
}

// Deployments returns the recorded deployments.
func (r *Repo) Deployments() []Deployment {
	r.in.s.mu.Lock()
	defer r.in.s.mu.Unlock()
	out := make([]Deployment, len(r.deploys))
	for i, d := range r.deploys {
		out[i] = *d
		out[i].Statuses = append([]string(nil), d.Statuses...)
	}
	return out
}

// ancestors returns sha and every commit reachable from it.
func (r *Repo) ancestors(sha string) map[string]bool {
	seen := map[string]bool{}
	stack := []string{sha}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[x] || r.commits[x] == nil {
			continue
		}
		seen[x] = true
		stack = append(stack, r.commits[x].parents...)
	}
	return seen
}

// ahead counts commits reachable from a but not from b.
func (r *Repo) ahead(a, b string) int {
	inB := r.ancestors(b)
	n := 0
	for sha := range r.ancestors(a) {
		if !inB[sha] {
			n++
		}
	}
	return n
}

// mergeBase returns the nearest commit (breadth-first from a) that b reaches.
func (r *Repo) mergeBase(a, b string) string {
	inB := r.ancestors(b)
	queue, seen := []string{a}, map[string]bool{}
	for len(queue) > 0 {
		x := queue[0]
		queue = queue[1:]
		if seen[x] || r.commits[x] == nil {
			continue
		}
		seen[x] = true
		if inB[x] {
			return x
		}
		queue = append(queue, r.commits[x].parents...)
	}
	return ""
}

// resolve turns a branch name or a known SHA into a SHA.
func (r *Repo) resolve(ref string) string {
	if sha, ok := r.branches[ref]; ok {
		return sha
	}
	if r.commits[ref] != nil {
		return ref
	}
	return ""
}

func (r *Repo) String() string { return fmt.Sprintf("ghtest.Repo(%s)", r.FullName()) }
