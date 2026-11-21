package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Engine hands out the effective policy of a project. Project files are read
// from Dir; a file that changes on disk is picked up on the next call (checked
// at most once per second per project), so a policy PR deployed to the host
// takes effect without a restart and with a new policy_version.
type Engine struct {
	cat  *Catalog
	base *Pack
	dir  string
	now  func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	checked time.Time
	size    int64
	mtime   time.Time
	missing bool
	eff     *Effective
}

// NewEngine returns an engine over the baseline and the project files in dir.
// dir may be empty: every project then gets the baseline.
func NewEngine(cat *Catalog, base *Pack, dir string) *Engine {
	return &Engine{cat: cat, base: base, dir: dir, now: time.Now, cache: map[string]cached{}}
}

// Catalog returns the op catalog.
func (e *Engine) Catalog() *Catalog { return e.cat }

// Baseline returns the baseline pack.
func (e *Engine) Baseline() *Pack { return e.base }

// For returns the effective policy of project; never nil. An unreadable or
// invalid project file gives an Effective with Invalid set (fail closed).
func (e *Engine) For(project string) *Effective {
	if e.dir == "" || !projectRe.MatchString(project) {
		return e.base.ForProject(project)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	c, ok := e.cache[project]
	if ok && now.Sub(c.checked) < time.Second {
		return c.eff
	}
	path := filepath.Join(e.dir, project+".yaml")
	st, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if ok && c.missing {
			c.checked = now
			e.cache[project] = c
			return c.eff
		}
		c = cached{checked: now, missing: true, eff: e.base.ForProject(project)}
	case err != nil:
		c = cached{checked: now, eff: e.broken(project, err)}
	case ok && !c.missing && st.Size() == c.size && st.ModTime().Equal(c.mtime):
		c.checked = now
	default:
		data, rerr := os.ReadFile(path)
		var eff *Effective
		if rerr != nil {
			eff = e.broken(project, rerr)
		} else if eff, err = e.base.LoadProject(project, data, e.cat); err != nil {
			eff = e.broken(project, fmt.Errorf("%s: %w", filepath.Base(path), err))
		}
		c = cached{checked: now, size: st.Size(), mtime: st.ModTime(), eff: eff}
	}
	e.cache[project] = c
	return c.eff
}

func (e *Engine) broken(project string, err error) *Effective {
	eff := e.base.ForProject(project)
	eff.Version = e.base.Version + "+invalid"
	eff.Invalid = fmt.Errorf("policy for project %s is invalid: %w", project, err)
	return eff
}

// Problem is a project file the engine cannot use as written, found by [Engine.Problems].
type Problem struct {
	Project string
	File    string // the file name in the policy folder, <project>.yaml
	// Block is "" when the whole project is refused (an invalid file), or the part that is off: "pr" for a bad tier
	// glob, which turns off pr.merge and pr.update only, "linear.issues" for a bad block of that name, which turns
	// off the Linear issue operations only, "sentry" for a bad block of that name, which turns off the Sentry
	// operations only, and "resend" for a bad block of that name, which turns off the Resend side of mail.send only.
	Block string
	Err   error
}

// Problems reads every project file in the policy folder and returns the ones that are invalid, or whose pr block is
// unusable. chapd logs them once at start. It reads through [Engine.For], so it fills the cache and a file that
// changes later is still picked up on the next call.
func (e *Engine) Problems() []Problem {
	if e.dir == "" {
		return nil
	}
	entries, err := os.ReadDir(e.dir)
	if err != nil {
		return nil
	}
	var out []Problem
	for _, ent := range entries {
		name := ent.Name()
		project, ok := strings.CutSuffix(name, ".yaml")
		if !ok || ent.IsDir() || !projectRe.MatchString(project) {
			continue
		}
		eff := e.For(project)
		if eff.Invalid != nil {
			out = append(out, Problem{Project: project, File: name, Err: eff.Invalid})
			continue
		}
		if eff.PR != nil && eff.PR.Invalid != nil {
			out = append(out, Problem{Project: project, File: name, Block: "pr", Err: eff.PR.Invalid})
		}
		if eff.Linear != nil && eff.Linear.IssuesInvalid != nil {
			out = append(out, Problem{Project: project, File: name, Block: "linear.issues", Err: eff.Linear.IssuesInvalid})
		}
		if eff.Sentry != nil && eff.Sentry.Invalid != nil {
			out = append(out, Problem{Project: project, File: name, Block: "sentry", Err: eff.Sentry.Invalid})
		}
		if eff.Resend != nil && eff.Resend.Invalid != nil {
			out = append(out, Problem{Project: project, File: name, Block: "resend", Err: eff.Resend.Invalid})
		}
	}
	return out
}
