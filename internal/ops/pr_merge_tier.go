package ops

import (
	"path"
	"regexp"
	"strings"

	"github.com/joshua-noel/chaperone/internal/tierglob"
)

// PRTier is the review tier of a pull request (decision #22, ADR-002 step 5).
// It is decided by the paths the PR changes, never by who wrote it.
type PRTier string

// The tiers, lowest to highest.
const (
	// TierLow merges on the checks alone: docs and tests.
	TierLow PRTier = "low"
	// TierMedium needs one approval card: any other code path.
	TierMedium PRTier = "medium"
	// TierHigh needs an approval card that shows the diff: workflows,
	// migrations, host scripts, auth and payment code, deploy files, and any
	// path the policy cannot classify.
	TierHigh PRTier = "high"
)

func (t PRTier) rank() int {
	switch t {
	case TierLow:
		return 1
	case TierMedium:
		return 2
	}
	return 3 // TierHigh and anything unknown
}

// PRTierGlobs is the project part of the path classifier (policy data,
// `policy/<project>.yaml`). Globs are slash-separated, case-insensitive, and
// `**` matches any number of directories. A project can raise a path (High,
// Medium) or flag more paths Low, but a path the baseline makes high stays
// high: the strongest tier among all matching globs wins.
type PRTierGlobs struct {
	High, Medium, Low []string
}

// Baseline globs. High is deliberately wide: it is cheaper to approve one card
// than to merge a workflow edit, a migration or a deploy file unseen.
var (
	baselineHigh = []string{
		".github/**",
		"**/migrations/**",
		"scripts/**",
		"**/*.ps1", "**/*.psm1", "**/*.sh", "**/*.bash", "**/*.bat", "**/*.cmd",
		"**/auth/**", "**/authn/**", "**/authz/**", "**/authentication/**", "**/authorization/**",
		"**/auth.*", "**/auth-*", "**/auth_*", "**/*-auth.*", "**/*_auth.*",
		"**/payment/**", "**/payments/**", "**/billing/**", "**/stripe/**",
		"**/payment.*", "**/payments.*", "**/payment-*", "**/payment_*", "**/billing.*", "**/stripe.*",
		"**/deploy/**", "**/deploy.*", "**/deploy-*", "**/deploy_*",
		"**/dockerfile*", "**/docker-compose*", "**/compose.y*ml",
		"**/package.json", "**/package-lock.json", "**/pnpm-lock.yaml", "**/yarn.lock",
		"**/go.mod", "**/go.sum", "vendor/**", "**/.npmrc",
		"**/.env", "**/.env.*", "**/*.pem", "**/*.key",
		"**/codeowners", "**/.gitmodules", "**/.gitattributes", "**/agents.md", "**/claude.md",
		"**/redteam/**",
		"**/*.exe", "**/*.dll", "**/*.so", "**/*.dylib", "**/*.bin", "**/*.jar", "**/*.msi",
		"**/*.com", "**/*.scr", "**/*.vbs", "**/*.wsf", "**/*.lnk",
		"**/uv.lock",
		// Files and folders that instruct or configure a coding agent, an editor agent or an MCP client: a PR that
		// edits one changes what the agents of the project are told or may run. Matched at any depth, because
		// these tools read them in subfolders too.
		"**/gemini.md", "**/agent.md", "**/claude.local.md", "**/skill.md", "**/copilot-instructions.md", "**/*.instructions.md",
		"**/.cursorrules", "**/.windsurfrules", "**/.clinerules", "**/.aider*", "**/.mcp.json", "**/mcp.json",
		"**/.claude/**", "**/.cursor/**", "**/.clinerules/**", "**/.codex/**", "**/.gemini/**", "**/.omp/**",
		// A documentation build runs these.
		"**/.readthedocs.yaml", "**/.readthedocs.yml",
	}
	// baselineMedium raises paths that would otherwise be low (every *.txt is
	// docs) or that tell the build what to install: a Python requirements file
	// can point pip at another index, so it needs a card like code does. The
	// npm, pnpm, yarn, uv and go manifests and lock files are already high
	// above; pyproject.toml would be medium as a .toml file, and is listed so
	// the floor does not depend on the extension list.
	baselineMedium = []string{
		"**/requirements*.txt", "**/constraints*.txt", "**/pyproject.toml",
		// A build script that the *.txt rule would call low.
		"**/cmakelists.txt",
		// MDX is compiled to a program that runs when the site is built, and an SVG can carry script; the other
		// documentation types (Markdown, text, reStructuredText, AsciiDoc, images) are inert.
		"**/*.mdx", "docs/**/*.svg",
	}
	// baselineTests are the paths a PR weakens the checks through. Tests are
	// low on their own (CI runs them), but deleting or skipping them is medium.
	baselineTests = []string{
		"test/**", "tests/**", "e2e/**", "**/__tests__/**",
		"**/*_test.*", "**/*.test.*", "**/*.spec.*", "**/test_*.py",
	}
	// skipMarker matches an added line that switches a test off: Go t.Skip,
	// Jest, Vitest and Mocha skip, xit, xdescribe, xtest, .only (runs one test
	// and skips the rest), pytest skip and xfail, unittest skip, JUnit
	// @Disabled and @Ignore, Rust #[ignore].
	skipMarker = regexp.MustCompile(`(?i)(\.skip(now|f)?\s*\(|\b(skip|skipif|skipunless|xfail)\b\s*[(,)]|\bx(it|test|describe|context)\s*\(|\.only\s*\(|\bf(it|describe)\s*\(|pytest\.mark\.(skip|xfail)|unittest\.skip|@disabled\b|@ignore\b|#\[ignore\b)`)
	// Under docs/ only documentation file types are low. Anything else there falls through to the code rules, because
	// a documentation build runs it (docs/conf.py for Sphinx, docs/hooks.py, a Makefile).
	baselineLow = []string{
		"**/*.md", "**/*.txt", "license", "license.*",
		"docs/**/*.rst", "docs/**/*.adoc", "docs/**/*.png", "docs/**/*.jpg", "docs/**/*.jpeg", "docs/**/*.gif", "docs/**/*.webp",
		"**/*_test.go", "**/*.test.*", "**/*.spec.*",
	}
	// testDirs are low on their own (CI runs the tests), except the build and shell files in them: see lowByBaseline.
	testDirs = []string{"test/**", "tests/**", "e2e/**", "**/__tests__/**"}
	// testdata holds fixtures, and a YAML file there is data for a test, so only the files a build or a shell runs
	// are taken out of it.
	testdataDirs = []string{"**/testdata/**"}
	// Code and asset extensions that count as "any other code path". A path with
	// none of these, and no glob above, cannot be classified and is high.
	codeExt = map[string]bool{
		".go": true, ".ts": true, ".tsx": true, ".mts": true, ".cts": true, ".js": true, ".jsx": true,
		".mjs": true, ".cjs": true, ".css": true, ".scss": true, ".sass": true, ".less": true,
		".html": true, ".htm": true, ".svelte": true, ".vue": true, ".py": true, ".rb": true,
		".rs": true, ".java": true, ".kt": true, ".swift": true, ".c": true, ".h": true,
		".cc": true, ".cpp": true, ".json": true, ".jsonc": true, ".yaml": true, ".yml": true,
		".toml": true, ".sql": true, ".graphql": true, ".gql": true, ".proto": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true,
	}
)

// Validate reports a malformed glob.
func (g PRTierGlobs) Validate() error {
	for _, set := range [][]string{g.High, g.Medium, g.Low} {
		for _, p := range set {
			if err := tierglob.Validate(p); err != nil {
				return err
			}
		}
	}
	return nil
}

// globMatch matches a slash-separated path (already lower case) against a
// lower-case glob. `**` as a whole segment matches zero or more directories.
func globMatch(pattern, name string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegs(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for len(pat) > 0 && pat[0] == "**" {
				pat = pat[1:]
			}
			if len(pat) == 0 {
				return len(name) > 0 // "dir/**" needs something below dir
			}
			for i := range name {
				if matchSegs(pat, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], name[0])
		if err != nil || !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

func anyGlob(globs []string, name string) bool {
	for _, g := range globs {
		if globMatch(strings.ToLower(g), name) {
			return true
		}
	}
	return false
}

// cleanPath returns the lower-case form of a repository path, or false if it is not a plain path. A path that is not
// plain cannot be classified, and the classifier calls it high, whatever pattern it would match.
//
// The rule is a form, not a list of bad characters. A file system can read a name as another one in more ways than
// any list holds: Windows drops a trailing dot or space and has 8.3 short names (`github~1` is `.github`), NTFS has
// stream names (`agents.md::$DATA`), HFS+ ignores some invisible characters, case-insensitive APFS folds `ſ` to `s`
// and `ﬆ` to `st`. So only a path whose every component is made of ASCII letters and digits and the punctuation
// `. _ - + @ ( ) [ ] , =` and the space can be low (or get any test-path treatment), and the component
//
//   - is not empty, `.` or `..`;
//   - does not start or end with a space and does not end with a dot;
//   - has no `~`, so it is no short name.
//
// A name outside that form, such as `docs/café.md` or `docs/日本語.md`, is high and needs an approval. That is the
// price of not having to know every alias. A path that is absolute or holds a backslash is not plain either.
func cleanPath(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if !plainSegment(seg) {
			return "", false
		}
	}
	return strings.ToLower(p), true
}

// plainSegment reports whether one component of a path is in the form cleanPath allows.
func plainSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." || seg[0] == ' ' || seg[len(seg)-1] == ' ' || seg[len(seg)-1] == '.' {
		return false
	}
	for i := 0; i < len(seg); i++ {
		if c := seg[i]; c >= 0x80 || !tierglob.PlainRune(rune(c)) {
			return false
		}
	}
	return true
}

// ClassifyPath returns the tier of one repository path.
func (g PRTierGlobs) ClassifyPath(p string) PRTier {
	t, _ := g.classify(p)
	return t
}

// classify returns the tier and whether a rule classified the path. A path no
// rule covers is high and not classified.
func (g PRTierGlobs) classify(p string) (PRTier, bool) {
	name, ok := cleanPath(p)
	if !ok {
		return TierHigh, false
	}
	if anyGlob(baselineHigh, name) || anyGlob(g.High, name) {
		return TierHigh, true
	}
	if anyGlob(g.Medium, name) || anyGlob(baselineMedium, name) {
		return TierMedium, true
	}
	if lowByBaseline(name) || anyGlob(g.Low, name) {
		return TierLow, true
	}
	if codeExt[path.Ext(name)] {
		return TierMedium, true
	}
	return TierHigh, false
}

// PRTierResult is the classification of a whole pull request.
type PRTierResult struct {
	Tier PRTier
	// Paths are the changed paths that set the tier (up to 10), for the card.
	Paths []string
	// More counts paths that also set the tier and are not listed.
	More int
	// Unclassified is true if the tier is high because a path (or the whole
	// file list) could not be classified.
	Unclassified bool
	// TestsWeakened is true if the PR deletes or skips tests and so is at
	// least medium (the tests alone would be low).
	TestsWeakened bool
}

// PRFile is one changed file as the classifier sees it.
type PRFile struct {
	Path         string
	PreviousPath string // set for a rename: both sides are classified
	Status       string // GitHub's file status: added, removed, modified, renamed, ...
	Patch        string // unified diff; GitHub leaves it out of a very large or binary file
	Changes      int    // added plus deleted lines
}

// isTestPath reports whether a path is a test file or in a test directory.
func isTestPath(p string) bool {
	name, ok := cleanPath(p)
	return ok && anyGlob(baselineTests, name)
}

// weakensTests reports whether a file deletes a test file, moves one out of
// the test paths, or adds a skip marker to one. A test file whose diff GitHub
// did not send cannot be read, so a change to it counts too.
func weakensTests(f PRFile) bool {
	switch {
	case f.Status == "removed" && isTestPath(f.Path):
		return true
	case f.PreviousPath != "" && isTestPath(f.PreviousPath) && !isTestPath(f.Path):
		return true
	case !isTestPath(f.Path):
		return false
	case f.Patch == "":
		return f.Changes > 0
	}
	for _, line := range strings.Split(f.Patch, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") && skipMarker.MatchString(line) {
			return true
		}
	}
	return false
}

// Classify classifies a PR: the highest tier of any changed path. An empty
// file list cannot be classified and is high.
func (g PRTierGlobs) Classify(files []PRFile) PRTierResult {
	if len(files) == 0 {
		return PRTierResult{Tier: TierHigh, Unclassified: true}
	}
	best := TierLow
	unclassified := false
	byTier := map[PRTier][]string{}
	add := func(p string) {
		t, ok := g.classify(p)
		unclassified = unclassified || !ok
		byTier[t] = append(byTier[t], p)
		if t.rank() > best.rank() {
			best = t
		}
	}
	var weakened []string
	for _, f := range files {
		add(f.Path)
		if f.PreviousPath != "" {
			add(f.PreviousPath)
		}
		if weakensTests(f) {
			weakened = append(weakened, f.Path)
		}
	}
	testsWeakened := false
	if len(weakened) > 0 && best.rank() <= TierMedium.rank() {
		// Tests are low on their own; deleting or skipping them is medium.
		testsWeakened = true
		if best == TierLow {
			best, byTier[TierMedium] = TierMedium, nil
		}
		byTier[TierMedium] = append(byTier[TierMedium], weakened...)
	}
	res := PRTierResult{Tier: best, Unclassified: unclassified && best == TierHigh, TestsWeakened: testsWeakened}
	const maxListed = 10
	if setters := byTier[best]; len(setters) > maxListed {
		res.Paths, res.More = setters[:maxListed], len(setters)-maxListed
	} else {
		res.Paths = setters
	}
	return res
}

// lowByBaseline reports whether the baseline calls a (plain, lower-case) path low. Anything under test/, tests/,
// e2e/, __tests__/ and testdata/ is low, as tests are, except a build or shell file there (a Makefile, a Dockerfile, a script, a workflow or
// compose file): that is run by a build or by a person, and is not a test.
func lowByBaseline(name string) bool {
	if anyGlob(testDirs, name) && buildFile(name) {
		return false
	}
	if anyGlob(testdataDirs, name) {
		ext := path.Ext(name)
		return !buildFile(name) || ext == ".yml" || ext == ".yaml"
	}
	return anyGlob(baselineLow, name) || anyGlob(testDirs, name)
}

// buildFile reports whether a lower-case path names a build, shell or pipeline file.
func buildFile(name string) bool {
	base := path.Base(name)
	switch {
	case base == "makefile", base == "gnumakefile", base == "justfile", strings.HasPrefix(base, "dockerfile"):
		return true
	}
	switch path.Ext(base) {
	case ".sh", ".bash", ".ps1", ".psm1", ".bat", ".cmd", ".mk", ".yml", ".yaml":
		return true
	}
	return false
}
