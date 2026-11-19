package ops

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
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
	}
	// baselineMedium raises paths that would otherwise be low (every *.txt is
	// docs) or that tell the build what to install: a Python requirements file
	// can point pip at another index, so it needs a card like code does. The
	// npm, pnpm, yarn, uv and go manifests and lock files are already high
	// above; pyproject.toml would be medium as a .toml file, and is listed so
	// the floor does not depend on the extension list.
	baselineMedium = []string{
		"**/requirements*.txt", "**/constraints*.txt", "**/pyproject.toml",
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
	skipMarker  = regexp.MustCompile(`(?i)(\.skip(now|f)?\s*\(|\b(skip|skipif|skipunless|xfail)\b\s*[(,)]|\bx(it|test|describe|context)\s*\(|\.only\s*\(|\bf(it|describe)\s*\(|pytest\.mark\.(skip|xfail)|unittest\.skip|@disabled\b|@ignore\b|#\[ignore\b)`)
	baselineLow = []string{
		"docs/**", "**/*.md", "**/*.mdx", "**/*.txt", "license", "license.*",
		"test/**", "tests/**", "e2e/**", "**/__tests__/**", "**/testdata/**",
		"**/*_test.go", "**/*.test.*", "**/*.spec.*",
	}
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
			if err := validGlob(p); err != nil {
				return err
			}
		}
	}
	return nil
}

func validGlob(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, `\`) {
		return fmt.Errorf("ops: bad tier glob %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "**" {
			continue
		}
		if _, err := path.Match(strings.ToLower(seg), ""); err != nil {
			return fmt.Errorf("ops: bad tier glob %q: %w", p, err)
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

// cleanPath returns the lower-case form of a repository path, or false if it
// is not a plain relative slash path. Such a path cannot be classified, and
// the classifier then calls it high. A path is not plain when it is empty,
// absolute, holds a backslash, a dot segment or a control character (these
// five were refused before), or when a file system could read it as another
// name than the one it has:
//
//   - a hidden character: a Unicode format character (bidi controls,
//     zero-width characters, a byte order mark) or another default-ignorable
//     code point (a variation selector, a tag, U+034F, U+115F, U+1160,
//     U+17B4, U+17B5, U+180B-U+180F, U+3164, U+FFA0). macOS HFS+ ignores
//     some of them in names, so `agents<U+200C>.md` is `agents.md` there, and
//     a glob would take it for a doc;
//   - a name that ends in a dot or a space: Windows drops them, so
//     `agents.md.` and `agents.md ` are `agents.md` on a Windows checkout;
//   - a colon: on NTFS `agents.md::` is the stream of `agents.md`.
func cleanPath(p string) (string, bool) {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.Contains(p, `\`) || strings.Contains(p, ":") {
		return "", false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || hiddenRune(r) {
			return "", false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return "", false
		}
	}
	return strings.ToLower(p), true
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
	if anyGlob(baselineLow, name) || anyGlob(g.Low, name) {
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

// hiddenRune reports whether r is a character that shows as nothing, or that a file system ignores in a name: a
// Unicode format character (class Cf) or another default-ignorable code point.
func hiddenRune(r rune) bool {
	switch {
	case unicode.Is(unicode.Cf, r):
		return true
	case r == 0x034f, r == 0x115f, r == 0x1160, r == 0x17b4, r == 0x17b5, r == 0x3164, r == 0xffa0:
		return true
	case r >= 0x180b && r <= 0x180f, r >= 0xfe00 && r <= 0xfe0f, r >= 0xe0000 && r <= 0xe007f, r >= 0xe0100 && r <= 0xe01ef:
		return true
	}
	return false
}
