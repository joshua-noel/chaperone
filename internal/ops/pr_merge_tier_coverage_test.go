package ops_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/joshua-noel/chaperone/internal/ops"
)

// Gap: files under docs/ that a documentation build runs (conf.py, a Makefile, a hook) were low. Under docs/ only
// documentation file types are low; every other file falls through to the code rules.
func TestOnlyDocumentationFileTypesAreLowUnderDocs(t *testing.T) {
	g := ops.PRTierGlobs{}
	for p, want := range map[string]ops.PRTier{
		"docs/notes.md": ops.TierLow, "docs/a/b/guide.MD": ops.TierLow, "docs/page.mdx": ops.TierLow, "docs/notes.txt": ops.TierLow,
		"docs/index.rst": ops.TierLow, "docs/guide.adoc": ops.TierLow, "docs/img/logo.png": ops.TierLow, "docs/a.jpg": ops.TierLow,
		"docs/a.jpeg": ops.TierLow, "docs/a.gif": ops.TierLow, "docs/a.webp": ops.TierLow,
		"docs/diagram.svg": ops.TierMedium, // an SVG can carry script
		"docs/conf.py":     ops.TierMedium, "docs/hooks.py": ops.TierMedium, "docs/_config.yml": ops.TierMedium, "docs/site.html": ops.TierMedium,
		"docs/Makefile": ops.TierHigh, "docs/.readthedocs.yaml": ops.TierHigh, "docs/package.json": ops.TierHigh, "docs/CNAME": ops.TierHigh,
		"docs/build.sh": ops.TierHigh, "docs/Dockerfile": ops.TierHigh, ".readthedocs.yml": ops.TierHigh,
		// elsewhere, as before
		"README.md": ops.TierLow, "guide.rst": ops.TierHigh, "logo.png": ops.TierMedium, "conf.py": ops.TierMedium,
	} {
		if got := g.ClassifyPath(p); got != want {
			t.Errorf("ClassifyPath(%q) = %s, want %s", p, got, want)
		}
	}
}

// Tests are low by design. A build or shell file under a test folder is not a test.
func TestBuildFilesUnderTestFoldersAreNotLow(t *testing.T) {
	g := ops.PRTierGlobs{}
	for p, want := range map[string]ops.PRTier{
		// low, as before
		"tests/foo_test.go": ops.TierLow, "tests/new_thing.go": ops.TierLow, "tests/conftest.py": ops.TierLow,
		"tests/test_a.py": ops.TierLow, "test/a.js": ops.TierLow, "e2e/login.ts": ops.TierLow, "tests/fixtures/data.json": ops.TierLow,
		"tests/notes.md": ops.TierLow, "internal/x/testdata/ci.yml": ops.TierLow,
		// not low
		"tests/Makefile": ops.TierHigh, "tests/GNUmakefile": ops.TierHigh, "test/justfile": ops.TierHigh, "tests/rules.mk": ops.TierHigh,
		"tests/run.sh": ops.TierHigh, "tests/run.ps1": ops.TierHigh, "tests/run.bat": ops.TierHigh, "tests/run.cmd": ops.TierHigh,
		"tests/Dockerfile": ops.TierHigh, "tests/Dockerfile.ci": ops.TierHigh, "e2e/docker-compose.yml": ops.TierHigh,
		"tests/ci.yml": ops.TierMedium, "tests/ci.yaml": ops.TierMedium, "e2e/pipeline.yml": ops.TierMedium, "test/x.test.yml": ops.TierMedium,
	} {
		if got := g.ClassifyPath(p); got != want {
			t.Errorf("ClassifyPath(%q) = %s, want %s", p, got, want)
		}
	}
	// A new test file is low; removing one is medium (tests weakened), as before.
	if r := g.Classify([]ops.PRFile{{Path: "tests/new_test.go", Status: "added", Changes: 5, Patch: "+func TestA(t *testing.T) {}\n"}}); r.Tier != ops.TierLow {
		t.Errorf("a new test file = %+v", r)
	}
	if r := g.Classify([]ops.PRFile{{Path: "tests/old_test.go", Status: "removed", Changes: 5}}); r.Tier != ops.TierMedium || !r.TestsWeakened {
		t.Errorf("a removed test file = %+v", r)
	}
}

// Files that instruct or configure an agent are high, at any depth, whatever the case. A build script is not low.
func TestAgentInstructionFilesAreHigh(t *testing.T) {
	g := ops.PRTierGlobs{}
	for _, p := range []string{
		"GEMINI.md", "sub/gemini.md", "AGENT.md", "pkg/Agent.md", "CLAUDE.local.md", "sub/claude.local.md",
		".cursorrules", "web/.cursorrules", ".windsurfrules", "web/.windsurfrules", ".clinerules", ".clinerules/rules.md",
		".github/copilot-instructions.md", "copilot-instructions.md", "docs/guide.instructions.md", ".github/instructions/go.instructions.md", "x.INSTRUCTIONS.md",
		".claude/settings.json", ".claude/commands/deploy.md", "sub/.claude/settings.json", ".cursor/rules/a.mdc", ".cursor/mcp.json",
		".codex/config.toml", ".gemini/settings.json", ".omp/agents/a.md", ".aider.conf.yml", ".aiderignore", ".aider.chat.history.md",
		".mcp.json", "mcp.json", ".vscode/mcp.json", "skills/deploy/SKILL.md", "SKILL.md", ".claude/skills/x/skill.md",
	} {
		if got := g.ClassifyPath(p); got != ops.TierHigh {
			t.Errorf("ClassifyPath(%q) = %s, want high", p, got)
		}
	}
	for _, p := range []string{"CMakeLists.txt", "sub/CMakeLists.txt", "cmake/cmakelists.txt"} {
		if got := g.ClassifyPath(p); got != ops.TierMedium {
			t.Errorf("ClassifyPath(%q) = %s, want medium", p, got)
		}
	}
	if got := g.ClassifyPath("notes.txt"); got != ops.TierLow {
		t.Errorf("notes.txt = %s, want low", got)
	}
}

// A project glob may flag more paths low but never lowers a baseline medium: the manifests stay medium.
func TestProjectLowGlobNeverLowersBaselineMedium(t *testing.T) {
	g := ops.PRTierGlobs{Low: []string{"**", "**/*.txt", "**/*.toml", "requirements.txt", "pyproject.toml"}}
	for _, p := range []string{"requirements.txt", "requirements-dev.txt", "constraints.txt", "pyproject.toml", "sub/pyproject.toml", "CMakeLists.txt", "docs/diagram.svg"} {
		if got := g.ClassifyPath(p); got != ops.TierMedium {
			t.Errorf("with a project low glob of **, ClassifyPath(%q) = %s, want medium", p, got)
		}
	}
	for _, p := range []string{".github/workflows/ci.yml", "CLAUDE.md", ".claude/settings.json", "scripts/run.sh"} {
		if got := g.ClassifyPath(p); got != ops.TierHigh {
			t.Errorf("with a project low glob of **, ClassifyPath(%q) = %s, want high", p, got)
		}
	}
}

// A project glob with a character that no plain path name can hold would never match anything: refuse it, and say why.
func TestTierGlobThatCanNeverMatchIsRefused(t *testing.T) {
	for _, bad := range []string{"docs/caf\u00e9/**", "docs/\u65e5\u672c\u8a9e/**", "web/a~1/**", "docs/a#b.md", "docs/a$b/**", "docs/a;b/**", "docs/a{b}/**", "docs/a|b", "docs/a%b", "docs/a\tb", "docs/a:b", `docs\a`, "docs/a!b"} {
		for name, g := range map[string]ops.PRTierGlobs{"high": {High: []string{bad}}, "medium": {Medium: []string{bad}}, "low": {Low: []string{bad}}} {
			err := g.Validate()
			if err == nil {
				t.Errorf("%s glob %q accepted", name, bad)
			} else if !strings.Contains(err.Error(), strconv.Quote(bad)) {
				t.Errorf("the refusal of %q does not name it: %v", bad, err)
			}
		}
	}
	err := (ops.PRTierGlobs{Low: []string{"docs/caf\u00e9/**"}}).Validate()
	if err == nil || !strings.Contains(err.Error(), "always high") {
		t.Errorf("the refusal does not say what happens to such a name: %v", err)
	}
	ok := ops.PRTierGlobs{
		High:   []string{"web/src/**/*.ts", "**/*.sh", "a/**/b.go", "docs/[a-c]*.md", "docs/[^a]?.md"},
		Medium: []string{"Docs/Getting Started/**", "docs/v1.2/**", "x/a+b@c(1)[2],d=e_f-g/**"},
		Low:    []string{"docs/**"},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("a plain glob was refused: %v", err)
	}
}
