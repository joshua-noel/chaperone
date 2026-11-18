package ops

import (
	"strings"
	"testing"
)

func TestTitleRule(t *testing.T) {
	good := []string{
		"feat: add pr.merge",
		"fix(gh): refuse a fork",
		"feat(ops)!: drop the old verb",
		"docs: " + strings.Repeat("a", 66), // exactly 72
		"ci: pin runner",
		"chore(deps): bump x/crypto",
		"feat: " + strings.Repeat("é", 66), // 72 characters, 138 bytes
	}
	bad := []string{
		"",
		"Update notes",
		"feat add thing",
		"feat:no space",
		"feat: ",
		"feature: add",
		"FEAT: add",
		"feat(Scope): add",
		"feat(): add",
		"docs: " + strings.Repeat("a", 67), // 73
		"feat: add\nBREAKING CHANGE: x",
		"feat: add\r",
		"feat: add ",
		"feat: add\u2028x",
		"feat: \xff",
		" feat: add",
	}
	for _, s := range good {
		if err := checkTitle(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	for _, s := range bad {
		err := checkTitle(s)
		if err == nil {
			t.Errorf("%q accepted", s)
			continue
		}
		if len(s) > 12 && strings.Contains(err.Error(), s) {
			t.Errorf("reason echoes the title: %v", err)
		}
	}
}
