package ops

import (
	"fmt"
	"regexp"
	"unicode/utf8"
)

// MaxPRTitle is the longest squash commit header (AGENTS.md, house rules).
const MaxPRTitle = 72

// titleRE is one Conventional Commits header: type(scope)!: description. The
// types are the ones AGENTS.md lists.
var titleRE = regexp.MustCompile(`^(?:feat|fix|docs|test|refactor|chore|style|perf|build|ci)(?:\([a-z0-9][a-z0-9._/-]*\))?!?: [^\s]`)

// checkTitle applies ADR-002 step 6: the squash commit header is the PR title,
// one Conventional Commit line of at most 72 characters. The reason it returns
// never repeats the title (it is attacker-controlled text).
func checkTitle(title string) error {
	if n := utf8.RuneCountInString(title); n > MaxPRTitle {
		return fmt.Errorf("title is %d characters, the limit is %d", n, MaxPRTitle)
	}
	if !utf8.ValidString(title) {
		return fmt.Errorf("title is not valid UTF-8")
	}
	for _, r := range title {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return fmt.Errorf("title is not a single line")
		}
	}
	if title != "" && (title[len(title)-1] == ' ' || title[len(title)-1] == '\t') {
		return fmt.Errorf("title ends with whitespace")
	}
	if !titleRE.MatchString(title) {
		return fmt.Errorf("title is not a Conventional Commit header (type(scope): description)")
	}
	return nil
}
