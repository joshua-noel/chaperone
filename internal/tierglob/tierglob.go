// Package tierglob checks the path globs a project may add to the pull request tier classifier
// (`tiers:` in policy/<project>.yaml). It depends on the standard library only, so the policy loader and the
// classifier in internal/ops can both import it and use the same rule.
//
// The classifier calls a path low only when its form is plain (see PlainRune). Every other path is high, whatever
// glob it would match. A glob that holds a character no plain path can hold would therefore never match anything,
// and Validate refuses it, so a mistake does not silently do nothing.
package tierglob

import (
	"fmt"
	"path"
	"strings"
)

// PlainRune reports whether r may be in a component of a plain path: an ASCII letter or digit, one of
// `. _ - + @ ( ) [ ] , =`, or the space. It is the one definition of the allowed characters; internal/ops uses it to
// decide which paths can be low.
func PlainRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-+@()[],= ", r)
}

// Validate reports why a tier glob is not usable: it is empty, absolute, holds a backslash or a character that no
// plain path can hold, or is not valid glob syntax. Globs are slash-separated and case-insensitive; `**` as a whole
// component matches any number of directories. The error names the glob.
func Validate(glob string) error {
	if glob == "" || strings.HasPrefix(glob, "/") || strings.Contains(glob, `\`) {
		return fmt.Errorf("bad tier glob %q: it must be a non-empty relative path with forward slashes", glob)
	}
	for _, r := range glob {
		if !PlainRune(r) && !strings.ContainsRune("*?^/", r) {
			return fmt.Errorf("tier glob %q holds %q, which no plain path name can hold, so it would never match: a path with an accent, another script, ~ or other punctuation in its name is always high (docs/running-chapd.md)", glob, r)
		}
	}
	for _, seg := range strings.Split(glob, "/") {
		if seg == "**" {
			continue
		}
		if _, err := path.Match(strings.ToLower(seg), ""); err != nil {
			return fmt.Errorf("bad tier glob %q: %w", glob, err)
		}
	}
	return nil
}
