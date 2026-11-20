// Package tierglob checks the path globs a project may add to the pull request tier classifier
// (`tiers:` in policy/<project>.yaml). It depends on the standard library only, so the policy loader and the
// classifier in internal/ops can both import it and use the same rule.
//
// The classifier calls a path low only when its form is plain (see PlainRune). Every other path is high, whatever
// glob it would match. A glob that can never match a plain path would therefore do nothing, and Validate refuses
// it, so a mistake does not pass unnoticed.
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

// Validate reports why a tier glob is not usable. Globs are slash-separated and case-insensitive. `**` as a whole
// component matches any number of directories, `*` and `?` match within a component, and `[...]` is a character
// class: a set of characters or ranges such as `[a-c]`, with `^` first for "not". The class has no escape, so a
// folder whose name holds brackets, such as Next.js `app/[slug]/`, is written with `?` for each bracket:
// `app/?slug?/`.
//
// A glob is refused when it can never match a plain path: it is empty, absolute, or holds a backslash or a
// character that no plain path can hold; it has an empty component (a trailing or doubled slash), a `.` or `..`
// component, or a component that starts or ends with a space or ends with a dot; it uses `^` outside a class; or
// it has a class that is empty, reversed (`[z-a]`) or not closed. The error names the glob.
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
		if err := validComponent(seg); err != nil {
			return fmt.Errorf("tier glob %q can never match a plain path: %s", glob, err)
		}
		if seg == "**" {
			continue
		}
		if _, err := path.Match(strings.ToLower(seg), ""); err != nil {
			return fmt.Errorf("bad tier glob %q: %w", glob, err)
		}
	}
	return nil
}

// validComponent checks one slash-separated component of a glob.
func validComponent(seg string) error {
	switch {
	case seg == "":
		return fmt.Errorf("it has an empty component (a trailing or doubled slash)")
	case seg == "." || seg == "..":
		return fmt.Errorf("%q is not a name", seg)
	case seg[0] == ' ' || seg[len(seg)-1] == ' ':
		return fmt.Errorf("a component starts or ends with a space")
	case seg[len(seg)-1] == '.':
		return fmt.Errorf("a component ends with a dot")
	}
	for i := 0; i < len(seg); i++ {
		switch seg[i] {
		case '^':
			return fmt.Errorf("`^` is only for negating a class, as in [^a]")
		case '[':
			end, err := classEnd(seg, i)
			if err != nil {
				return err
			}
			i = end
		}
	}
	return nil
}

// classEnd returns the index of the `]` that closes the class opened at seg[open], or says why it is not a usable class.
func classEnd(seg string, open int) (int, error) {
	i := open + 1
	if i < len(seg) && seg[i] == '^' {
		i++
	}
	items := 0
	for i < len(seg) && seg[i] != ']' {
		lo := seg[i]
		i++
		if i+1 < len(seg) && seg[i] == '-' && seg[i+1] != ']' {
			hi := seg[i+1]
			if hi < lo {
				return 0, fmt.Errorf("the range %c-%c is reversed", lo, hi)
			}
			i += 2
		}
		items++
	}
	switch {
	case i >= len(seg):
		return 0, fmt.Errorf("a [ class is not closed")
	case items == 0:
		return 0, fmt.Errorf("a [] class is empty")
	}
	return i, nil
}
