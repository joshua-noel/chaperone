package vault

import "strings"

// isPtyPipeName reports whether name, the object name of a Windows pipe, is
// the pipe MSYS2, Cygwin or mintty uses as a pseudo-terminal, for example
// `\msys-dd50a72ab4668b33-pty0-to-master`. The same rule as go-isatty.
func isPtyPipeName(name string) bool {
	name = strings.ToLower(name)
	return (strings.HasPrefix(name, `\msys-`) || strings.HasPrefix(name, `\cygwin-`)) && strings.Contains(name, "-pty")
}
