package kit

import "strings"

// CLIPath is the command's words: "intake.list" is "intake list".
func (o Op) CLIPath() string { return strings.ReplaceAll(o.Name, ".", " ") }

// CLISummary is the line `chap help` shows for the command.
func (o Op) CLISummary() string {
	if o.CLI.Summary != "" {
		return o.CLI.Summary
	}
	s := strings.TrimSuffix(o.Summary, ".")
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// CLIUsage is the usage line of the generated command: the path, the
// positional ref, the params in declaration order, then the ref flag or
// --repo, then --dry-run. A param with no flag (from the ref, or a const) is
// left out.
//
//	chap intake move <SHOP-12> --state <name>
//	chap intake list [--refresh] [--closed] [--team <key>]
//	chap pr files <n> [--page <p>] [--expected-head <sha>] [--repo owner/name] [--dry-run]
func (o Op) CLIUsage() string {
	parts := []string{"chap " + o.CLIPath()}
	if o.Target.Positional != "" {
		parts = append(parts, "<"+o.Target.Positional+">")
	}
	for _, p := range o.Params {
		if !p.hasFlag() {
			continue
		}
		f := "--" + p.FlagName()
		switch p.Kind {
		case Bool:
			parts = append(parts, "["+f+"]")
		case String, Int:
			s := f + " <" + p.Placeholder + ">"
			if !p.Required {
				s = "[" + s + "]"
			}
			parts = append(parts, s)
		case Text:
			parts = append(parts, "[--body <b> | --body-file <f>]")
		}
	}
	if o.Target.Flag != "" {
		parts = append(parts, "[--"+o.Target.Flag+" <"+o.Target.Placeholder+">]")
	}
	if o.Target.Repo {
		parts = append(parts, "[--repo owner/name]")
	}
	if o.CLI.DryRun != "" {
		parts = append(parts, "[--dry-run]")
	}
	return strings.Join(parts, " ")
}
