package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/joshua-noel/chaperone/internal/runtoken"
)

const profileHelp = `usage: chapd profile add -file <profile.json> [-db <state.db> | -profiles-dir <dir>]
       chapd profile digest -file <profile.json>

add checks a factory-spec generic profile (schema, a branch_prefix) and copies it
to <digest hex>.json in the profile folder chapd reads (-profiles-dir; default:
"profiles" next to the database). It prints the digest a runner.* run token
must carry in profile.digest. digest prints it and writes nothing.
`

// profileCmd is `chapd profile`: admit a generic profile to the folder behind
// -profiles-dir (LF-3). Run it as an account that may write the folder.
func profileCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "add" && args[0] != "digest") {
		fmt.Fprint(stderr, profileHelp)
		return 2
	}
	fs := flag.NewFlagSet("chapd profile "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "profile JSON file")
	dir := fs.String("profiles-dir", "", "profile folder (default: profiles next to -db)")
	db := fs.String("db", defaultDB, "path of state.db, to find the default profile folder")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *file == "" || fs.NArg() != 0 {
		fmt.Fprint(stderr, profileHelp)
		return 2
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	if args[0] == "digest" {
		digest, _, err := runtoken.ParseProfile(data)
		if err != nil {
			fmt.Fprintf(stderr, "chapd: %s: %v\n", *file, err)
			return 1
		}
		fmt.Fprintln(stdout, digest)
		return 0
	}
	if *dir == "" {
		*dir = filepath.Join(filepath.Dir(*db), "profiles")
	}
	digest, err := runtoken.AdmitProfile(*dir, data)
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %s: %v\n", *file, err)
		return 1
	}
	fmt.Fprintf(stdout, "admitted %s in %s\n", digest, *dir)
	return 0
}
