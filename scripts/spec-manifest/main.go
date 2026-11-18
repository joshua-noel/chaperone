// Command spec-manifest writes internal/spec/specdata/MANIFEST: the SHA-256 of
// every file of the vendored spec contract (schemas, stop table, golden vectors
// and schema examples). internal/spec's tests compare each file with the
// MANIFEST, so an unplanned edit to the contract is found by `go test`.
//
// The contract lives in this repository and is edited here. After an edit,
// bring the derived hashes in the examples and vectors up to date (op_hash,
// challenge_sha256, ledger hash chains, profile digests: the tests in
// internal/spec say which are wrong), then re-seal:
//
//	go run ./scripts/spec-manifest          # rewrite MANIFEST
//	go run ./scripts/spec-manifest -check   # fail if MANIFEST is out of date, write nothing
//
// Run it from the repository root, or pass -root.
package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

const dataDir = "internal/spec/specdata"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("spec-manifest", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", ".", "repository root")
	check := fl.Bool("check", false, "compare MANIFEST with the files and write nothing")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if err := seal(*root, *check, stdout); err != nil {
		fmt.Fprintf(stderr, "spec-manifest: %v\n", err)
		return 1
	}
	return 0
}

func seal(root string, check bool, stdout io.Writer) error {
	dir := filepath.Join(root, filepath.FromSlash(dataDir))
	var names []string
	sums := map[string][32]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "MANIFEST" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		names = append(names, rel)
		sums[rel] = sha256.Sum256(b)
		return nil
	})
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("%s holds no files", dataDir)
	}
	sort.Strings(names)
	var want bytes.Buffer
	for _, n := range names {
		fmt.Fprintf(&want, "%x  %s\n", sums[n], n)
	}
	path := filepath.Join(dir, "MANIFEST")
	have, _ := os.ReadFile(path)
	if check {
		if !bytes.Equal(have, want.Bytes()) {
			return fmt.Errorf("%s/MANIFEST is out of date: run `go run ./scripts/spec-manifest`", dataDir)
		}
		fmt.Fprintf(stdout, "spec-manifest: MANIFEST matches %d files\n", len(names))
		return nil
	}
	if err := os.WriteFile(path, want.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "spec-manifest: wrote MANIFEST for %d files\n", len(names))
	return nil
}
