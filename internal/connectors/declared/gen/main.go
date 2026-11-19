// Command gen rewrites the generated regions of api/manual.yaml and
// api/openapi.yaml from the connectors' declarations. Run it with
// `go generate ./internal/connectors/...`; a test in package declared fails
// when the regions are out of date.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/joshua-noel/chaperone/internal/connectors/declared"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
)

func main() {
	root := flag.String("root", ".", "the repository root")
	check := flag.Bool("check", false, "write nothing; exit 1 when a file is out of date")
	flag.Parse()
	changed, err := kit.SyncAll(*root, declared.Connectors(), !*check)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kit:", err)
		os.Exit(1)
	}
	for _, f := range changed {
		if *check {
			fmt.Fprintf(os.Stderr, "kit: %s is out of date; run `%s`\n", f, kit.Regenerate)
		} else {
			fmt.Printf("kit: wrote %s\n", f)
		}
	}
	if *check && len(changed) > 0 {
		os.Exit(1)
	}
}
