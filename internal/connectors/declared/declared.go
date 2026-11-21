// Package declared lists every connector that has declared its operations with
// the kit. It is the one list the generator, the `chap` command table and the
// drift tests read, so adding a connector to the kit is one line here.
//
// Connectors that are not listed (Google, so far) still keep their facts in the
// places the kit replaces; see docs/connectors.md.
package declared

import (
	"github.com/joshua-noel/chaperone/internal/connectors/github/githubspec"
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
	"github.com/joshua-noel/chaperone/internal/connectors/sentry/sentryspec"
)

//go:generate go run ./gen -root ../../..

// Connectors returns the declared connectors. The regions of the catalog and
// of the params schemas sit where the hand-written entries they replaced were.
func Connectors() []kit.Connector {
	return []kit.Connector{githubspec.Connector, githubspec.CI, linearspec.Connector, sentryspec.Connector}
}

// Ops returns every declared operation, connector by connector.
func Ops() []kit.Op {
	var all []kit.Op
	for _, c := range Connectors() {
		all = append(all, c.Ops...)
	}
	return all
}
