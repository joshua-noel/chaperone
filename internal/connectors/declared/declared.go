// Package declared lists every connector that has declared its operations with
// the kit. It is the one list the generator, the `chap` command table and the
// drift tests read, so adding a connector to the kit is one line here.
//
// Connectors that are not listed (GitHub and Google, so far) still keep their
// facts in the places the kit replaces; see docs/connectors.md.
package declared

import (
	"github.com/joshua-noel/chaperone/internal/connectors/kit"
	"github.com/joshua-noel/chaperone/internal/connectors/linear/linearspec"
)

//go:generate go run ./gen -root ../../..

// Connectors returns the declared connectors.
func Connectors() []kit.Connector {
	return []kit.Connector{linearspec.Connector}
}

// Ops returns every declared operation, connector by connector.
func Ops() []kit.Op {
	var all []kit.Op
	for _, c := range Connectors() {
		all = append(all, c.Ops...)
	}
	return all
}
