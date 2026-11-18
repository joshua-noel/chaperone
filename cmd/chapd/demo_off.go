//go:build !demo

package main

import "flag"

// demoFlags adds the dev-only flags of the -tags demo build to `chapd run`. The
// shipped build has none.
func demoFlags(*flag.FlagSet, *Config) {}
