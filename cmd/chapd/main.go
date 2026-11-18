// Command chapd: the daemon (HTTP API, policy, op lifecycle), `chapd orch` for the
// orchestrator token, `chapd vault` for the secrets vault, and `chapd enroll` for
// the first passkey.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/joshua-noel/chaperone/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one invocation and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: chapd version | run [flags] | svc [flags] | orch issue|revoke|list | vault init|import|list | profile add|digest | connect google | host keygen | ledger keygen | enroll [flags]")
		return 2
	}
	switch args[0] {
	case "connect":
		return connectCmd(args[1:], stdout, stderr)
	case "enroll":
		return enrollCmd(args[1:], stdout, stderr)
	case "run":
		return runCmd(args[1:], stdout, stderr)
	case "svc":
		return svcCmd(args[1:], stdout, stderr)
	case "orch":
		return orchCmd(args[1:], stdout, stderr)
	case "vault":
		return vaultCmd(args[1:], stdout, stderr)
	case "profile":
		return profileCmd(args[1:], stdout, stderr)
	case "host":
		return hostCmd(args[1:], stdout, stderr)
	case "ledger":
		return ledgerCmd(args[1:], stdout, stderr)
	case "version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: chapd version")
			return 2
		}
		if err := version.Fprint(stdout, "chapd"); err != nil {
			fmt.Fprintf(stderr, "chapd: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "chapd: unknown command %q (known: version, run, svc, orch, vault, profile, connect, host, ledger, enroll)\n", args[0])
		return 2
	}
}
