# Architecture decision records

These records explain the main design decisions behind Chaperone. Each ADR ends with an "Amendments" section that says what changed and why; the body is the current text.

| ADR | Title | Later amendments cover |
| --- | --- | --- |
| [001](001-language-runtime.md) | Language and runtime (Go) | Toolchain and dependency facts; separate agent account; phone passkey; hand-written MCP server |
| [002](002-github-identity.md) | GitHub identity and `pr.merge` | Separate agent account; risk-tiered review; orchestrator as a caller; local CI result; issue and read ops |
| [003](003-vault.md) | Vault | Separate agent account; one-device approval; critical class for secrets; Linear intake credential; Sentry auth token |
| [004](004-approvals.md) | Approvals: Hello or phone passkey, push as wake-up | One-device approval; phone approval; no daily approval limit; critical class; card wording and local time |
| [005](005-run-token.md) | Run token and revocation | Separate agent account; orchestrator token; tagged spec release; order of revocation checks |
| [006](006-ledger.md) | Ledger | Orchestrator events; critical ops; storage layer (`internal/store`); anchors |
| [007](007-orchestrator-token.md) | The orchestrator authenticates with an orchestrator token | New; account split |
| [008](008-custom-keys.md) | Custom keys: a Chaperone token for a script or an agent | New |
| [009](009-local-mcp-front-end.md) | A local MCP front end (`chap mcp`) | New; hand-written server (ADR-001 amendment 7) |

A new third-party module needs a line in `../dependencies.allow` and an addendum to ADR-001.
