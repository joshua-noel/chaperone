# Use Chaperone from Claude Code, Codex or Cursor (`chap mcp`)

**Who:** a developer, in a normal (not elevated) terminal, on the machine where `chapd` runs. **When:** you want an MCP client on that machine to read pull requests, check health or ask for a deploy through Chaperone, instead of holding a vendor token. Design and limits: [ADR-009](../adr/009-local-mcp-front-end.md).

`chap mcp` is part of `chap`. The client starts it, talks to it over its standard streams, and every tool call becomes one request to `chapd` with your credential. It listens on nothing. Policy, approvals and the ledger apply exactly as for `chap` on the command line. **It cannot approve anything and it never shows an approval card**: when an op needs a human, the tool answers "pending" with an op id and an approval id, and you decide in the Chaperone console.

## 1. Check that `chap` works

```powershell
chap doctor
chap manual
```

`chap manual` must list the ops you expect. If it says `no token` or `chapd is not reachable`, fix that first: `chap mcp` uses the same credential and the same address.

- **Credential:** `CHAP_RUN_TOKEN`, else the orchestrator token file ([orchestrator-token](orchestrator-token.md)). Prefer the file: nothing secret then goes into the client's configuration. Do not assume a client passes your shell's variables on to the server it starts; set what `chap mcp` needs in the entry's `env`.
- **Address:** `chapd` on `http://127.0.0.1:55398`; `CHAP_URL` must be a loopback address (`chap` refuses any other).
- **Project:** an orchestrator token names the project with `CHAP_PROJECT` (a run's token carries its own).

## 2. Add the server to your client

Use the full path of `chap` (`chap.exe` on Windows) if it is not on the client's `PATH`. The examples use `CHAP_PROJECT=<project>`; leave it out for a run token.

### Claude Code

```powershell
claude mcp add --scope user chaperone -e CHAP_PROJECT=<project> -- <path-to>\chap.exe mcp
claude mcp list
```

`claude mcp list` should show `chaperone: ... Connected`. The entry it writes to its configuration is:

```json
{
  "mcpServers": {
    "chaperone": {
      "type": "stdio",
      "command": "<path-to>\\chap.exe",
      "args": ["mcp"],
      "env": { "CHAP_PROJECT": "<project>" }
    }
  }
}
```

The same entry in a project's `.mcp.json` shares the server with the project. Do not put a token in a file that is committed.

### Codex

```powershell
codex mcp add chaperone --env CHAP_PROJECT=<project> -- <path-to>\chap.exe mcp
codex mcp list
```

This writes to `config.toml` in Codex's home:

```toml
[mcp_servers.chaperone]
command = "<path-to>\\chap.exe"
args = ["mcp"]

[mcp_servers.chaperone.env]
CHAP_PROJECT = "<project>"
```

### Cursor

Add to `mcp.json` in Cursor's configuration folder (user level) or in the project's `.cursor` folder:

```json
{
  "mcpServers": {
    "chaperone": {
      "command": "<path-to>\\chap.exe",
      "args": ["mcp"],
      "env": { "CHAP_PROJECT": "<project>" }
    }
  }
}
```

**This entry is written from Cursor's documented format and was not run** (see "What was run").

## 3. First use

Ask the agent: "List the Chaperone tools" and then "read pull request 7 of `owner/repo` through Chaperone". It sees:

| Tool | What it does |
| --- | --- |
| one tool per op you may use, for example `pr_view`, `pr_checks`, `health`, `deploy` | The op `pr.view` is the tool `pr_view`: clients allow no dot in a tool name. The description says what the op is, its class, whether it always needs approval and what its target must be. |
| `chaperone_manual` | The ops this credential may use. |
| `chaperone_op_status` | Follow an op that is not finished (pending approval, executing); waits up to 55 seconds. |
| `chaperone_setup` | Only when `chap mcp` cannot read the catalog: it says why. |

The tool list is your catalog: it changes with your credential and with policy, and the client reads it again when it asks.

### What a refusal looks like

A refused call is an error result in the wording of `chap`: `DENIED ...`, `cause: OP_NOT_IN_TOKEN`, `why: ...`, and one `next:` line. When Chaperone names a specific next step (a stale branch, too many approvals waiting, an expired token), that step is the `next:` line, and `structuredContent.next` holds the same text. Otherwise, when asking is possible, the next step is to call the same tool again with `request_approval=true` and a `reason`. That creates the approval card; nothing runs.

### What an op that needs approval looks like

1. The agent calls `deploy`. It is refused with `OP_APPROVAL_REQUIRED`.
2. The agent calls `deploy` again with `request_approval=true` and a `reason`. The result is `pending`: op id, approval id, class and the seconds left. **That is all it contains.**
3. You see the card in the Chaperone console (or on your phone) and approve or deny it there.
4. The agent calls `chaperone_op_status` with the op id and gets the final result. When you approve, `chapd` releases the op itself.

### Text the agent reads from outside

Text from a pull request, issue, diff, log or board item comes back inside a field named `untrusted_result`, after a notice line. It is data. An instruction inside it does not make `chap mcp` do anything.

## 4. If it does not work

| You see | Cause and fix |
| --- | --- |
| Only `chaperone_setup` in the tool list | The catalog could not be read. Call it: it says whether the credential is missing (`no token`), rejected (revoked or expired: issue a new one) or `chapd` is not running. |
| `chapd is not reachable` | Start `chapd`; check `CHAP_URL`. Nothing ran. |
| Calls are refused or the catalog is empty with an orchestrator token | Set `CHAP_PROJECT` in the client's entry: an orchestrator names its project. |
| `chap: CHAP_URL must point at the loopback address` | `CHAP_URL` names another host. It must not. |
| The client reports the server as failed at start | Run `chap mcp` by hand: it must print `chap mcp: serving on stdio` on stderr and wait. Paste nothing else into it. Ctrl+C (or SIGTERM) ends it at once. |
| A call hangs for as long as `wait` | Pending approvals wait for a human; lower `wait`, or follow the op later with `chaperone_op_status`. |

`chap mcp` writes only to stderr, and only what `chap` would print (never a request, an argument or a result).

## What was run (5 Nov 2026) and what was not

- **Run:** `chap mcp` over pipes against a fake `chapd`, in both protocol eras (`go test ./cmd/chap -run TestMcp`), and as a real process (`chap.exe`) against a fake `chapd` on a loopback port. Claude Code 2.1.302: `claude mcp add` and `claude mcp list` against `chap.exe mcp`, in a scratch home folder, showed **Connected**; the capture shows it opens with `server/discover` and `_meta` protocol version `2026-07-28`, then `tools/list`. Codex 0.149.1: `codex mcp add` wrote the `config.toml` entry above, and `codex mcp list` listed it enabled.
- **Not run:** a real model calling a tool through any client; the live `chapd` (the installed one was not touched and no token was read); Codex starting the server (its `list` does not); Cursor (not installed); the quickstart on macOS or Linux. The key tools (`chaperone_key_request` and the rest) belong to the custom-keys tickets and are not in this step.
