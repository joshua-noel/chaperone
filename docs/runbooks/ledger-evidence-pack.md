# Runbook: read the ledger evidence pack

The ledger is `chapd`'s record of everything that matters: every op request, approval, result, denial, stop, token grant and revoke, written in the same transaction as the change, chained by SHA-256 so an edit shows (ADR-006). The **evidence pack** is what you hand to a reviewer or keep after an incident: the daily JSONL segments, the output of `chap ledger verify`, and the newest signed anchor. This page says how to read it and what it can and cannot prove.

**What runs, and when.** The chain, `chap ledger verify` (with `--against-export` and `--anchor`) and the console **Ledger** page are on `main`. The JSONL export schedule and the signed anchors run only when `chapd` is started with `-ledger-key-secret <vault secret id>` (the Ed25519 seed made by `chapd ledger keygen` and stored with `chapd vault import`), together with `-vault-dir`, `-export-dir` and `-ntfy-topic-secret`; without it nothing writes the export and no anchor exists, and `chap ledger verify --anchor` reports `ANCHOR_NONE`. Once on, `chapd` exports new events every 10 minutes, anchors at start, every 24 hours and after every finished deploy, and raises the `ledger-export-stale` or `ledger-anchor-stale` alert after 26 hours without one. Backing up the export folder is not done by Chaperone: copy it with your own backup job. Run logs: [`logs/orchestrator-token.log`](logs/orchestrator-token.log) shows `chap ledger verify` reporting the head before and after real events, and [`logs/vault-recovery.log`](logs/vault-recovery.log) shows the same head before and after a vault recovery. The export and anchor behaviour itself is covered by the tests in `internal/ledger/anchor_test.go` and `cmd/chapd/ledger_anchor_test.go`, not by a run on a real server yet.

## 1. Is the chain intact?

From a normal window, as the orchestrator (the command is orchestrator-only):

```powershell
& 'C:\Program Files\Chaperone\chap.exe' ledger verify
```

```
ledger ok: chain chaperone.host1, head seq 3, hash sha256:42081d0e...
```

`--json` gives `ok`, `chain`, `head_seq`, `head_hash`, `checked_export` and `problems`. Exit code 5 means not ok. Write down the **head seq and hash**: they are the pack's fingerprint. The console does the same at **Ledger, Check integrity**.

What the check covers: the strict JSON and canonical form of each stored event, the indexed columns against the event, no gap in `seq`, the hash chain (`prev_hash`, `hash`, `trace_id`), the stored head against the last event (a cut-off tail), and each `ledger.anchor` against the event it names. A failure raises the stop code `LEDGER_CHAIN_BROKEN`, and `chapd` refuses every append until restart.

| Problem code | Means |
| --- | --- |
| `BAD_EVENT`, `NOT_CANONICAL`, `COLUMN_MISMATCH` | A stored event was altered or damaged |
| `SEQ_GAP`, `CHAIN` | An event is missing, reordered or its hash does not follow |
| `HEAD_MISSING`, `HEAD_MISMATCH` | Events exist without a head, or the tail was cut off |
| `ANCHOR_MISMATCH` | A `ledger.anchor` names a head the chain does not have |
| `EXPORT_DIFFERS`, `EXPORT_MISSING`, `EXPORT_AHEAD`, `EXPORT_GAP`, `EXPORT_BAD_LINE`, `EXPORT_STRAY` | (`--against-export`) the JSONL and SQLite disagree |
| `EXPORT_TORN` | The last export line has no newline (a crash mid-export); the next export repairs it |

## 2. Find the events

**Console, Ledger** (`http://localhost:55398/ledger`): search by run id, request id, op, event name or time. It shows metadata and never a secret or token.

**The JSONL segments (anchors on):** `D:\Chaperone\ledger\<chain>\<yyyy-mm-dd>.jsonl` (UTC day), one canonical event per line, readable by you (that folder is the only ledger path your account can read). A line is one event:

```powershell
Get-Content D:\Chaperone\ledger\chaperone.host1\2026-10-24.jsonl | ForEach-Object { $e = $_ | ConvertFrom-Json; '{0} {1} {2}' -f $e.seq, $e.event_name, $e.body }
```

Fields to know: `seq` and `hash`/`prev_hash` (the chain), `time_unix_nano`, `event_name` (`op.request`, `op.approve`, `op.result`, `denial`, `grant`, `run.start`, `run.end`, `token.revoke`, `stop.*`, `ledger.anchor`), `run_id` (absent for the orchestrator), `attributes` (the closed set per event name: `factory.op`, `factory.op_hash`, `factory.requester.kind`, ...) and `body` (one plain sentence; never a secret).

How to follow one thing:

| Question | Look for |
| --- | --- |
| What happened to one request? | The `factory.request_id` (`q-...`): `op.request`, then `op.approve` if it needed a card, then `op.result` with `outcome` |
| What did the orchestrator do while a token was live? | `factory.requester.kind = orchestrator`; the window is between the `orchestrator.issue` and `orchestrator.revoke` events (see [`orchestrator-token.md`](orchestrator-token.md)) |
| What did one run do? | Its `run_id`: `run.start`, `grant`, its ops, `run.end` or `token.revoke` |
| Who approved? | `op.approve`: approver, channel, the op hash it bound to |
| What was refused and why? | `denial` events: `cause_code`, the surface and target |

## 3. Does the export agree with the database?

```powershell
& 'C:\Program Files\Chaperone\chap.exe' ledger verify --against-export
```

compares every JSONL line with its SQLite row byte for byte, and the export's reach with its recorded mark. An edit in only one of the two is found. **Someone who controls the database file and the export folder can rewrite both consistently**; only an anchor kept elsewhere catches that.

## 4. Anchors: the part that makes it evidence

`chapd` signs the head (`{chain, head_seq, head_hash}`) with an Ed25519 ledger key held in the vault, at start, daily and after every finished deploy, and writes it to two places it cannot later edit: a signed line in `<export-dir>\anchors\<chain>.jsonl` (inside the nightly backup set) and an ntfy push to the phone. To check a chain against what you kept:

```powershell
& $chap ledger verify --anchor [--anchor-file <restored copy>] [--anchor-pub <base64url public key>] [--against-export]
```

It adds "compared with N signed anchor record(s)" and "newest anchor: head seq S, hash H" (the phone shows the same two values). A rewritten history shows `ANCHOR_REWRITTEN`, a cut-off tail `ANCHOR_CUT`, no records `ANCHOR_NONE`. Compare the two values on the phone with the ones on the screen: if they match, the chain up to that head is what `chapd` wrote.

## 5. Making a pack

1. `chap ledger verify --json` (add `--against-export --anchor` when the anchors are on); save the output.
2. Copy the JSONL segments for the period (and the `anchors` file) to a folder; do not edit them.
3. Write the head seq/hash, the policy version(s) in the events, the comments on the pull requests of any merge that was done by hand in the period: those merges are **not** in the ledger.
4. Keep the phone's anchor message for the end of the period.

## What the ledger cannot tell you

- Merges done by hand, and anything an agent did that did not go through `chapd`. Compare against GitHub's own log.
- Whether the server's clock was right (`chap doctor` checks it; events carry the time `chapd` saw).
- That the host was not compromised: a writer with the account's keys can write plausible events. The off-server anchors are the independent witness.
