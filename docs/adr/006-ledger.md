# ADR-006: Ledger storage: SQLite with a hash chain, a JSONL export, anchors, OTel export

- **Status:** **Accepted** (operator sign-off). Amended 2026-10-24 for the approval-limit rule, orchestrator events, the tagged spec release and critical ops, and for what the first build produced: see "Amendments" at the end.
- **Contract:** factory-spec v0 `ledger-event.schema.json`. Each writer (the runner, Chaperone) keeps **its own chain**; an event has `chain`, `seq` (0-based, +1 per event), `prev_hash`, `hash` = SHA-256 over the RFC 8785 (JCS) form of the event without `hash`, written `sha256:<hex>`; first event uses the all-zero digest; the shape follows the OTel log-record model (`time_unix_nano`, `trace_id`, `span_id`, `severity_*`, `event_name`, `resource`, `attributes`, `body`) and **attribute sets are closed per `event_name`**; `trace_id` = first 16 bytes of SHA-256(`run_id`) in hex; a `ledger.anchor` event records a checkpoint "copied somewhere the ledger writer cannot rewrite" with `kind` one of `git-tag`, `transparency-log`, `offline-copy`. The spec's reference implementation is `src/hashing.mjs` (`jcs`, `eventHash`, `verifyChain`).
- Chaperone's events: `grant`, `op.request`, `op.approve`, `op.result`, `denial`, `stop.*`, `report.*`, `ledger.anchor` (spec names).

## Context

- Chaperone already needs a database for run state, approvals, the revoked-token set and the op state machine (ADRs 004, 005). The ledger entries are the audit trail of exactly those transitions.
- SQLite WAL: writers sync the WAL on every commit when `PRAGMA synchronous=FULL`, and skip that sync when `NORMAL`, at the price of durability after power loss (<https://www.sqlite.org/wal.html>). A ledger must survive a power cut (the 21 Oct host crash is why we care).
- OTel's Logs Data Model is **Stable** and has an `EventName` field (<https://opentelemetry.io/docs/specs/otel/logs/data-model/>). I could not read the Go SDK's logs-signal maturity page `[INFERENCE: check at implementation; fallback below]`.
- JCS is RFC 8785 (<https://www.rfc-editor.org/rfc/rfc8785.html>). Two implementations (spec's JS, Chaperone's Go) must agree byte for byte, so conformance is by golden vectors (ADR-001).

## Decision

### Storage

**One SQLite database `D:\Chaperone\data\state.db` (`modernc.org/sqlite`, WAL, `synchronous=FULL`, `foreign_keys=ON`), owned by `svc-chaperone`. The ledger is a table in it, `ledger_events`, with the exact spec event as JSON plus indexed copies of `run_id`, `event_name`, `time_unix_nano`, `seq`.**

- **Same transaction as the state change.** An op state transition and its ledger event commit together or not at all (`BEGIN IMMEDIATE`). No high-impact op executes unless its `op.request` / `op.approve` events committed: **ledger failure fails closed** (disk full, locked, chain error means the op is refused with an alert). A preflight free-space check on `D:` warns early.
- **Single writer.** One goroutine assigns `seq`, reads the previous hash, computes `hash`, inserts. Other goroutines send events through it. `UNIQUE(chain, seq)` backs it up.
- **Append-only guard.** `BEFORE UPDATE` and `BEFORE DELETE` triggers on `ledger_events` call `RAISE(ABORT)`. This stops bugs, not an attacker with file access; the chain and anchors cover that.
- **Closed attributes and redaction** at the write boundary: the event is validated against the spec schema (unknown attributes rejected) and passed through `redact` (ADR-003). `body` is never a secret.
- **Chain id:** `chaperone.<instance>` (e.g. `chaperone.host1`), one chain per `chapd` instance. Chain breaks on restore are explicit `ledger.anchor`-referenced new chains, never silent re-seq.

### Verification and export

- `chap ledger verify` (and a console button) walks the chain with the same algorithm as the spec's `verifyChain` (seq gaps, `prev_hash`, `hash`, `trace_id` derivation, no mixed chains). A failure raises stop code `LEDGER_CHAIN_BROKEN`.
- **Daily JSONL segments**, `D:\Chaperone\ledger\<chain>\<yyyy-mm-dd>.jsonl`, one spec event per line, `fsync` per batch, written by `chapd` and readable by the operator account (this is the only ledger path the operator account can read). `chap ledger verify --against-export` checks that SQLite and the JSONL files agree, so an edit in only one place is found. These files are the **evidence pack** format and are included in the nightly backup set.

### Anchors (what makes it tamper-evident, not only tamper-resistant)

A hash chain stored with the key that writes it proves integrity against partial edits, **not** against someone who can rewrite the whole chain. The spec's answer is an anchor.

- **Phase 1:** `kind: offline-copy`. Every 24 hours, and after every approved `deploy`, `chapd` writes `ledger.anchor` (head hash, head seq) and copies `{chain, head_seq, head_hash, signed_by_ledger_key}` to two places `chapd` cannot later edit: (a) an ntfy message to the operator's phone (hash and sequence only; it is on a device outside the server), (b) the nightly backup set that leaves the server for the Drive copy (a backup job on the host already does that for other dumps `[INFERENCE: the Chaperone export would be added to its list]`). The anchor is signed with a dedicated Ed25519 ledger key kept in the vault.
- **P2:** `kind: git-tag`: push an annotated tag naming the head hash to a dedicated private repo using a separate App installation limited to that repo (GitHub's server-side push time is the witness). Not tamper-proof against a compromised `chapd` (it can hold the key), but it moves the evidence to a place with an independent clock.
- **P3 (optional):** `kind: transparency-log` (public log of hashes only).

### OpenTelemetry export

- **Export only, never the source of truth.** The console and `chap` read SQLite. An optional exporter tails committed rows by a persisted cursor (outbox pattern) and sends them as OTLP log records over OTLP/HTTP to a collector; at-least-once, idempotent by `(chain, seq)`.
- Because the spec event is already log-record-shaped (and uses OTLP/JSON-style `unix_nano` strings), no translation layer is needed. **Off by default** until a collector exists (the runner phase). Fallback if the Go OTel logs SDK is not mature enough: write OTLP/JSON files for a collector `filelog` receiver.
- Resource attributes: `service.name=chaperone`, `service.instance.id`, `factory.chain`. Event attributes keep the spec's `factory.*` names.

## Alternatives

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| **SQLite table + hash chain + JSONL export + anchors** | One store for state and audit, atomic with transitions; indexed queries for the console (by run, op, time); same hash rule as the spec; the JSONL export gives a plain-text evidence format. | A single file can be rewritten by whoever owns the account; so anchors are not optional. | **Chosen** |
| Append-only JSONL file as the primary store | Trivial, human-readable, and tamper evidence is the same chain. | No atomicity with op state (two sources of truth); the console needs an index anyway, so you end up with SQLite beside it; harder to enforce append-only on Windows files. | Kept as the *export*, not the primary |
| Transparency-log service (Trillian/Tessera, Rekor) as the primary | Strong tamper evidence. | Another service, public or heavy; far more than one server needs. | Optional anchor (P3), not primary |
| A purpose-built immutable DB (immudb or similar) | Built-in verification. | Another daemon in the trusted path; not evaluated in depth `[INFERENCE]`. | Rejected for Phase 1 |
| Postgres | Rich. | A second service just for the ledger; house rule keeps agents off Docker and DBs on the server. | Rejected |
| OTel pipeline as the system of record | Standard. | Lossy and best-effort by design; an outage loses audit events. | Rejected (export only) |

## Verify

- Golden vectors: `eventHash`, `prev_hash` chaining and `trace_id` match the spec's JS outputs.
- Tamper tests: change a payload byte, drop a row (needs a trigger bypass in the test), reorder, truncate the tail, edit only the JSONL, edit only SQLite, each detected with a precise message; crash test (kill `chapd` mid-write, restart, chain intact, no gap); power-loss behaviour documented by `synchronous=FULL` test; triggers refuse UPDATE/DELETE.
- Ledger failure fails closed: with a read-only DB, `op.request` is refused.
- Anchor event written, signed, delivered to both places, and verification detects a rewrite of everything before the anchor.

## Amendments (2026-10-24, first build)

**Amendment 1. `internal/store` is the storage layer this ADR assumes.** `store.Open` applies `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON` and a 5 s `busy_timeout` to every pooled connection and **fails closed** if SQLite reports any other value. `DB.Immediate` runs a function inside `BEGIN IMMEDIATE` (commit on nil, rollback on error, panic or cancelled context); the state change and its ledger event go through it together. **Write gate (2026-10-24):** the writers of one process first queue on a one-slot gate, first come first served, so they never compete in SQLite's busy handler (it polls with no queue and let one writer lose every poll for the whole 5 s, which failed ledger appends with `SQLITE_BUSY` under load). A writer waits for the gate until its context ends, or at most 30 s (`ErrWriteGate`, which the ledger maps to `ErrUnavailable`, so it fails closed). A write started with the context of a running `Immediate` function, or `Ledger.Append` called inside one, is refused at once with `ErrNestedWrite` (use the transaction's `Tx` and `AppendTx`). Other processes that open `state.db` (`chapd vault`, `orch`, `enroll`, `connect google`) are outside the gate and still wait on SQLite's 5 s busy handler only. Every production write goes through `Immediate`; none uses the read pool. The ledger's own table, triggers and appender are in `internal/ledger` (Amendment 6).

**Amendment 2. Migrations are forward-only.** `DB.Migrate` applies `internal/store/migrations/NNNN_name.sql` in one `BEGIN IMMEDIATE` transaction, records each with a SHA-256 of name and SQL, and refuses: a list that is not strictly ascending, a pending migration older than one already applied, an applied migration whose name or SQL changed, and a database that holds a migration the binary does not know (no downgrade). `ledger_events` and its append-only triggers arrive as a new numbered file; nothing may edit an applied one.

**Amendment 3. Orchestrator events.** Events caused by the orchestrator (the lead agent that coordinates other agents) carry `factory.requester.kind: orchestrator` and no `run_id` (spec v0.1.0). The spec paragraph that defines `trace_id` says an event with no run derives it from its `chain` id instead of a run id; Chaperone ports that rule from `src/hashing.mjs`. Token issue and revoke for the orchestrator are operator actions; ADR-007 says how they are recorded.

**Amendment 4. Critical ops.** `op.request`, `op.approve` and `op.result` for `secrets.*`, `repo.settings` and `host.scripts.refresh` are ordinary events; "logged loudly" is an alert on top of them (ADR-004), not a different ledger shape.

**Amendment 5. Reports never set approval limits.** No ledger field or report feeds an approval limit. Approvals per day, time-to-decision and denial rate are read from the ledger for reporting only.

## Amendments (2026-10-24, ledger)

**Amendment 6. What `internal/ledger` built.**

- **Tables** (migration `0003_ledger_events`): `ledger_events` holds each event as canonical (RFC 8785) JSON in `event`, plus indexed copies `chain`, `seq`, `hash`, `prev_hash`, `time_unix_nano`, `event_name`, `run_id`; `PRIMARY KEY (chain, seq)`; `BEFORE UPDATE` and `BEFORE DELETE` abort. `ledger_chains` keeps per chain the committed head (`head_seq`, `head_hash`) and the export mark (`exported_seq`, `exported_hash`). Triggers let both marks only move forward, and only to an event that exists, so a cut-off tail shows as "head says N, last event is M" even though a chain alone cannot show it.
- **Single writer = SQLite's write lock.** Every append runs in `BEGIN IMMEDIATE`, reads the head inside the transaction and writes event and head together. `AppendTx(ctx, tx, Draft)` runs in the caller's `store.DB.Immediate` transaction, so an op's state and its event commit together. `Append(ctx, Draft)` queues to one writer goroutine that commits queued events in groups (one fsync per group). The head is never cached in memory, so a rolled-back transaction leaves no gap.
- **Fail closed.** Every error means "not recorded": `ErrRejected` (spec schema or size), `ErrUnavailable` (database cannot write: disk full, read-only, locked), `ErrChainBroken` (stop code `LEDGER_CHAIN_BROKEN`: head and last event disagree). After `ErrChainBroken` the ledger refuses every append until restart, and `Open` refuses to start on a damaged chain. `Preflight` is a write probe that leaves no trace.
- **Redaction** runs on every string and every object key of a draft before it is validated and hashed, so even a validator error quotes masked text only. `Receipt.Redactions` lists the rules that fired; the caller raises `REDACTION_BLOCKED`.
- **Export**: `<ExportDir>/<chain>/<yyyy-mm-dd>.jsonl` (UTC day; an event whose clock went backwards follows its predecessor's segment), one canonical event per line, `fsync` per write, directory `fsync` on a new segment (a no-op on Windows), and only then the export mark. A torn last line is cut off and rewritten at the next export. Export refuses (`ErrExportMismatch`) when the newest line differs from SQLite or the export is shorter than the mark.
- **`ledger.Verify`** (the library behind `chap ledger verify [--against-export]`): strict I-JSON and canonical form of each stored event, indexed copies against the JSON, no `seq` gap, `spec.VerifyChain`, head against last event, anchors against the events they name, and with `AgainstExport` every JSONL line against its SQLite row byte for byte plus the export's reach against its mark. Findings are `Problem{Code, Seq, Msg}`; `Report.Err()` wraps `ErrVerifyFailed`.
- **What it cannot see.** Whoever controls the database file and the export directory can rewrite both consistently. Anchors delivered off the server (Amendment 7) are the only answer; `Ledger.Anchor` writes the `ledger.anchor` event (head hash and seq) and `Verify` checks each anchor names a real event with that hash.
- **Not done here**: the free-space preflight on `D:` (ADR text above) and OTel export are not part of this amendment.

## Amendments (2026-10-24, anchors)

**Amendment 7. What `internal/ledger/anchor*` built.**

- **Record.** For each `ledger.anchor` event of kind `offline-copy`, chapd makes a signed record `{v, chain, head_seq, head_hash, anchor_seq, anchor_hash, time_unix_nano, key_id, sig}` (one canonical RFC 8785 line). `sig` is Ed25519 by the ledger key over `"chaperone.ledger-anchor.v1\x00"` and the canonical record without `sig`. `head_*` is the event the anchor covers; `anchor_*` is the anchor event itself, so rewriting the anchor event is also caught. The event's closed attribute set has no signature, so the signature lives only in the off-box copies.
- **Two places chapd cannot edit afterwards.** (a) The record is appended (fsync) to `<export-dir>/anchors/<chain>.jsonl`, inside the export root that the nightly backup set holds (the backup job is changed separately, outside Chaperone). (b) The record is pushed to the operator's phone by ntfy through `internal/notify` (`Anchor`, `BuildAnchor`, `Ntfy.NotifyAnchor`): chain, head seq, head hash, key id and signature, built from a fixed template with every field checked against a pattern. The topic stays in the request body like every other push.
- **Schedule** (`ledger.Anchors`, one pass a minute): an anchor at start, then every 24 hours, and at once after any deploy whose `op.result` is newer than the last anchor (found from the ledger and the `ops` table, so a deploy that finished while chapd was down is still anchored). The JSONL export runs every 10 minutes and right after an anchor. A failed push is retried every 10 minutes; after an outage only the newest anchor is pushed (it covers the older ones). Delivery state is in the records file and `store_meta`, so a restart repeats nothing and an anchor event without a record gets one.
- **Alerts** (through `alerts.ps1`, keys `ledger-export-stale`, `ledger-anchor-stale`, `ledger-export-broken`): no completed export for 26 hours; no anchor in both the records file and on the phone for 26 hours; an export that disagrees with SQLite (raised at once). The daily anchor is itself an event, so the export folder changes at least once a day while chapd runs: a check outside chapd (a check outside chapd) can alert on a segment or anchors file older than 26 hours, which also catches chapd being down.
- **Verification.** `chap ledger verify --anchor [--anchor-file F]... [--anchor-pub K]...` (`POST /v0/ledger/verify` with `anchor`, `anchor_records`, `anchor_keys`) compares the chain with the records chapd keeps and with any the caller supplies: a copy restored from the Drive backup is the check that chapd cannot have influenced. Findings: `ANCHOR_REWRITTEN` (the chain has other hashes than a record: every event before the anchor may have been rewritten, however consistent the new chain is with itself), `ANCHOR_CUT`, `ANCHOR_BAD_SIGNATURE`, `ANCHOR_KEY_UNKNOWN`, `ANCHOR_RECORD_MISSING` (an anchor event with no record after 6 hours), `ANCHOR_BAD_RECORD`, `ANCHOR_OTHER_CHAIN`, and `ANCHOR_NONE` (no record at all is not a pass). The output names the newest anchor's head seq and hash: compare them with the phone.
- **Key.** `chapd ledger keygen --seed-out PATH` makes the ledger key; import it as `ledger-key` (kind `ed25519-seed`); start chapd with `-ledger-key-secret ledger-key`. Keep the printed public key somewhere other than the PC. After a rotation, old records need the old public key (`--anchor-pub`).
- **Limit.** Anchors prove the chain was not rewritten *since the anchor was copied off the PC*. Events after the newest anchor are covered only by the chain and the export. An attacker who controls chapd and the vault can sign new anchors, but cannot change the copies already on the phone and in the Drive backup.
