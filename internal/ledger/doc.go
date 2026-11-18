// Package ledger is Chaperone's hash-chained audit ledger (ADR-006, ticket L1-02).
//
// # Storage
//
// Events live in the `ledger_events` table (migration 0003) as canonical
// RFC 8785 JSON, exactly the factory-spec ledger event, with `seq`, `prev_hash`
// and `hash` assigned here. `BEFORE UPDATE` and `BEFORE DELETE` triggers refuse
// changes. `ledger_chains` records the committed head and the last exported
// event of each chain, so a cut-off tail is visible.
//
// # Writing
//
// SQLite's write lock is the single writer: every append runs inside a
// BEGIN IMMEDIATE transaction, reads the chain head inside it, and writes the
// event and the new head together.
//
//   - [Ledger.AppendTx] appends inside the caller's [store.DB.Immediate]
//     transaction, so an op's state change and its event commit together or not
//     at all.
//   - [Ledger.Append] queues the event to one writer goroutine, which commits
//     queued events in groups (one fsync per group).
//
// Every failure is an error and the caller MUST refuse the operation (fail
// closed): [ErrRejected] for a draft the spec does not accept, [ErrUnavailable]
// when the database cannot write (disk full, read-only, locked), and
// [ErrChainBroken] (stop code [StopChainBroken]) when the stored chain does not
// match its head. After [ErrChainBroken] the ledger refuses every append until
// restart.
//
// Each draft passes through the [Redactor] before it is validated and hashed;
// the masked rules come back in [Receipt.Redactions] and the caller raises
// REDACTION_BLOCKED when there are any.
//
// # Export and verification
//
// [Ledger.Export] appends new events to the daily segment
// `<ExportDir>/<chain>/<yyyy-mm-dd>.jsonl`, one event per line, and fsyncs
// before it records the export mark. [Verify] (the library behind
// `chap ledger verify [--against-export]`) rechecks the chain with
// [spec.VerifyChain], the indexed copies, the head and the anchors, and with
// AgainstExport compares SQLite and the JSONL files byte for byte.
//
// A chain stored beside the key that writes it cannot show a wholesale
// rewrite; that is what `ledger.anchor` events delivered off the server are for
// (L1-21 delivers them; [Ledger.Anchor] writes the event).
package ledger
