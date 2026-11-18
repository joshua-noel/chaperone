// Package approvals is Chaperone's approvals engine (ticket L1-12, ADR-004): the
// human decision that stands between an agent's request for a high-impact
// operation and the operation running.
//
// # The life of an approval
//
//		pending ─► approved ─► consumed
//		   │           └─► expired | cancelled
//		   └─► denied | expired | cancelled
//
//	 1. [Engine.RequestTx] makes the card for one request: it renders the
//	    per-op card text, hashes it (display_sha256), and stores the request, the
//	    checks and the text together. It refuses before a card exists when a
//	    check failed, the op needs no approval, the same op hash was denied or
//	    left unanswered in the last 60 minutes (sticky deny), or the caller has
//	    too many cards waiting (2 per run, 5 per project, 10 in total:
//	    APPROVAL_FLOOD). The same op hash from the same caller while a card is
//	    pending returns that card and wakes nobody (dedupe).
//	 2. The operator reads the card in the console and starts the decision
//	    himself: [Engine.BeginDecision] makes a challenge, SHA-256 over the JCS
//	    form of the approval's id, request, run, op hash, decision, approver,
//	    nonce, expiry, policy version and display_sha256 ([spec.ApprovalChallenge]).
//	    So one assertion covers the exact text that was shown, the decision and
//	    who made it, and cannot be replayed for another request, another
//	    decision or another approver.
//	 3. [Engine.Approve] takes the challenge (single use, burned on any
//	    attempt), has the [Verifier] check a fresh WebAuthn assertion with user
//	    verification over it (never the console session, which approves nothing),
//	    re-derives the op hash and the card from the stored request, and then
//	    does the compare-and-set pending→approved in one BEGIN IMMEDIATE
//	    transaction with the op.approve ledger event. Ten concurrent approvals of
//	    one card leave exactly one winner; the others get APPROVAL_CONSUMED.
//	    [Engine.Deny] needs no assertion: it only ever removes authority.
//	 4. [Engine.ConsumeTx] is the approved→consumed compare-and-set the op state
//	    machine runs in the same transaction that moves the op to executing. The
//	    request being released is hashed again: one byte of difference in the
//	    params is APPROVAL_HASH_MISMATCH and the approval stays unused.
//
// A token (a run's or the orchestrator's) can never decide an approval: every
// decision entry point takes an [Actor] and refuses a non-approver with
// POLICY_BREACH.
//
// # Atomicity and effects
//
// The *Tx methods run inside the caller's [store.DB.Immediate] transaction so
// an op's state change, its approval row and its ledger events commit
// together. They never perform I/O the transaction cannot roll back: the
// wake-up push and the critical-class alerts are returned as [Effects], which
// the caller runs after the commit ([Engine.Atomic] does both).
//
// # What this package does not do
//
// There is no quiet hours, daily budget or push-rate logic (decision #16); the
// pending caps bound what agents queue and never what the operator decides.
//
// # The phone
//
// With [Config.PhoneOrigins] set, a decision begun at a phone origin is the
// phone channel (ADR-004 section 5). The server card shows a two-digit number
// ([Engine.PCNumber]); the phone page shows three ([Engine.PhoneChoices]) and
// the approver taps the server's. [Engine.PhoneMatch] denies the card on a wrong
// tap (sticky-deny cooldown, ledgered) and on a right one leaves a one-use
// permission that [Engine.BeginDecision] takes at the phone origin: without it
// the phone gets no challenge. One assertion then approves any approve-tier op.
// Without PhoneOrigins only the "pc" channel is accepted.
package approvals
