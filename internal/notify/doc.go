// Package notify wakes the operator's phone when an approval is waiting (ticket
// L1-13, ADR-004 section 4).
//
// The push carries no authority. Decision #18: it only wakes the phone, which
// then opens the console page over the tailnet. So a push holds the kind of
// operation, the project, the first 8 hex characters of the op hash, the expiry
// time and the number of pending approvals, and nothing else: no parameters, no
// recipients, no body text, no link and no action button. [Build] is the only
// code that makes push text, and it works from the five fields of [Wake]
// after checking each against a strict pattern, so text from an agent's request
// cannot reach the phone.
//
// Parts:
//
//   - [Notifier] is the interface every driver implements.
//   - [Ntfy] is the Phase 1 driver. It publishes over HTTPS to ntfy.sh (or a
//     self-hosted server) with the JSON publish API, so the topic travels in the
//     request body and never in a URL, a log line or an error.
//   - [Topic], [TopicStore] and [InitTopic] hold the random 128-bit topic. ntfy
//     treats the topic as a password. The store is an interface because the vault
//     (L1-03) lands separately.
//   - [Service] wraps a driver: one push per op hash, and a send that never
//     blocks the caller. An outage of ntfy.sh costs a missed wake-up and a log
//     line; the console card and the Windows toast still work.
//   - Package ntfytest is the fake ntfy server for tests.
//
// Decision #16 means there is no coalescing, no rate cap and no quiet hours:
// every push has the same priority at every time of day, and nothing here limits
// how many pushes the operator gets. Dedupe (one push per op hash) and the
// agent-facing pending caps in the approvals package bound the volume.
package notify
