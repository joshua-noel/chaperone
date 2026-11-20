package spec

import "strings"

// The pinned spec (v0.1.5) knows two requester kinds, run and orchestrator. A
// custom key (ADR-008) is a third kind in Chaperone's own tables, but the ledger,
// the approval request and the denial body are spec documents, and a spec
// document cannot name a kind the spec does not have. These two functions are
// the one place that edge is written: a key is projected onto the spec as an
// orchestrator whose id is "key." plus the key id (a valid orchestrator id).
// When the spec adds a `key` kind (SR-1), only this file changes.

// KeyRequesterPrefix starts the id of every projected key requester. No real
// orchestrator may be called by an id that starts with it (runtoken refuses to
// issue one), so the projection cannot be forged by naming an orchestrator.
const KeyRequesterPrefix = "key."

// KeyRequester is the spec requester of the key with this id.
func KeyRequester(keyID string) Requester {
	return Requester{Kind: "orchestrator", ID: KeyRequesterPrefix + keyID}
}

// KeyIDOf returns the key id of a projected key requester.
func KeyIDOf(r Requester) (string, bool) {
	if r.Kind != "orchestrator" {
		return "", false
	}
	id, ok := strings.CutPrefix(r.ID, KeyRequesterPrefix)
	return id, ok && id != ""
}
