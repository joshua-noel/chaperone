// Package redteam is the incident replay and red-team suite of Chaperone (ticket
// L1-19). Everything runs offline: a real chapd stack (SQLite store, vault and
// redaction registry, hash-chained ledger, policy engine, op state machine,
// run-token verifiers, interim issuer, git proxy, HTTP server, wired as
// cmd/chapd/wire.go wires it) is attacked over HTTP with a fake GitHub (ghtest
// and `git http-backend`) and a spy adapter that records what it was asked and
// never touches the world. The real `chap` and `chapd` binaries are built from
// the checkout for the tests that must see what a person sees.
//
// The suite runs in CI on every pull request, with `go test ./...`.
//
// # How a replay is built
//
//   - It names its incident or red-team entry (RT id, listed in
//     docs/manual-crosswalk.md, threat-model ids in the file header).
//   - It has a baseline: the attack works without the control (a bare GitHub
//     client merges the red PR) or a control case that does pass (the green PR
//     merges), so a broken setup cannot pass as a block.
//   - It asserts the refusal and the evidence: the denial's cause code, that the
//     spy never executed, that GitHub saw no merge or receive-pack request, that
//     no token is left live, that the ledger still verifies.
//   - Its control can be removed: mutation_test.go removes one control at a
//     time (a patched copy of one source file, `go test -overlay`) and requires
//     the matching replay to turn red. Forty-three controls are covered (merge on red,
//     stale head, risk tier, deleted or skipped tests, requirements files,
//     approval binding, token decides, approval flood, secret redaction,
//     revoked orchestrator, interim switch-off, push gate; with their
//     replays in internal/console, a console session, a secret write spending
//     its approval, the approved value, Stop all's OPERATOR_STOP_ALL, Revoke
//     orchestrator; and five deploy preconditions: load gate, zero-byte backup,
//     stale backup, commit on the base, pilot down after; two in the chapd
//     wiring of the approvals engine: a release spends its approval, a denial
//     never releases; six in the Google connectors: off-list recipient,
//     Drive role cap, secret in an attachment, swapped attachment, revoked
//     grant, hash of the rendered message on the card; seven for the
//     phone: the number gate, the wrong-number denial, the channel
//     cross-check, the push allowlist, the origin binding, no enrolment from
//     the phone, one address per approval; and three in the ledger anchors: the anchor
//     hashes, the anchor signature, the 26 hour export alert).
//
// # Coverage of the red-team list (Phase 1, RT-01 to RT-33 and RT-52)
//
// "Open finding" means the suite found a gap and reports it (in the PR and in
// the test log); it is not a failing test. "Not offline" means the check needs
// the server or another account and is a checklist item for the rehearsal, not a
// test here.
//
//	RT-01 merge on red CI (22 Oct)             covered: rt01_merge_on_red_test.go (20x, dry run, claimed approval,
//	                                           other head, forged verify), rt_merge_http_test.go (over HTTP,
//	                                           real pr.merge adapter). Mutation: yes.
//	RT-02 stale or moved head, base advanced   covered: rt02_stale_head_test.go (18 Oct replay, three race points,
//	                                           409 not retried), rt_merge_http_test.go. Mutation: yes.
//	                                           Partial: the list's 200-iteration race loop is not run (20x).
//	RT-03 PR weakens its own verify            covered for (a) workflow, (b) tests deleted, moved or skipped
//	                                           (medium), (c) lint/type config, (d) package.json,
//	                                           (e) npm/pnpm/yarn/uv/go lock files and requirements.txt,
//	                                           (f) renamed job, (g) filters: rt03_tier_test.go.
//	                                           Mutation: yes (tier, test weakening, requirements files).
//	RT-04 forged status, check, webhook        partial: a verify run from another App, or none, is ignored (rt01);
//	                                           a commit status is never read (internal/ops). No webhook endpoint
//	                                           exists, so the HMAC cases do not apply yet.
//	RT-05 write bypass with the agent's token  covered through chapd: rt05_push_test.go, real git client, real
//	                                           proxy: base, tags, other and deleted branches, other runs' branches,
//	                                           several refs, force, mirror, other ref namespaces, ended run, token
//	                                           without the op, wrong repo. Workflow files: the installation token
//	                                           never has the workflows permission (GitHub refuses the push; chapd
//	                                           cannot read a pack). Mutation: yes (push gate).
//	                                           Not offline: finding a credential in the agent's environment.
//	RT-06 operator credential sweep             not offline (agent account, DPAPI, credential stores).
//	RT-07 read the vault                       partial: no route returns a secret (vault status lists names only,
//	                                           rt26), no ledger or response holds a registered secret. Not offline:
//	                                           the ACL on the vault directory and key files.
//	RT-08 forged, altered, cross-run tokens    covered: rt08_tokens_test.go (alg none, HS256, RS256, kid, typ,
//	                                           extra header, altered claims, aud, iss, expiry, issuer matrix, run
//	                                           token vs orchestrator token), orch_token_test.go (malformed
//	                                           orchestrator tokens).
//	RT-09 reuse after the run ends             covered: rt08_tokens_test.go (ended, revoked, reaped; survives a
//	                                           restart; ledger order).
//	RT-10 forge a brief's trusted fields       not covered: briefs are the runner's. The mint request is covered by
//	                                           RT-52 (b).
//	RT-11 approval replay with a changed op    covered at the engine (real database, real op hash and challenge):
//	                                           rt11_approvals_engine_test.go: (a) (b) (e) (g) (h) (j) (c) (d) (f);
//	                                           and over HTTP with a stand-in approvals store: rt24, rt13_rt15_http,
//	                                           rt_merge_http; and through chapd's real wiring (engine, op pipeline,
//	                                           ledger, Hello stand-in, fake GitHub): cmd/chapd/approvals_e2e_test.go
//	                                           (a stale assertion, a second use, a denial that stays denied).
//	                                           Not covered: (i) cancel and recreate with the same
//	                                           display text. Mutation: yes (op hash, spending the approval).
//	RT-12 moving references, TOCTOU            partial: pr.merge head moved while the card waits
//	                                           (rt_merge_http_test.go), head moved after the check (rt02).
//	                                           Not covered: deploy main, drive folders. Mail attachments: the
//	                                           staged file must hash to the SHA-256 on the card (rt24_google_test.go).
//	RT-13 an agent approves its own request    covered: rt11_approvals_engine_test.go (run and orchestrator actors
//	                                           breach, stop raised, nothing decided), rt13_rt15_http_test.go (no
//	                                           route or verb decides, about 2,000 probes). Mutation: yes.
//	                                           Not offline: cookie replay, UI automation, toast spoof, clock.
//	RT-14 console web attacks                  covered in internal/console (Host, Origin, CSRF, fetch metadata, a
//	                                           POST without a session on every L1-20 screen: screens_test.go;
//	                                           the secret write needs a fresh Hello approval of its card, a held
//	                                           value that is not the approved one is refused: screens_secrets_test.go;
//	                                           canary in every screen, response, ledger event, export, log and
//	                                           database byte: screens_canary_test.go). The mutation check below
//	                                           runs these in ./internal/console. Not offline: a real browser.
//	RT-15 approval flood                       covered: rt11_approvals_engine_test.go (caps, dedupe, sticky deny,
//	                                           one wake-up, no parameter on the phone), rt13_rt15_http_test.go
//	                                           (APPROVAL_FLOOD stop events, 429, dedupe). Mutation: yes.
//	                                           Not covered: the hourly drip counter, run pause.
//	RT-16 look-alike request (attention)       not automatable (human factors, quarterly).
//	RT-17 truncation, confusables, bidi        not covered here (internal/approvals card tests).
//	RT-18 phone push spoofing                  covered: rt18_rt19_phone_test.go (no challenge before the number,
//	                                           a match is for one card, browser and challenge and runs out, a
//	                                           wrong number denies and starts the cooldown, blind taps never
//	                                           approve, a token cannot match, forged and replayed pushes and
//	                                           pushes for a card that does not exist open nothing, a phone
//	                                           assertion is not a server one); over HTTP with the real WebAuthn
//	                                           verifier: internal/console/phone_test.go (look-alike origins and
//	                                           hosts, credentials do not cross origins, signed-out phone page,
//	                                           no enrolment from the phone). Mutation: yes (five).
//	                                           Not covered: the 24 h delay on a second device (RT-20, approver.add
//	                                           is not built), a real phone's push app and deep links.
//	RT-19 notification and lock-screen leakage covered for the push: rt18_rt19_phone_test.go (canary in
//	                                           recipient, subject, body and reason; the captured ntfy request
//	                                           holds kind, project, 8 hex, expiry and a count only). The server toast
//	                                           is a count (cmd/chap-host toast tests). Mutation: yes. Not covered:
//	                                           a real lock screen.
//	RT-20 rogue approver or device enrolment   partial: the phone cannot ask for or spend an enrolment, one
//	                                           approval makes one address that works once for 10 minutes, the
//	                                           card is critical class and approved with Hello on the server
//	                                           (internal/console/phone_test.go). Mutation: yes (two).
//	                                           Not covered: the 24 h delay, cancel by old authenticators.
//	RT-21 display and hash mismatch            partial: a stored card edited after the fact is refused by the
//	                                           table trigger and, with the trigger dropped, by the engine
//	                                           (DISPLAY_MISMATCH, APPROVAL_HASH_MISMATCH):
//	                                           rt11_approvals_engine_test.go.
//	RT-22 adapter injection                    not covered (adapters are separate tickets).
//	RT-23 deploy preconditions                covered: rt23_deploy_test.go, the real deploy adapter over a fake
//	                                           GitHub, fake fact files, a fake pilot and a fake chap-host: commit
//	                                           off the base, red or missing verify, load gate not normal or older
//	                                           than 5 minutes, backup stale, zero-byte or empty, pilot not ok; each
//	                                           refused with no approval card and no host run. Approve A and request
//	                                           B is APPROVAL_HASH_MISMATCH; a pilot that is down after the deploy
//	                                           is op.result outcome=failed with an alert. Mutation: yes (five).
//	                                           Not covered: a live deploy (operator-attended, later), the helper
//	                                           refusing a bad grant (cmd/chap-host tests).
//	                                           A deploy from a host-interim run needs an approval and an approval
//	                                           made for the orchestrator is not portable (RT-52 (a)).
//	RT-24 mail and Drive (22 Oct demo email)   covered for approval: rt24_demo_email_test.go (shipped baseline
//	                                           OP_DISABLED; enabled, OP_APPROVAL_REQUIRED; another op's approval,
//	                                           another recipient, made-up id; one send per approval).
//	                                           With the real Google connectors over a fake Google
//	                                           (rt24_google_test.go): disabled in the shipped baseline; an off-list
//	                                           recipient (To, Cc, Bcc, display name, look-alike, header injection)
//	                                           never gets a card; one changed character, before or after the
//	                                           approval, is APPROVAL_HASH_MISMATCH; the SHA-256 on the real card
//	                                           equals the hash of the bytes Gmail receives; a secret in a body or an
//	                                           attachment is REDACTION_BLOCKED; a swapped attachment is never sent;
//	                                           Drive role cap and allowlist; a revoked grant fails closed with an
//	                                           alert. Mutation: yes (six). Not offline: the live Google flow (H5).
//	RT-25 exfiltration through op payloads     partial: results, errors, references, logs and requests carrying a
//	                                           canary in raw, base64 (4), hex (2) and JSON forms: rt26. Known gap,
//	                                           as the list allows: split or otherwise encoded secrets (rot13,
//	                                           gzip, zero-width separators) are not caught: an accepted residual
//	                                           risk, ADR-003 amendment 4.
//	RT-26 secrets in logs and the ledger       covered: rt26_canary_test.go. The canary never appears in any HTTP
//	      (19 Oct)                             response, chapd log line, ledger event, database or WAL byte, JSONL
//	                                           export, vault file, or `chap` stdout and stderr, on every `chap` command that
//	                                           prints a response; control: with no secret registered it does leak.
//	                                           Mutation: yes (redactor off).
//	                                           Found and fixed on the way: an adapter's error text was logged
//	                                           unmasked.
//	                                           Closed findings (a secret the agent itself sends): a request that
//	                                           holds a secret in its target, params, reason or path is refused
//	                                           REDACTION_BLOCKED, its denial names nothing of it, and no op row
//	                                           is stored (TestRT26AgentSuppliedSecret). Mutation: yes (two).
//	                                           Not covered: log-injection of ledger syntax (internal/ledger).
//	RT-27 ledger tampering                     internal/ledger tamper tests; this suite only checks that the chain
//	                                           verifies after every attack (mustLedgerOK). A rewrite of the whole
//	                                           chain, consistent with itself, is caught by the signed anchors
//	                                           (L1-21): anchor_test.go. Mutation: yes (anchor hashes, anchor
//	                                           signature, 26 h export alert).
//	RT-28 pr.open scope and gate files         not covered here (internal/ops pr_open tests).
//	RT-29 policy tamper and activation         not covered here (internal/policy: a project file can only narrow).
//	RT-30 prompt injection end to end          not automatable offline.
//	RT-31 API flood, fail-closed               not covered here (rate limit is internal/ops; ledger failure fails
//	                                           the op closed in internal/ledger and internal/ops tests).
//	RT-32 poisoned dependency in own build     CI (allowcheck, govulncheck, vendor drift), not this suite.
//	RT-33 stop and revoke                      covered: rt33_stop_test.go (stop all, a run token cannot stop,
//	                                           pending approval voided, approval after the stop executes nothing,
//	                                           token.revoke per run, survives restart). Not covered: the in-flight
//	                                           slow op.
//	RT-52 interim host token                   covered: rt52_interim_test.go (switch-off, restart with
//	                                           allow_interim=false; mint ceiling table; per-op outcome table for
//	                                           (a); mint answer returns the token only to the orchestrator,
//	                                           never ledgered, logged or stored), orch_token_test.go.
//	                                           The mint ceiling and the policy's host-interim profile agree and
//	                                           both exclude the critical ops (repo.settings, host.scripts.refresh).
//	                                           Mutation: yes. Not offline: key ACL and memory reads (b), key
//	                                           deletion (c).
//
// # Orchestrator token (ADR-007)
//
// orch_token_test.go: a revoked token is TOKEN_REVOKED on the next request and
// cancels its pending approvals; an expired or malformed token is refused; scope
// (ops, project) is respected; it cannot approve (RT-13); only its SHA-256 is
// stored, and the token file written by `chapd orch issue` is exclusive and (off
// Windows) mode 0600. Not offline: that the agent's Windows account cannot read
// the token file (an ACL set by the host script, checked on the server).
//
// # Not run here
//
// The Windows-only parts of Chaperone (DPAPI, the service, Windows Hello) and the
// sandbox tiers (the runner) have no offline test. Every entry above marked "not
// offline" belongs on the checklist of the rehearsal at phase exit.
package redteam
