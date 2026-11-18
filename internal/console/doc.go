// Package console is Chaperone's operator console: the HTML shell, the guard
// that every console request passes through, and the WebAuthn ceremonies that
// turn a Windows Hello (or, later, phone) assertion into a console session
// (ticket L1-06, ADR-004).
//
// # What the guard enforces (all on [Console.Handler], nothing global)
//
//   - Host: the request's Host header must be exactly the host of one
//     configured [Origin]. A DNS-rebinding page (Host: evil.example) is
//     refused before any handler runs, and so is 127.0.0.1 when the origin is
//     http://localhost:55398.
//   - Origin: when present it must equal that origin exactly; POST requires
//     it. Sec-Fetch-Site, when sent, must be same-origin or none.
//   - CSRF: every POST carries X-CSRF-Token, an HMAC of the csrf cookie (and
//     of the session, once there is one) under a per-process key.
//   - Cookies are HttpOnly and SameSite=Strict (Secure on https origins).
//   - Every response is Cache-Control: no-store, except /static/.
//   - CSP: script and style from 'self' only; no inline, no eval.
//
// # WebAuthn
//
// A credential is created with authenticatorAttachment platform, a
// discoverable key, user verification required and attestation none, and is
// stored with the rp_id and origin it was made at. An assertion only counts
// at that origin. User verification is checked twice: by go-webauthn and
// again here. A ceremony row is deleted before its response is read, so a
// replayed response finds nothing, and it is bound to the browser's csrf
// cookie.
//
// The package emits an [Event] through [Config.OnEvent] for each enrolment,
// login and refusal; the ledger (L1-02) and the approval engine (L1-12)
// attach there.
//
// # Screens (L1-20)
//
// [Console.UseApprovals] turns on /approvals; [Console.UseScreens] adds the
// rest, all server-rendered with htmx for the few actions:
//
//	GET  /                                  Home: pending approvals, recent denials, health, Stop all
//	POST /stop-all                          revoke every active run (OPERATOR_STOP_ALL)
//	GET  /runs                              active runs and orchestrator tokens
//	POST /runs/{id}/revoke                  revoke one run (OPERATOR_STOP_RUN)
//	POST /orchestrators/{id}/revoke         "Revoke orchestrator" (ADR-007 item 7)
//	GET  /catalog                           operations catalog, read-only
//	GET  /ledger                            search (run, request, op, event, time), last anchor
//	POST /ledger/verify                     the integrity check (optionally against the export)
//	GET  /secrets                           vault metadata, waiting secret writes, the import/rotate form
//	POST /secrets/request                   ask to import or rotate (critical op secrets.write)
//	POST /secrets/{approval}/commit         retry the store of an approved secret write whose first store failed
//	POST /secrets/{approval}/cancel         discard the value and close the approval
//
// Taking authority away (Stop all, revoke a run, revoke an orchestrator) needs
// the session and a browser confirmation. Adding a secret needs a fresh
// Windows Hello assertion over the approval card (ADR-004), exactly like any
// critical op: the value waits in memory under a keyed commitment that the
// approved op hash covers, and is stored only when that approval is consumed.
// No screen, response, log line or ledger event carries a secret value or a
// token; screens_canary_test.go searches for them in every form.
//
// The screens take their data through small interfaces ([RunsAdmin],
// [OrchAdmin], [LedgerView], [PolicyView], [VaultAdmin]) that the real
// registries satisfy, so chapd passes them in as they are.
package console
