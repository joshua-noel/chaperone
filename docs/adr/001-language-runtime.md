# ADR-001: Language and runtime for Chaperone (`chapd`, `chap`)

- **Status:** **Accepted** (operator sign-off; Go replaces the "TypeScript service" row of the original plan). Amended 2026-10-24 for later design decisions and for what the first build produced: see "Amendments" at the end.
- **Deciders:** the orchestrator (the lead agent that coordinates other agents), operator. **Author:** Chaperone maintainers.
- **Scope:** the Chaperone repo: the daemon `chapd`, the CLI `chap`, and the user-session helper `chap-host` (ADR-004).

## Context

What the language has to give us, taken from the original plan, the design drafts and the factory-spec v0 draft:

1. **`chap` is a single file you can drop in.** The CLI runs on the Windows host today and inside the Ubuntu sandboxes of the runner in Phase 2 (the runner is a separate project that starts agent runs and signs their run tokens; it is not yet public). It must work with no runtime installed, and be built from one tag for both OSes.
2. **`chapd` is the trusted control plane.** It holds the GitHub App key, Google tokens and deploy credentials (ADR-003). Its dependency tree is attack surface. The factory's whole supply-chain story (7-day cooldown, admission) says the gateway must have a small, auditable tree.
3. **It runs as a Windows service under a dedicated local account** (ADR-003: DPAPI scope separates it from the agents, which run as the operator before the runner exists).
4. **Needs:** SQLite, age encryption, WebAuthn server, JWT/EdDSA verify, JCS (RFC 8785), a GitHub REST client, an HTTP reverse proxy that parses git pkt-lines (ADR-002), OTLP export, Windows DPAPI.
5. Agents write nearly all the code, so "which language the team already knows" is a weak criterion. Review cost, build reproducibility and runtime surface are strong ones.

## Decision

**Go (1.26.x, the current release since 2026-02-10), one module, three static binaries built with `CGO_ENABLED=0`:** `chapd`, `chap`, `chap-host`. Targets: `windows/amd64` (all three) and `linux/amd64` (+ `linux/arm64` if Stage B needs it) for `chap`.

Consequences we accept with the decision:

- **Policy is code in the Chaperone repo; project overrides are data.** The baseline policy (the 35-control mapping, op catalog, checks) is Go, reviewed by PR, versioned (`policy_version` = module tag + catalog hash). A project's `.factory/project.yaml` can only *narrow or parametrise* it (allowlists, thresholds, which ops are enabled), validated against the factory-spec schema. The original plan said "TypeScript policy packs ... project overrides"; this ADR keeps the baseline + overrides split and drops "project-supplied code". Reason: a TS pack that a project repo can ship is code that executes inside the process that holds the secrets. Data cannot do that.
- **factory-spec tooling stays JavaScript** (`src/hashing.mjs`, ajv validators). The two implementations are tied together by **golden vectors**: the spec repo publishes `op_hash`, `event hash`, `trace_id`, run-token and approval fixtures; Chaperone CI must reproduce them byte for byte.
- **Dependency policy (enforced in CI):** standard library first. Allowed third-party modules for Phase 1, each pinned, vendored (`go mod vendor`, `-mod=vendor`) and bumped only by a PR that passes `go mod verify` and `govulncheck`: `golang.org/x/sys` (Windows service + DPAPI), `modernc.org/sqlite`, `filippo.io/age`, `github.com/go-webauthn/webauthn`, `github.com/golang-jwt/jwt/v5`, an RFC 8785 JCS module, OpenTelemetry Go SDK (optional export). Adding a module needs a line in an ADR addendum. Prefer the 7-day-old rule for bumps, same as the npm mirror.
- **Console UI:** server-rendered `html/template` + vendored htmx and Basecoat files pinned by SHA-256 (no npm, no build step, no `templ` code generation).
- **Windows service** via `golang.org/x/sys/windows/svc`; the same binary runs in the foreground (`chapd run`) for tests and development.

## Evidence

| Fact | Source |
| --- | --- |
| Node single-executable apps (SEA) are **Stability 1.1 "Active development"**; SEA embeds one script and injects a blob into the `node` binary. | <https://nodejs.org/api/single-executable-applications.html> (v26.12.1 docs) |
| In a SEA, **native addons cannot be loaded from the embedded VFS** because `process.dlopen()` needs a real file; `--build-sea` exists since v25.5.0; VFS is Stability 1.0. | same page |
| Node's built-in `node:sqlite` is **Stability 1.2 "Release candidate"**. | <https://nodejs.org/api/sqlite.html> |
| Node 24 is the current LTS line (22 also LTS); 26 is current. | the version list on the SEA page |
| Bun can `--compile` a TypeScript file to a standalone Windows or Linux executable (`--target=bun-windows-x64`), but it is a second runtime with its own release cadence. | <https://bun.com/docs/bundler/executables> |
| Go 1.26.0 released 2026-02-10. It adds an **experimental `runtime/secret`** package (enable with `GOEXPERIMENT=runtimesecret`) for erasing temporaries in code that handles secrets. | <https://go.dev/doc/devel/release> and <https://go.dev/doc/go1.26> |
| `golang.org/x/sys/windows/svc` provides everything required to build a Windows service (`Run`, `IsWindowsService`, `Handler`); `x/sys/windows` has `CryptProtectData` / `CryptUnprotectData`. | <https://pkg.go.dev/golang.org/x/sys/windows/svc>, <https://pkg.go.dev/golang.org/x/sys/windows> |
| `modernc.org/sqlite` is "pure-Go SQLite, no cgo"; v1.61.0 published 2026-10-21. | <https://pkg.go.dev/modernc.org/sqlite> |
| `filippo.io/age` v1.3.2 (2026-08-29) is the reference Go implementation of the age format. | <https://pkg.go.dev/filippo.io/age> |
| `github.com/go-webauthn/webauthn` is at **v0.18.2** (2026-09-19): pre-1.0, so its API can still break. | <https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn> |

## Alternatives

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| **Go** | True static single binary on both OSes with no runtime; native Windows service API; pure-Go SQLite (no C toolchain on the build host); age is native Go; small tree; one `GOOS=linux` build for sandboxes. | Policy cannot be hot-loaded TS; `go-webauthn` is pre-1.0; a second language next to the TS product repo. | **Chosen** |
| TypeScript on Node 24 LTS + SEA for `chap` | Matches the example project's stack and the original plan's row; one language for policy and the repo's tooling. | SEA is Stability 1.1 and native addons (e.g. `better-sqlite3`) cannot load from it, so we would depend on `node:sqlite` (RC); the service needs a wrapper (WinSW or NSSM, not evaluated here) to run on Windows; a large `node_modules` tree inside the secrets-holding process `[INFERENCE: size not measured]`; `chap` ships a whole Node binary per OS `[INFERENCE: tens of MB, not measured]`. | Fallback only |
| TypeScript on Bun `--compile` | Fast single file from TS. | Another runtime to pin and admit; I found no Windows-service support in the Bun docs I read `[INFERENCE: not exhaustively checked]`; judgment: a younger runtime is a poor fit for a secrets-holding service. | Rejected |
| Rust | Memory safety, static binary. | Judgment `[INFERENCE]`: slower for agents to iterate and review on the SQLite + WebAuthn + service plumbing; the threat model here is small JSON documents, not memory-unsafe parsing of hostile binary input. | Rejected for Phase 1; revisit for a hardened signing core |
| Hybrid: Go `chap` + TS `chapd` | Fast CLI, TS policy. | Two toolchains and two copies of every schema and hash rule in one repo. | Rejected |

## Flip conditions

Move back to TypeScript only if one of these becomes true: the operator wants to author policy himself in TS at runtime; `go-webauthn` proves unusable for Windows Hello (the WebAuthn spike fails its acceptance); or a required connector SDK exists only in Node. The fallback plan is already costed above: Node 24 LTS, `node:sqlite`, no native addons, SEA for `chap`, WinSW for the service.

## Verify

- CI builds all three binaries with `CGO_ENABLED=0` on the CI runner; `file`/`dumpbin` shows no dynamic Go runtime dependency; `chap version` runs on a clean Ubuntu container with no packages added.
- CI fails if `go.mod` gains a module not on the allowlist file `docs/dependencies.allow`.

## Amendments (2026-10-24, first build)

**Amendment 1. Go accepted.** Go static binaries `chapd`, `chap`, `chap-host`. The "Flip conditions" stay as written; the only work that can trip one is the real Windows Hello run (see Amendment 5).

**Amendment 2. Toolchain and dependency facts fixed by the first build.**

| Fact | Value |
| --- | --- |
| Go toolchain | **Go 1.26.10** (latest 1.26.x on go.dev/dl on 2026-10-24). `go.mod` says `go 1.26.10`; CI reads it with `go-version-file`. |
| Dev toolchain on the server | Portable unzip of the official `go1.26.10.windows-amd64.zip` (SHA-256 checked against go.dev/dl) in `D:\Chaperone\tools\go\`; `govulncheck` in `D:\Chaperone\tools\gopath\bin\`. No installer, no admin. README "Developing" has the PATH lines. |
| SQLite driver | `modernc.org/sqlite` **v1.60.1**, not v1.61.0: v1.61.0 was published 2026-10-21, three days before the first build, and the 7-day rule above applies. Its nine indirect modules (`golang.org/x/sys` among them) are in `docs/dependencies.allow` with the reason for each. |
| Vendoring | `vendor/` is committed (about 136 MB, nearly all of it `modernc.org/sqlite/lib` and `modernc.org/libc` per-platform files). CI builds with `-mod=vendor` and fails on `go mod vendor` drift. The size is the price of "no module download in the trusted build"; the largest single file is 5.5 MB, well under GitHub's limit. |
| Allowlist check | `go run ./scripts/allowcheck` compares every module in `go.mod` (direct and indirect) with `docs/dependencies.allow`. It uses the standard library only. |

**Amendment 3. Interaction with other decisions.** The decision to run agents under a separate Windows account changes the threat model that "Context" item 3 assumes; see ADR-003 amendment 1. The decision to support a phone passkey adds `go-webauthn` work to Phase 1; the library is already on the list above, so no new module.

## Amendments (2026-10-24, spec binding)

**Amendment 4. Modules added for the spec binding (`internal/spec`).** Each is on `docs/dependencies.allow` with its reason and was at least 7 days old when chosen.

| Module | Version | Why |
| --- | --- | --- |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 (2026-06-28) | JSON Schema 2020-12 validation of the spec's schemas, as the plan names. Pure Go. |
| `github.com/dlclark/regexp2` | v1.12.0 (2026-04-18) | The schemas' `pattern` values use negative lookahead (`(?!...)`), which Go's `regexp` cannot compile. `jsonschema/v6` lets the engine be replaced; this is the engine. `internal/spec` rewrites each `$` to `\z` first, because `$` in a .NET-style engine also matches before a final newline and the reference (ECMAScript, Ajv) does not. |
| `golang.org/x/text` | v0.41.0 (2026-08-11) | Required by `jsonschema/v6` (error messages); `internal/spec` uses `language` and `message` to render them. |

Evidence that the validator agrees with the reference (Ajv 8, strict mode): every valid example passes, every invalid example fails with the keyword and instance path recorded in the spec's `expect.json`, and a one-off differential run over 36,000 random mutations of the examples (six schemas) produced zero disagreements, including the trailing-newline cases. That run is not kept in the repo.

## Amendments (2026-10-24, WebAuthn)

**Amendment 5. Dependency added for WebAuthn: `github.com/go-webauthn/webauthn` v0.18.2** (published 2026-09-19, so past the 7-day rule). It is the library "Decision" above names for WebAuthn; its eight new indirect modules are in `docs/dependencies.allow` with the reason for each. Licences: BSD-3-Clause (`go-webauthn/webauthn`, `go-webauthn/x`, `golang-jwt/jwt/v5`), MIT (`fxamacker/cbor/v2`, `x448/float16`, `go-viper/mapstructure/v2`, `tinylib/msgp`, `philhofer/fwd`), Apache-2.0 (`google/go-tpm`). Vendored size about 3.9 MB. The module needs `golang.org/x/crypto` v0.57.0, so the shared requirements moved from v0.56.0 to v0.57.0 and, through it, `golang.org/x/text` from v0.41.0 to v0.42.0 (both published 2026-09-08); the vault and `internal/spec` build and test against them. **Flip-condition status:** the library handles registration and assertion with user verification required, per-origin RP IDs and the refusals (wrong origin, wrong challenge, replay, UV false) in the `internal/console` tests, which use a software authenticator; headless Edge with a virtual CTAP2 authenticator completed registration and sign-in through the real page script. Only the real Windows Hello run (ADR-004 amendment 7), which has not been done yet, can trip a "Flip condition".

## Amendments (2026-10-24, policy files)

**Amendment 6. Dependency added for policy files: `go.yaml.in/yaml/v3` v3.0.5** (published 2026-07-26, past the 7-day rule; Apache-2.0 and MIT, no further modules). Policy data files are YAML (`policy/<project>.yaml`, the catalog `api/manual.yaml`, the baseline pack), and the standard library has no YAML parser. This is the maintained continuation of `gopkg.in/yaml.v3` under the YAML organisation (the original repository is unmaintained). `internal/policy` is its only importer; it decodes with `KnownFields(true)` and refuses a second document, so an unknown key or a stray `---` in a policy file is an error, never ignored.

## Amendments (2026-11-05, local MCP front end)

**Amendment 7. The MCP server for `chap mcp` is hand-written; no module is added.** ADR-009 has the decision and the facts. The official Go SDK (`modelcontextprotocol/go-sdk` v1.8.0, 2026-09-14) is maintained and supports MCP revision 2026-07-28; its licence is mixed (new work Apache-2.0, not-yet-relicensed contributions MIT) and it needs about eight modules the allowlist does not have (`google/jsonschema-go`, `segmentio/encoding`, `segmentio/asm`, `yosida95/uritemplate/v3`, `golang.org/x/oauth2`, `golang.org/x/time`, `golang.org/x/tools`, and test-only `google/go-cmp`) for OAuth and HTTP code a stdio server never runs. It was not vendored or built against. `internal/mcpfront` implements JSON-RPC over stdio for tools only and imports no `net` or `net/http` package; a test enforces that. The choice is revisited if step 2 (an HTTP endpoint) is approved. Amendment 6 said `internal/policy` is the only importer of `go.yaml.in/yaml/v3`; `internal/mcpfront` now also imports it, to read the `Params` schemas of `api/openapi.yaml`.
