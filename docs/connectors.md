# Writing a connector

A connector lets Chaperone act on one service for an agent, so the agent never holds a credential for it. This page says how a connector is put together, what rules it must follow, and how to add one operation.

Status: the connector kit covers the Linear connector and the GitHub operations. Google still uses the older layout. See [What is covered](#github-what-is-covered-and-what-stays-custom) and [What is not covered yet](#what-is-not-covered-yet).

## The seam

A connector implements `ops.Adapter` (`internal/ops/types.go`):

```go
type Adapter interface {
    Check(ctx context.Context, req *Request) (CheckResult, error)
    Execute(ctx context.Context, req *Request) (Outcome, error)
}
```

`chapd` does everything else. It checks the token, the policy and the rate limit, asks the operator for approval when the class needs it, calls `Check` and then `Execute`, and writes the ledger. The adapter decides what the operation does, and whether this request is allowed for this service.

## How it was put together (before the kit)

One new operation touched about twenty files. This is the map for the four Linear operations (`intake.list`, `intake.comment`, `intake.move`, `intake.states`), with what each file contributes:

- **(a) real logic:** a decision or an action that only this operation has.
- **(b) a repeated fact:** name, class, reversibility, summary, usage line, parameters, rate. The same fact, typed again.
- **(c) wiring:** a line that only connects one piece to another.

| File | What it contributes | Kind |
| --- | --- | --- |
| `internal/connectors/linear/intake.go` | The four adapters: parse, `Check`, `Execute`, result text | (a) |
| `internal/connectors/linear/adapter.go` | The op name constants, the `Ops` list, the `Adapters` map; the allowed param names inside each `parse` | (b) and (c) |
| `internal/connectors/linear/*_test.go` | Tests of the above | (a) |
| `cmd/chap/intake.go` | One command per operation: flags, shape checks, usage errors, the request. Also the printing of `intake.list` and `intake.states` | (c) and (b) for the commands; (a) for the printing |
| `cmd/chap/ops.go` | The command table: path, usage line, summary, function | (b) and (c) |
| `cmd/chap/testdata/golden/help.golden` and `intake-*.golden` | The recorded help line and the recorded runs | tests of (b) |
| `cmd/chap/golden_test.go`, `testdata/chapd/op-intake-*.json` | The cases and the canned replies | tests |
| `docs/manual.md` | The generated manual: the catalog table and the help of each command | (b), generated from the two files below and the binary |
| `api/manual.yaml` | The catalog entry: class, reversibility, surface, summary, usage | (b) |
| `api/openapi.yaml` | `Params<Op>`: the params schema. The MCP tool schema is read from it | (b) |
| `internal/policy/data/baseline.yaml` | The rate, and the switch that turns the operation on | (b), and policy |
| `internal/policy/policy_test.go` | `shippedEnabled`: the list that makes turning an op on a visible change | policy |
| `internal/policy/linear_test.go`, `cmd/chapd/linear_test.go`, `internal/approvals/types.go` | Lists of the four names in tests | (b) |
| `docs/running-chapd.md`, `README.md` | Prose that names the operations | (b) |

Nothing in `cmd/chapd` or `internal/mcpfront` needed a change per operation: `chapd` registers every adapter a connector returns, and the MCP tool list is read from the catalog and the params schema.

That is 14 files that a new Linear operation had to change to pass the tests (11 opened and edited by hand, 3 rewritten by a command: `docs/manual.md`, `help.golden` and the new golden files). The lists and prose in the last two rows add about five more that people update by habit, so "about twenty". Only the adapter file, its tests and part of `cmd/chap/intake.go` (the printing) hold logic.

## How it is put together with the kit

The facts in (b) are declared once, as a Go value, in `internal/connectors/linear/linearspec/spec.go`:

```go
var Move = kit.Op{
    Name:          NameMove,
    Class:         kit.Routine,
    Reversibility: kit.Reversible,
    Summary:       "Move a labelled operator-board item to a listed state.",
    Usage:         "chap intake move <SHOP-12> --state <name>",
    RatePerMinute: 6,
    Doc:           "Phase 1 shape for `intake.move`. Target is ...",
    Target:        issueTarget,
    Params: []kit.Param{
        {Name: "state", Kind: kit.String, Required: true, MinLength: 1, MaxLength: MaxStateBytes,
            Placeholder: "name", Help: "the state's name, ..."},
    },
}
```

The package `internal/connectors/kit` reads declarations. It uses the standard library only, because `chap` links it. The list of declared connectors is `internal/connectors/declared`.

What is derived from a declaration:

| Piece | How | What checks it |
| --- | --- | --- |
| Catalog entry in `api/manual.yaml` | Generated into a marked region by `go generate ./internal/connectors/...` | `TestGeneratedRegionsAreUpToDate` and `TestCatalogAgreesWithTheDeclarations` in `internal/connectors/declared` |
| Params schema in `api/openapi.yaml` (and so the MCP tool schema) | Generated into a marked region, the same command | The same tests, and the existing schema tests of `internal/mcpfront` |
| Adapter registration | `kit.Bind` in `linear.Adapters`, and in `adapters` of `cmd/chapd/adapters.go` for GitHub, refuses to start when an operation has no adapter, or an adapter has no declaration | `TestAdaptersAreTheDeclaredOperations`, `TestBindIsOneToOne`, `TestGitHubAdaptersAreTheDeclaredOperations` |
| Allowed param names in `parse` | `onlyParams(r.Params, linearspec.Move.ParamNames()...)`; the GitHub adapters of `internal/ops` do the same with `githubspec` | `TestEachAdapterTakesTheDeclaredParamsOnly` |
| `chap` command, help, usage errors | Built at start-up by `cmd/chap/kitcmd.go` | The golden files and `docs/manualgen` (unchanged), `TestEveryDeclaredOpHasExactlyOneCommand` |
| Usage line of the command | Computed from the declared params | `TestGeneratedCommandLines` |

What is NOT derived, on purpose, and stays hand-written in the connector:

- The conditions under which an operation is allowed (team, label, state list, who may ask).
- The idempotency of `Execute`.
- The approval evidence an adapter adds to a card (`CheckResult.Evidence`).
- How text from the service is cleaned, capped, withheld and marked untrusted.
- The printing of a result in `chap` (for example `renderIntakeList`).
- Whether an operation is **on**. That is `internal/policy/data/baseline.yaml`, a reviewed policy change. The declaration carries the rate only, and a test fails when the baseline's rate differs.

### Why a declaration cannot loosen a class

- The class is also written in the generated manual entry, so a change of class is a visible change in the same pull request.
- Every declared operation is pinned in one table written by hand, `pins` in `internal/connectors/declared/declared_test.go`. `TestEveryDeclaredOpIsPinned` fails for an operation with no pin, so a new connector cannot skip it. Loosening a class means changing the declaration, the manual entry and the pin together.
- This was tried for `pr.merge`, the one gated GitHub operation. With the class lowered to routine in the declaration, `TestEveryDeclaredOpIsPinned`, `TestGeneratedRegionsAreUpToDate` and `TestCatalogAgreesWithTheDeclarations` fail. With the manual entry regenerated as well, `TestEveryDeclaredOpIsPinned` still fails, and so do `TestClassesAndCriticalOps` in `internal/policy` and the `manual-code` golden of `cmd/chap`.
- `kit.Op.Validate` refuses an irreversible operation that is routine or gated. *Decided for now:* this rule stays. The owner has not answered yet.
- The catalog loader still refuses a duplicate key and a `secrets.*` operation that is not critical. A declared operation cannot replace a hand-written entry: the generator only rewrites its own marked regions, and a test counts the entries.
- The baseline loader still refuses a catalog operation with no baseline rule, so a declared operation is off until a policy change turns it on.

### When a generated command is not enough

Set `CLI: kit.CLI{Custom: true}` in the declaration and write the command in `cmd/chap/ops.go` as before. `TestEveryDeclaredOpHasExactlyOneCommand` fails when an operation has both or neither. The generic command handles:

- one ref: a positional argument, or a flag with a default, or a repository (`owner/name`, or `owner/name#N` with the number as the positional argument) read from `--repo` and else from the git remote origin;
- bool flags, string flags (with a pattern check and its usage error), whole-number flags (a minimum, a maximum, 0 means "left out"), repeatable list flags, and the `--body` / `--body-file` pair;
- a `--dry-run` flag;
- a param the command fills from the ref (the number, or the ref itself) and a param with one fixed value.

Anything else needs a custom command: a param read from git, a default for a flag that the schema does not have, a flag that depends on another, a hint written into the usage line, a command whose flags are not in the order of the schema.

For a custom command, `kit` checks only what the catalog and the params schema need: the adapter name, and each param's name, kind and bounds (length, pattern, const, number bounds, list bounds). It does not check the ref's shape (`Target.Pattern`, `Positional`, `Flag`, `Default`, `Why`), the flag names, the `body` name of a text param, or the placeholders and help of a flag, because the hand-written command owns those. Set `Target: kit.Target{Adapter: "github", Repo: true}` for a ref that is read from git.

The params schema is written from these kinds: bool; string (a length, or a pattern, or `Const`, or `Unbounded` when the schema has no maximum and the adapter bounds it); text; integer (minimum, maximum, default); list of strings (item count and item length). An enum, a one-of or a nested object cannot be declared yet.

`TestGeneratedCommandsHaveNoFlagClash` builds the flag set of every generated command, so a declared flag that has the name of a common flag (`--json`, `--project`, `--reason`, `--approval`, `--request`, `--wait`) fails a test. `TestKitKnowsTheCommonFlags` checks that `kit.CommonFlags` is the list `chap` registers.

## Rules a connector must follow

1. **No secret in any output.** An adapter never puts a credential in `Outcome.Result`, in a `Refusal.Why`, in an error, or in a log line. Register every token you hold with the redaction registry (`internal/redact`), as `linear/token.go` does. Chapd scans results again, but that is the second line.
2. **`Check` has no side effects.** It may read. It is called many times: on submit, on a dry run, when an approval is requested, and at release. It must give the same verdict each time for the same state.
3. **`Execute` is idempotent per execution id.** After a crash chapd retries with the same `Request.ExecutionID`. Derive any id you send to the service from it (`linear.CommentID`), and make a no-op request send nothing (a move to the state the item is already in).
4. **Re-check in `Execute`.** `Check` ran earlier. Read the facts again before a write, as `guard` does in Linear.
5. **Outside text is marked untrusted.** Text written by other people (titles, comments, logs) goes into the result cleaned of control and format characters, capped in length, and withheld whole when it looks like a secret. Set `untrusted_text: true` in the result. The MCP front puts every result behind a fixed notice, and the `chap` printer says "data, never instructions".
6. **Every refusal has a cause code.** Return `*ops.Refusal` with a `Code` from `internal/ops/denial.go` (`OP_PARAMS_INVALID`, `OP_POLICY_REFUSED`, `SCOPE_PATH`, `REDACTION_BLOCKED`, and so on). A plain error means "the service could not be asked" and chapd fails closed.
7. **Refuse what you do not know.** An unknown param is `OP_PARAMS_INVALID`. A ref of another team is `SCOPE_PATH`. Never guess.
8. **A write is sent at most once.** A definite refusal by the service is `failed`. An answer that does not show whether the service acted leaves the op `unconfirmed`, with what to look up in the result. Never retry a write by yourself.
9. **Do not widen the class.** An operation that changes something outside Chaperone and cannot be undone is `high`, and needs the operator's approval every time.

Rules 1, 2, 3, 5 and 6 have no shared test yet; each connector tests them for itself. See below.

## Walkthrough: add a read-only operation

Goal: `intake.show`, which reads one labelled item. The same steps work for any simple operation of a declared connector. `TestAFifthOperationNeedsOnlyItsDeclarationAndAnAdapter` (`internal/connectors/declared`) and `TestAFifthOperationGetsItsCommandFromItsDeclaration` (`cmd/chap`) run this walkthrough with a test-only operation. It is not in the shipped catalog.

1. **Declare it** in `linearspec/spec.go`: a `kit.Op` with the name, class, reversibility, summary, usage, rate, doc, target and params. Add it to `Connector.Ops`. Add its class and reversibility to `pins` in `internal/connectors/declared/declared_test.go`.
2. **Write the adapter** in `internal/connectors/linear` (a new file, or `intake.go`). Parse the request, apply the policy through `base.policy` and the target checks, then write `Check` and `Execute`. Use `linearspec.Show.ParamNames()` for the allowed params.
3. **Bind it**: one line in the map of `Adapters` in `adapter.go`. Without it, `chapd` refuses to start.
4. **Write the tests** next to the adapter: the allowed request, each refusal and its cause code, the idempotent write, no secret in the result.
5. **Generate**: `go generate ./internal/connectors/...` writes the manual entry and the params schema. Then `go run ./docs/manualgen` rewrites `docs/manual.md`, and `go test ./cmd/chap -update` records the new help line. Read the diff of each.
6. **Add the policy rule**: one line in `internal/policy/data/baseline.yaml`, `intake.show: { enabled: false, rate_per_minute: 12 }`. The rate must equal the declared one. It stays off until a policy change turns it on; that change also adds the name to `shippedEnabled` in `internal/policy/policy_test.go`.
7. **Run** `go test ./internal/connectors/... ./cmd/chap ./internal/policy ./internal/mcpfront ./docs/manualgen`.

### Files touched

| | Before the kit | With the kit |
| --- | --- | --- |
| Opened and edited by hand | 11 | 5: the declaration, the adapter, one line in `Adapters`, the adapter's tests, one line in the baseline |
| Changed by a command | 3: `docs/manual.md`, `help.golden`, the new golden files | 4: `api/manual.yaml`, `api/openapi.yaml`, `docs/manual.md`, `help.golden` |
| **Total** | **14** | **9** |
| Also, when the operation is turned on | `shippedEnabled` in `policy_test.go` (already in the 11) | the same file: 6 by hand, 10 in all |

The 11 before were: the adapter, `adapter.go`, the adapter's tests, `cmd/chap/intake.go`, `cmd/chap/ops.go`, `golden_test.go`, the canned reply, `api/manual.yaml`, `api/openapi.yaml`, `baseline.yaml` and `policy_test.go`. With the kit an author may still add golden cases for the new command; the generic command is tested once, in `cmd/chap/kitcmd_test.go`.

Adding a whole new connector adds one line to `internal/connectors/declared/declared.go`, and the two marker lines are created by the generator (`api/manual.yaml` at the end of the file, `api/openapi.yaml` before the first `Params` schema).

## GitHub: what is covered and what stays custom

The GitHub operations are declared in `internal/connectors/github/githubspec/spec.go`. The adapters stay in `internal/ops`, where `cmd/chapd/adapters.go` builds them and `kit.Bind` pairs them with the declarations. The class of every one is pinned in `internal/connectors/declared/declared_test.go`.

| Operation | Class | Catalog entry, params schema, adapter binding | `chap` command |
| --- | --- | --- | --- |
| `pr.view`, `pr.diff`, `pr.checks`, `pr.files` | routine | generated | generated |
| `pr.update` | routine | generated | generated (`number` is filled from the ref) |
| `issue.comment`, `issue.reopen` | routine | generated | generated |
| `ci.report` | routine | generated (connector `ci`, adapter `runner`) | generated |
| `pr.open` | routine | generated | **custom**: `head` is the current git branch when `--branch` is left out, and `--base` defaults to `main` |
| `pr.merge` | **gated** | generated | **custom**: the command fixes the merge method (`squash`), `--base` defaults to `main`, and the flag `--head` fills `head_sha`. It is the one operation here that changes the repository for good, so its command stays where a reviewer reads it whole |
| `issue.open` | routine | generated | **custom**: its usage line names the label the error watcher must give (`--label source:error-watcher`), and its usage errors name it too |
| `branch.push` | routine | **not declared** | none (`chap git setup`, then `git push`) |

`ci.report` is its own connector, `ci`, because a connector has one `target.adapter` and the ref of `ci.report` is a run (`runner`). Its act is still on GitHub.

`branch.push` is reached through the git proxy and not through `POST /v0/ops`. The kit writes `surface: op` and a params schema for every operation, and has no command or adapter to bind for a proxy. Its catalog entry stays hand-written, and so does the entry of `pr.push.workflow`.

What the move did not change: every golden file, `docs/manual.md`, the OpenAPI text of each params schema and the manual entry of each operation are the same bytes as before. The entries are in the same order in `api/manual.yaml`; in `api/openapi.yaml` the `ParamsPr*` blocks follow the same order now (the three issue blocks moved after `ParamsPrFiles`).

### Files touched, for a new GitHub read operation

Take a new read operation, `pr.commits`, that lists the commits of a PR for the orchestrator. The counts are the files a person edits. The "with the kit" column was checked by declaring the operation and running the tests: they fail until the pin, the regeneration, the baseline rule and the adapter exist, and nothing else.

| File | Before | With the kit |
| --- | --- | --- |
| `internal/gh/pulls.go`, its test | by hand (the GitHub call) | by hand |
| `internal/ops/pr_read.go`, its test | by hand: the adapter, the name, the `PRReadOps` list, the allowed params | by hand: the adapter, the name, the `PRReadOps` list. The allowed params are the declared ones |
| `cmd/chap/prread.go` | by hand: the command and the printing | by hand: the printing only |
| `cmd/chap/ops.go` | by hand: the table entry | not touched |
| `api/manual.yaml`, `api/openapi.yaml` | by hand | generated |
| `githubspec/spec.go` | not there | by hand: the declaration and one name in `Connector.Ops` |
| `declared_test.go` | not there | by hand: the pin |
| `internal/policy/data/baseline.yaml` | by hand | by hand (the rate must equal the declared one) |
| `internal/policy/policy_test.go` | by hand, when the op is turned on | the same |
| `cmd/chap/golden_test.go`, the canned reply | by hand | by hand (optional: the generic command is tested once) |
| `docs/manual.md`, `help.golden`, the new golden file | by command | by command |

**Before: 12 files by hand, 3 by command. With the kit: 11 by hand, 5 by command** (the two `api/` files move from "by hand" to "by command"; the declaration and the pin are new). The count hardly moves, because most of the files are logic: the GitHub call, the adapter, the printing and their tests. What moved is the number of places where the same facts are typed: name, class, summary, usage line, rate, params and their bounds were typed in `ops.go`, `manual.yaml`, `openapi.yaml`, the command in `prread.go` and the key list in `pr_read.go` (five places). They are typed once now, in the declaration, with the pin as the deliberate second copy of the class.

Without a declaration the new adapter is refused as well: `kit.Bind` stops `chapd` at start-up when a declared operation has no adapter, or an adapter has no declaration.

## What is not covered yet

- **Google is not migrated.** Its operations are declared by hand in the old places.
- **The kit cannot express a surface other than `op`.** `branch.push` and `pr.push.workflow` (the git proxy) have no declaration.
- **The kit cannot express a default that the schema does not have.** `pr merge --base main` and `pr open --base main` are command defaults and not schema defaults, so those two commands stay custom. The same holds for a param that is read from git (`pr open --branch`).
- **The kit cannot express an enum, a one-of or a nested object** in a params schema.
- **The kit declares the per-minute rate only.** The baseline also has per-hour rates for the GitHub reads and issues, and no test compares them with the declaration.
- **`Unbounded` strings.** The schemas of `head` and `base` in `pr.open` and `base` in `pr.merge` have no `maxLength`, as before; the adapters cap them (250 bytes in `pr.open`). The declaration says `Unbounded` so the gap shows. Adding a `maxLength` is a change of the contract and was not made here.
- **The command line is stricter than the schema for a sha.** The reads accept a 40 or a 64 character sha in the schema; the command accepts the 40 character one (`Param.CLIPattern`). That is how it was.
- **Order of two simultaneous usage errors.** The generic command checks the params in the order they are declared, which is the order of the schema. For `pr files` that means `--page` and `--per-page` are checked before `--expected-head`; the hand-written command checked `--expected-head` first. It matters only when two flags are wrong at once.
- **An unknown param is refused with the declared names in declaration order.** The refusal of `pr.files` lists `page, per_page, expected_head_sha`; it listed `expected_head_sha, page, per_page`.
- **Description quoting.** The generator writes a params description plain when it is short and plain, and in double quotes otherwise (over 160 characters, or a character that YAML reads specially). This is the rule that gives the bytes the hand-written text had.
- **No scaffold command.** `chap connector new <name>` does not exist. A new connector is copied from `linear` and `linearspec` by hand.
- **No conformance suite.** The rules above are tested by each connector for itself. A shared suite (`Check` changes nothing, `Execute` twice acts once, no secret in any output, untrusted marking, every refusal has a known cause code) is milestone 2.3.
- **Shared helpers are not shared.** The HTTP client that never logs a credential, the rate limit and retry code, and the text cleaning (`clean`, `checkText`) live in `linear`. Other connectors have their own copies.
- **The baseline is still edited by hand.** A new operation needs its one baseline line. This is deliberate for the switch that turns an operation on, but the line for a new, disabled operation could be added by the generator. *Decided for now:* no generation of the baseline, and the rate stays written in both the declaration and the baseline, with a test that they agree. The owner has not answered yet.
- **Approval card text.** An adapter adds evidence to a card in `Check`. The declaration does not describe it.
- **`api/openapi.yaml` and `api/manual.yaml` need a regeneration step.** Go does not run `go generate` during `go build`; the tests catch a missed run.
