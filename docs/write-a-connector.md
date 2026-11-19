# Write a connector

This page is a walkthrough. You add a read-only connector for a simple HTTP service. You go from an empty folder to a passing conformance suite. Then you do the steps that stay by hand.

You need a clone of this repository and the Go toolchain. You do not need to know the code. [Writing a connector](connectors.md) says what the kit is and which rules a connector follows. Read it after this page, or when a step here sends you to it.

The example service is called `notes`. It has one route:

```
GET /items/<id>     answers  {"id": "...", "title": "...", "body": "..."}
```

The request carries the header `Authorization: Bearer <token>`. Use your own name where `notes` appears. A name is 2 to 20 lower-case letters and digits, and it starts with a letter.

## 1. Make the skeleton

Run this in the root of the clone:

```
go run ./internal/connectors/scaffold notes
```

The tool writes six files and prints the steps that stay by hand. It changes no file that exists. It registers nothing and turns nothing on. If `internal/connectors/notes` exists, it stops.

| File | What it is |
| --- | --- |
| `internal/connectors/notes/notesspec/spec.go` | The declaration: the facts about each operation, typed once. |
| `internal/connectors/notes/adapter.go` | The adapter: `Check` and `Execute` of each operation, and the checks that every request passes. |
| `internal/connectors/notes/client.go` | A small HTTP client. It sends the credential in one header. Its errors never hold the credential or text from the service. |
| `internal/connectors/notes/notestest/server.go` | A fake of the service for the tests. |
| `internal/connectors/notes/conformance_test.go` | The test. It calls the conformance suite. |
| `internal/connectors/notes/doc.go` | The package comment. |

The tool is a `go run` command and not a `chap` command. `chap` is the client that an agent runs. It must stay small, and it must not have a verb that writes source files. Writing a connector is the work of a developer in a clone.

## 2. Run the suite on the skeleton

```
go test ./internal/connectors/notes/...
```

The test fails. Every failure says `is not implemented yet`. That is the skeleton working: the adapter of the example operation refuses every valid request until you write it. Three checks already pass, because they test what the skeleton does already:

- `no_secret_in_output`
- `refusals_have_a_known_code`
- `class_matches_pin`

To see each check by name, add `-v`.

## 3. Declare the operation

Open `notesspec/spec.go`. The example operation is `notes.show`. Change it to what your operation does. Each field is a fact that is typed here and nowhere else:

| Field | What to write |
| --- | --- |
| `Name` | The op kind, `group.verb`, in lower case. |
| `Class` | `kit.Routine` for a read. Never loosen a class to make a test pass. A class is a policy decision. |
| `Reversibility` | `kit.Reversible` for a read. |
| `Summary`, `Usage` | The catalog line (at most 60 characters) and the command line (at most 100). The usage starts with `chap` and the op name with the dot as a space. |
| `RatePerMinute` | How many calls each caller may make in a minute. The baseline repeats it. |
| `Doc` | What the target must be and what each param means. It becomes the description of the params schema. |
| `Target` | What the operation acts on. The pattern is a check for the command line only: the adapter checks the ref again. |
| `Params` | The allowed params, with their kinds and limits. The adapter refuses any other name. |

The example needs no change to run the rest of this page.

## 4. Write Check and Execute

Open `adapter.go`. Everything above the line `written by hand from here` is done: the refusals, the check of the caller, the target and the params, and the cleaning of text. Below that line are two methods that refuse. Delete them and put these in their place:

```go
// guide:show-implementation
// Check validates the request. It reads nothing and changes nothing.
func (a *showAdapter) Check(_ context.Context, r *ops.Request) (ops.CheckResult, error) {
	p, err := a.parse(r)
	if err != nil {
		return ops.CheckResult{}, err
	}
	return ops.CheckResult{Checks: []ops.Check{{Name: "item", Passed: true, Detail: p.id}}}, nil
}

// Execute reads the item and returns it. A read changes nothing, so every
// failure is a failed outcome and the caller may ask again.
func (a *showAdapter) Execute(ctx context.Context, r *ops.Request) (ops.Outcome, error) {
	p, err := a.parse(r)
	if err != nil {
		return failed(err), nil
	}
	item, err := a.cfg.Client.Item(ctx, p.id)
	switch {
	case errors.Is(err, ErrNotFound):
		return failed(paramsInvalid("the service has no item %s", p.id)), nil
	case err != nil:
		return failed(err), nil
	}
	res := map[string]any{"untrusted_text": true, "id": clean(item.ID, maxID)}
	if a.looksSecret(item.Title, item.Body) {
		res["title"], res["withheld"] = withheld, true
	} else {
		res["title"] = clean(item.Title, maxTitle)
		if p.detail {
			res["body"] = clean(item.Body, maxBody)
		}
	}
	return ops.Outcome{Result: res, ExternalRef: clean(item.ID, maxID)}, nil
}
```

What each part does:

- `a.parse(r)` is the one place a request is validated. `Check` and `Execute` both call it. A request that `Check` refuses is refused again when `Execute` runs.
- `Check` reads nothing here. It may read, but it must never write. It runs many times: when the request is made, on a dry run, when an approval is asked for, and when it is released.
- `Execute` calls the service once. The error of the client is a fixed sentence. It holds no credential and no text from the service.
- The result sets `untrusted_text: true`. The title and the body are written by other people. The text is cleaned of control and format characters, cut to a length, and withheld whole when it looks like a secret.
- A refusal is a `*ops.Refusal` with a cause code from `internal/ops/denial.go`. A plain error means "the service could not be asked", and chapd fails closed.

Now run the suite again:

```
go test -v ./internal/connectors/notes/...
```

All seven checks pass for `notes.show`.

## 5. What the seven checks do

The suite drives your real adapter against the fake service. A check fails with a sentence that names the sample and the cause.

| Check | What it proves |
| --- | --- |
| `check_has_no_side_effects` | `Check` sends no write to the fake in three calls, answers the same each time, and does not change the request. |
| `execute_acts_once` | `Execute` twice with one execution id changes the fake once. For a read-only operation it also proves that `Execute` sends no write. |
| `no_secret_in_output` | The credential is in no `CheckResult`, no `Outcome`, no error, no refusal and no log line. The suite makes its own value the credential. It also looks for every credential the fake saw. It runs the samples again against a service that rejects the credential and repeats it in its error text. |
| `refusals_have_a_known_code` | Every refusal your invalid samples cause is a `*ops.Refusal` with a cause code that chapd knows. `Execute` does not act on the same requests. |
| `params_and_limits_are_enforced` | A param that is not declared, a missing required param, a value of the wrong kind and a value past a declared limit are refused. The suite makes these requests from your declaration. It checks `Check` and `Execute`. |
| `service_text_is_untrusted` | Text from the service is cleaned of control and format characters and capped, in the result, in the check lines and in refusals. An operation of the strict kind (`ServiceText`) also marks the result `untrusted_text` and withholds an item that looks like a secret. An operation that says it returns no service text does not echo any. |
| `class_matches_pin` | The class and the reversibility in the declaration are the ones in the table that was written by hand. |

## 6. Write your own samples

`conformance_test.go` holds the samples. For each operation you give:

- `Valid`: requests the adapter must accept. The first one is the base of the generated requests that break a limit, so give it every optional param.
- `Invalid`: requests that `Check` must refuse. Give each refusal the adapter makes by hand, with the cause code you expect.
- `ReadOnly`: `true` for an operation that never writes. The suite then fails the operation if `Execute` sends a write.
- `Text`: `conformance.ServiceText` when the result holds text the service wrote and you follow rule 5 in full (clean, cap, mark `untrusted_text`, withhold an item that looks like a secret); `conformance.CleanedText` when the text is part of the answer and you clean and cap it, as the GitHub adapters do for a path in a check line (the front ends mark the result and chapd redacts it as a whole); `conformance.NoServiceText` when the result holds none.
- `Plant`: how to put hostile text in the fake where the first valid sample reads it.

The fake is yours too. Make `notestest/server.go` answer what your service answers. Count every call that changes state in `WriteCalls`, and in `WritesApplied` only when the fake acts on it.

An operation that writes needs more. See [A write operation](#a-write-operation).

## 7. The steps that stay by hand

The tool does not do these. Each one is a decision.

1. **Pin the class.** Add the operation to `internal/connectors/pintable/pintable.go`. Write its class and reversibility out again. Then, in `conformance_test.go`, delete the local `pins` and pass `pintable.Pins`. This table is the second copy of a class. A change of class needs an edit to the declaration, to the generated manual entry and to this table, all in one reviewed change.
2. **Register the declaration.** In `internal/connectors/declared/declared.go`, add the import of `notesspec` and add `notesspec.Connector` to the list that `Connectors()` returns. Then run:

   ```
   go generate ./internal/connectors/...
   go run ./docs/manualgen
   go test ./cmd/chap -update
   ```

   The first command writes the manual entry in `api/manual.yaml` and the params schema in `api/openapi.yaml`. The second rewrites `docs/manual.md`. The third records the help line of the new command. Read the diff of each file.
3. **Wire the adapters into chapd.** Copy `installLinear` in `cmd/chapd/linear.go`. Build the client from the vault: read the token with `a.vault.Use`, and pass `a.Reg` as the `Registry` so the redaction check learns the token. Call `notes.Adapters`. Add the adapters to the map. `kit.Bind` stops chapd at start-up when a declared operation has no adapter, or an adapter has no declaration.
4. **Add the baseline rule, off.** In `internal/policy/data/baseline.yaml`, add one line for each operation. The rate must be the declared one:

   ```
   notes.show: { enabled: false, rate_per_minute: 12 }
   ```

   The operation stays off. Turning it on is a separate, reviewed policy change. That change also adds the name to `shippedEnabled` in `internal/policy/policy_test.go`.
5. **Run the tests that look at the whole:**

   ```
   go test ./internal/connectors/... ./cmd/chap ./cmd/chapd ./internal/policy ./internal/mcpfront ./docs/manualgen
   ```

Nothing in the first three steps changes what chapd does, until step 3 is merged. Nothing runs until step 4 is turned on.

## A write operation

A write needs these changes to the example:

- Set `Class` and `Reversibility` for what the write does. An operation that changes something outside Chaperone and cannot be undone is `kit.High` and needs the operator's approval every time. The declaration refuses an irreversible operation that is routine or gated.
- Drop `ReadOnly: true` from the samples. Give a valid sample that writes. The suite needs one, or `execute_acts_once` proves nothing and says so.
- Make the write safe to repeat. After a crash chapd does not run an operation again, but your adapter must still derive any id it sends from `Request.ExecutionID`, so the service refuses a repeat. Linear does this for comments (`linear.CommentID`). An operation that sends nothing when the request is a no-op (a move to the state the item is already in) needs no id.
- If the service has no way to refuse a repeat, say so in `NotRepeatable` with the reason. The suite then checks that the declaration is true: the second `Execute` must change the fake again. A stale declaration fails.
- Read the facts again in `Execute`, before the write. `Check` ran earlier.
- Send a write at most once. A definite refusal by the service is a `failed` outcome. An answer that does not show whether the service acted is `unconfirmed`, and the result says what to look up. Never retry a write in the adapter.
- Count the write route in the fake, in `WriteCalls` and in `WritesApplied`.

## When a check cannot pass yet

Put the check in `Known` of the operation, with the reason:

```go
Known: map[conformance.CheckID]string{
	conformance.CheckServiceText: "the result has no untrusted_text flag yet",
},
```

The suite still runs the check. It reports the gap as a skip, with what the check found. When the gap closes, the suite fails and tells you to remove the entry. Use this for a gap that you can name and that a reviewer can read. Do not use it to hide a defect.

## What the suite does not prove

The suite tests your adapter against a fake that you wrote. It does not prove:

- **That the class is right.** It proves that the declaration equals the pin. It does not look at what the operation does. A write declared routine passes, if both say routine.
- **That the real service behaves like the fake.** A fake is your reading of the service. Check the real service by hand once, with a token that can do no harm.
- **That the credential is safe in every place.** It looks in what the adapter returns, in the log output of the default loggers, and in `Rig.Logs`. It does not look in a log that goes elsewhere, in the memory of the process, or in the ledger.
- **That a hostile service cannot trick the adapter.** It tries one: a service that rejects the credential and repeats it. Other tricks are for your own tests.
- **That text is safe to show.** It checks control and format characters, length, and (for the strict kind) text shaped like a secret. It does not judge what the words say. A hostile instruction in a title is still an instruction. The front ends put results behind a notice, and chapd and the operator decide what runs next.
- **That `Check` leaves nothing behind.** It counts writes. A token that the adapter mints and does not revoke is not a write, and the suite does not see it.
- **That the adapter is idempotent against the real service.** It proves it against the fake. The fake only refuses a repeat if you wrote it to.
- **Limits that the declaration cannot express.** A `Pattern`, a string with `Unbounded`, a ref with a shape of its own, a policy that depends on the project: write `Invalid` samples for these.
- **That the operation is on, or allowed.** The baseline and the policy decide that.

The suite also made findings against Linear and GitHub. They are fixed, except three repeat-safety gaps that are declared `NotRepeatable` in `internal/connectors/github/conformance_test.go`: see [What the conformance suite found](connectors.md#what-the-conformance-suite-found). The `Known` lists of both connectors are empty.
