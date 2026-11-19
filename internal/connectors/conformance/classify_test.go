package conformance

import (
	"strings"
	"testing"
)

// Known skips a check only when every problem is the named one.
func TestKnownSkipsOnlyTheNamedProblem(t *testing.T) {
	op := Op{Known: map[CheckID]Gap{CheckNoSecretInOutput: {Reason: "the error text is relayed", Match: "error text"}}}
	id := CheckNoSecretInOutput

	if errs, skip := classify(op, id, []string{"a: Check (error text) holds a credential"}); len(errs) != 0 || !strings.Contains(skip, "known gap") {
		t.Errorf("the known problem alone: errs %v skip %q", errs, skip)
	}
	errs, skip := classify(op, id, []string{"a: Check (error text) holds a credential", "the captured log output holds a credential"})
	if skip != "" || len(errs) == 0 || !strings.Contains(errs[0], "log output") {
		t.Errorf("a new problem beside the known one must be an error: errs %v skip %q", errs, skip)
	}
	if errs, _ := classify(op, id, nil); len(errs) != 1 || !strings.Contains(errs[0], "now passes") {
		t.Errorf("a closed gap must be an error: %v", errs)
	}
	if errs, skip := classify(op, CheckNoSideEffects, []string{"x"}); len(errs) != 1 || skip != "" {
		t.Errorf("another check is not covered by the entry: %v %q", errs, skip)
	}
}

// NotRepeatable shows as a skip with its reason, and only when the check
// finds nothing wrong.
func TestNotRepeatableIsASkipWithItsReason(t *testing.T) {
	op := Op{NotRepeatable: "no idempotency key"}
	if errs, skip := classify(op, CheckExecuteActsOnce, nil); len(errs) != 0 || !strings.Contains(skip, "no idempotency key") {
		t.Errorf("errs %v skip %q", errs, skip)
	}
	if errs, skip := classify(op, CheckExecuteActsOnce, []string{"stale"}); len(errs) != 1 || skip != "" {
		t.Errorf("a stale declaration must fail: %v %q", errs, skip)
	}
	if _, skip := classify(op, CheckNoSideEffects, nil); skip != "" {
		t.Errorf("only the idempotency check is skipped: %q", skip)
	}
}
