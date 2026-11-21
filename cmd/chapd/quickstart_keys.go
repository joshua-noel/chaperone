package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/joshua-noel/chaperone/internal/keys"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/policy"
)

// The playground gives the agent a KEY, not the orchestrator's token (ADR-008, "the agent asks, you tap").
//
// The flow, and why:
//
//  1. The operator makes the first passkey (as before).
//  2. The agent enrols itself: `chap agent enrol --label playground-agent --project playground --out <folder>/agent.key`
//     prints a short code; the operator types it at Agents and signs the enrolment card with the passkey just made.
//     The agent then holds a REQUEST-ONLY key: no access at all, it can only ask.
//  3. The agent asks for what it needs: `chap key request --ops pr.checks,pr.diff,pr.files,pr.view --repo
//     playground/storefront ...`. The operator answers at Agents and signs the card. The key in the file is replaced
//     by one that can read the playground pull requests.
//
// The quickstart does NOT make a key itself. A key that no person approved would be a grant out of nowhere: the first
// approver and the orchestrator token are bootstrapped by an operator-recorded op, which is not an approval, and the
// design has no sanctioned path for a key without a card. So the quickstart only prints the commands, `chap` writes the
// key file (internal/privfile: private from the moment it exists), and chapd only READS the file at start to say what
// state the agent's key is in.
//
// What a key can do here: read the four pull-request ops on playground/storefront, and ask. It can never hold
// pr.merge (the key ceiling, internal/ops/keyceiling.go, is the four pull-request reads, health, logs and deploy, and is
// not widened for the demo). The merge demo, "an action that needs your approval", is therefore run with the
// ORCHESTRATOR token, in the operator's own terminal: the human plays the orchestrator, which is the role that holds
// pr.merge in the real design. The output says so.

const (
	quickstartKeyFile   = "agent.key"
	quickstartKeyLabel  = "playground-agent"
	quickstartKeyTTL    = "8h"
	quickstartKeyReason = "read the playground pull requests"
)

// quickstartKeyOps are the ops the printed `chap key request` asks for: the four pull-request reads, all routine.
var quickstartKeyOps = []string{"pr.checks", "pr.diff", "pr.files", "pr.view"}

// keyOpsOn are the key operations the PLAYGROUND turns on. They stay off in the shipped baseline (and in the Windows
// service and `chapd run`): only this command's chapd, which knows the one project "playground", has them on.
var keyOpsOn = []string{"keys.issue", "keys.request", "keys.extend"}

// quickstartBaseline is the shipped baseline pack with keys.issue, keys.request and keys.extend turned on. A project
// file cannot turn an op on (the baseline does that), so the quickstart's own chapd gets its own copy of the pack. It
// fails closed: an op that is not found switched off, or an extra change, is an error, not a silent no-op.
func quickstartBaseline(shipped []byte) ([]byte, error) {
	out := shipped
	for _, op := range keyOpsOn {
		re := regexp.MustCompile(`(?m)^(\s*` + regexp.QuoteMeta(op) + `:\s*\{\s*)enabled:\s*false`)
		if len(re.FindAll(out, -1)) != 1 {
			return nil, fmt.Errorf("quickstart: the baseline pack does not have %s switched off exactly once", op)
		}
		out = re.ReplaceAll(out, []byte("${1}enabled: true"))
	}
	return out, nil
}

// agentKeyState is what the agent's key file says at start.
type agentKeyState struct {
	Kind    string    // none, request-only, ready, ended
	Why     string    // for ended: expired, revoked, stopped, unknown or unreadable
	Expires time.Time // of a live key
	Ops     []string  // of a live key
	Label   string    // the label the printed enrolment command uses
}

// inspectAgentKey reads the key file in the quickstart folder (already trusted by prepareQuickstartFolder: owner and
// permissions) and asks chapd's key store what the key is. It never prints or logs the key. An ended key (expired,
// revoked, stopped by a human, or one this database does not know) leaves the file in place: retireEndedKey removes it
// so that `chap agent enrol --out` can create it again.
func inspectAgentKey(ctx context.Context, app *App, path string) (agentKeyState, error) {
	label, err := nextAgentLabel(ctx, app.DB.SQL())
	if err != nil {
		return agentKeyState{}, err
	}
	st := agentKeyState{Kind: "none", Label: label}
	raw, err := readSmallFile(path, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return agentKeyState{Kind: "ended", Why: "unreadable", Label: label}, nil
	}
	tok := strings.TrimSpace(string(raw))
	who, err := app.Keys.VerifyKey(ctx, tok)
	var ve *ops.VerifyError
	switch {
	case errors.As(err, &ve):
		why := "unknown"
		switch ve.Code {
		case ops.CodeTokenExpired:
			why = "expired"
		case ops.CodeTokenRevoked:
			why = "revoked"
			if strings.Contains(ve.Detail, keys.StoppedWhy) {
				why = "stopped"
			}
		}
		return agentKeyState{Kind: "ended", Why: why, Label: label}, nil
	case err != nil:
		return agentKeyState{}, err
	}
	if who.Project != quickstartProject {
		return agentKeyState{Kind: "ended", Why: "unknown", Label: label}, nil // a key of another project is not this agent's
	}
	st.Expires, st.Ops, st.Label = who.Expires, slices.Clone(who.KeyOps), who.KeyHolder
	st.Kind = "ready"
	if len(who.KeyOps) == 0 {
		st.Kind = "request-only"
	}
	return st, nil
}

// readSmallFile reads at most max bytes of a regular file.
func readSmallFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

// retireEndedKey removes the key file of an ended key. The key is dead; the file is in the quickstart's own private
// folder, and a regular file the user owns (the folder check ran). Nothing is removed that is not a plain file.
func retireEndedKey(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a plain file", path)
	}
	if err := checkTrusted(path); err != nil {
		return err
	}
	return os.Remove(path)
}

// nextAgentLabel is the label the printed enrolment uses: the playground's own, or, when a human has stopped that agent
// (Agents -> Revoke: it can never be enrolled again), the first of playground-agent-2, -3 ... that is not stopped.
func nextAgentLabel(ctx context.Context, db *sql.DB) (string, error) {
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT label FROM key_agents`)
	if err != nil {
		return "", fmt.Errorf("quickstart: read stopped agents: %w", err)
	}
	defer rows.Close()
	stopped := map[string]bool{}
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			return "", err
		}
		stopped[l] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	label := quickstartKeyLabel
	for n := 2; stopped[label]; n++ {
		label = quickstartKeyLabel + "-" + strconv.Itoa(n)
		if n > 99 {
			return "", errors.New("quickstart: ninety-nine agents of this folder were stopped: use a new --dir")
		}
	}
	return label, nil
}

// policyBaselineShipped is the baseline pack as shipped (a function so a test can assert nothing turned it on).
func policyBaselineShipped() []byte { return policy.BaselineBytes() }
