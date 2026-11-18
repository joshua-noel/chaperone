package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/joshua-noel/chaperone/internal/ledger"
	"github.com/joshua-noel/chaperone/internal/notify"
	"github.com/joshua-noel/chaperone/internal/ops"
	"github.com/joshua-noel/chaperone/internal/runtoken"
)

// Ticket L1-21: the JSONL export schedule and the anchors (ADR-006 "Anchors").
//
// It is off unless -ledger-key-secret is set. Then chapd, every minute:
// exports new ledger events to <export-dir>/<chain>/<day>.jsonl, writes a
// ledger.anchor event daily and after each finished deploy, signs it with the
// ledger key, appends the record to <export-dir>/anchors/<chain>.jsonl (in the
// nightly backup set) and pushes it to the operator's phone through ntfy, and
// raises an alert (alerts.ps1) when no export or no anchor was delivered for
// 26 hours. `chap ledger verify --anchor` compares the chain with those records.

// anchorConfig holds the flags of L1-21.
type anchorConfig struct {
	// KeySecretID is the vault secret holding the ledger key's Ed25519 seed
	// (`chapd ledger keygen`, then `chapd vault import`).
	KeySecretID string
}

func (c *anchorConfig) register(fs *flag.FlagSet) {
	fs.StringVar(&c.KeySecretID, "ledger-key-secret", "",
		"vault secret id of the ledger key's Ed25519 seed (chapd ledger keygen): turns on the JSONL export schedule and the anchors (needs -vault-dir, -export-dir and -ntfy-topic-secret)")
}

func (c anchorConfig) enabled() bool { return c.KeySecretID != "" }

// anchorSet is the running L1-21 machinery of one chapd.
type anchorSet struct {
	sched  *ledger.Anchors
	signer *ledger.VaultAnchorSigner
	led    *ledger.Ledger
	base   ledgerBackend

	done    chan struct{}
	started atomic.Bool
}

// setupAnchors builds the scheduler. It returns nil, nil when the flag is off.
// ntfy is the phone driver ([notify.Ntfy] built from -ntfy-topic-secret); pass
// a nil interface, not a nil *notify.Ntfy, when there is none. It is required
// when anchors are on, because an anchor that reaches only the
// server proves nothing (the same check ledger.NewAnchors makes).
func (a *App) setupAnchors(ctx context.Context, c anchorConfig, ntfy notify.AnchorNotifier) (*anchorSet, error) {
	if !c.enabled() {
		return nil, nil
	}
	switch {
	case a.vault == nil:
		return nil, errors.New("chapd: -ledger-key-secret needs the vault (-vault-dir)")
	case a.cfg.ExportDir == "":
		return nil, errors.New("chapd: -ledger-key-secret needs -export-dir (the export and the anchor records live there)")
	case ntfy == nil:
		return nil, errors.New("chapd: -ledger-key-secret needs the phone push (-ntfy-topic-secret): an anchor must also reach the phone")
	}
	signer, err := ledger.NewVaultAnchorSigner(ctx, a.vault, c.KeySecretID)
	if err != nil {
		return nil, fmt.Errorf("chapd: ledger key: %w", err)
	}
	var alerts ledger.Alerter
	if d := a.cfg.Deploy; d.AlertsScript != "" {
		ps := d.PowerShell
		if ps == "" {
			ps = filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		}
		alerts = &ops.AlertsScript{PowerShell: ps, Script: d.AlertsScript, Folder: d.AlertsFolder, Log: a.log}
	} else {
		a.log.Warn("ledger anchors: no -alerts-script, so a stale export or anchor is only logged")
	}
	sched, err := ledger.NewAnchors(ledger.AnchorsConfig{
		Ledger: a.Ledger, Signer: signer, Notifier: ntfy, Alerts: alerts, Log: a.log, Now: a.cfg.now,
	})
	if err != nil {
		return nil, err
	}
	a.log.Info("ledger anchors on", "chain", a.Ledger.Chain(), "key_id", signer.KeyID(),
		"public_key", base64.RawURLEncoding.EncodeToString(signer.Public()), "records", ledger.AnchorsPath(a.cfg.ExportDir, a.Ledger.Chain()))
	return &anchorSet{sched: sched, signer: signer, led: a.Ledger, base: ledgerBackend{l: a.Ledger}, done: make(chan struct{})}, nil
}

// start runs the scheduler until ctx ends.
func (s *anchorSet) start(ctx context.Context) {
	s.started.Store(true)
	go func() {
		defer close(s.done)
		s.sched.Run(ctx)
	}()
}

// wait blocks until the scheduler has stopped (it exports once more on the way
// out). Call it after the context ended and before closing the ledger.
func (s *anchorSet) wait() {
	if !s.started.Load() {
		return
	}
	select {
	case <-s.done:
	case <-time.After(15 * time.Second):
	}
}

// backend wraps the ledger backend of the API with `chap ledger verify --anchor`.
func (s *anchorSet) backend() ops.LedgerBackend { return anchoredLedger{ledgerBackend: s.base, set: s} }

// anchoredLedger is the API's ledger backend plus [ops.AnchorVerifier].
type anchoredLedger struct {
	ledgerBackend
	set *anchorSet
}

var _ ops.AnchorVerifier = anchoredLedger{}

const maxProblemText = 300 // LedgerVerdict.problems items

// VerifyAnchors answers POST /v0/ledger/verify with anchor: true. It runs the
// ordinary verify (so the verdict is the whole story), then compares the chain
// with the records chapd keeps and with any the caller supplied (a copy restored
// from the Drive backup is the real check: chapd cannot have edited it).
func (b anchoredLedger) VerifyAnchors(ctx context.Context, req ops.AnchorVerifyRequest) (any, error) {
	var recs []ledger.AnchorRecord
	for i, line := range req.Records {
		r, err := ledger.ParseAnchorRecord([]byte(line))
		if err != nil {
			return nil, &ops.AnchorInputError{Why: "anchor record " + strconv.Itoa(i+1) + ": " + err.Error()}
		}
		recs = append(recs, r)
	}
	keys := []ed25519.PublicKey{b.set.signer.Public()}
	for i, k := range req.Keys {
		pub, err := ledger.ParsePublicKey(k)
		if err != nil {
			return nil, &ops.AnchorInputError{Why: "anchor key " + strconv.Itoa(i+1) + ": " + err.Error()}
		}
		keys = append(keys, pub)
	}
	base, err := b.ledgerBackend.Verify(ctx, req.AgainstExport)
	if err != nil {
		return nil, err
	}
	out, ok := base.(map[string]any)
	if !ok {
		return nil, errors.New("chapd: unexpected ledger verdict")
	}
	rep, err := b.set.led.VerifyAnchors(ctx, recs, keys)
	if err != nil {
		return nil, err
	}
	problems, _ := out["problems"].([]string)
	for _, p := range rep.Problems {
		problems = append(problems, clipText(p.String(), maxProblemText))
	}
	out["problems"] = problems
	out["ok"] = len(problems) == 0
	out["anchors_checked"] = rep.Checked
	if n := rep.Newest; n != nil {
		when := ""
		if ns, err := strconv.ParseInt(n.TimeUnixNano, 10, 64); err == nil {
			when = time.Unix(0, ns).UTC().Format(time.RFC3339)
		}
		out["newest_anchor"] = map[string]any{"anchor_seq": n.AnchorSeq, "head_seq": n.HeadSeq, "head_hash": n.HeadHash, "time": when}
	}
	return out, nil
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// ---- chapd ledger keygen ----------------------------------------------------

const ledgerUsage = `usage: chapd ledger keygen --seed-out PATH

Makes the ledger key that signs anchors (ticket L1-21). The seed is written to
PATH (it must not exist; keygen never overwrites a key). Import it into the
vault as the service account and delete the file:

    chapd vault import --name ledger-key --kind ed25519-seed --file PATH --delete

then start chapd with -ledger-key-secret ledger-key.

The public key is printed. Keep a copy of it somewhere other than the server
(password manager, phone notes): with it, and a copy of the anchor records
from the Drive backup, anyone can check the ledger even if the server is lost.`

// ledgerCmd is `chapd ledger`.
func ledgerCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "keygen" {
		fmt.Fprintln(stderr, ledgerUsage)
		return 2
	}
	fs := flag.NewFlagSet("chapd ledger keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, ledgerUsage) }
	seedOut := fs.String("seed-out", "", "where to write the new key's seed")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *seedOut == "" {
		fs.Usage()
		return 2
	}
	seed, public, err := runtoken.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	// No newline in the seed file: the vault secret must be exactly the seed text.
	if err := writeNew(*seedOut, seed); err != nil {
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	pub, err := ledger.ParsePublicKey(public)
	if err != nil {
		_ = os.Remove(*seedOut)
		fmt.Fprintf(stderr, "chapd: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "ledger public key: %s\nkey id: %s\nseed written to %s: import it into the vault, then delete it\n", public, ledger.KeyID(pub), *seedOut)
	return 0
}
