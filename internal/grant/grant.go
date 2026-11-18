// Package grant defines the execution grant: the signed message with which
// chapd lets chap-host run one allowlisted runbook on the host, once.
//
// A grant is an Ed25519 signature by chapd over a fixed set of fields: the op
// and its op_hash, who asked (a run or the orchestrator), the runbook name, the
// SHA-256 of the script the runbook may run, the runbook's arguments (checked
// against a fixed schema, see [RunbookSpec]), a single-use nonce, and an expiry of
// at most five minutes. chap-host trusts nothing else: it pins chapd's public
// key, verifies with [Verifier], and compares script_sha256 with the file it is
// about to run.
//
// Wire form (one ASCII string, at most 4096 bytes):
//
//	lg1.<base64url(payload)>.<base64url(signature)>
//
// The payload is a JSON object with exactly the fields of [Grant] (no unknown
// field). The signature is Ed25519 over "chaperone.exec-grant.v1\x00" followed by
// the payload bytes exactly as transmitted, so there is no canonicalization
// step to get wrong, and the domain prefix keeps a signature made for another
// purpose with the same key from being accepted as a grant. Unpadded base64url
// (RFC 4648 section 5) is used throughout.
//
// The package imports nothing from the vault or the store: the signer is
// chapd's concern, the verifier runs in the user session and holds only a public
// key.
package grant

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	// Version is the only payload version.
	Version = 1

	// MaxLifetime is the longest allowed distance between iat and exp.
	MaxLifetime = 5 * time.Minute

	// MaxClockSkew is how far in the future iat may be. exp gets no leeway.
	MaxClockSkew = 30 * time.Second

	// MaxTokenBytes bounds the wire form before anything is parsed.
	MaxTokenBytes = 4096

	tokenPrefix = "lg1"
	sigDomain   = "chaperone.exec-grant.v1\x00"
	hashPrefix  = "sha256:"
)

// Grant is the signed payload. All fields are required; exactly one of RunID
// and OrchestratorID is set.
type Grant struct {
	Version int `json:"v"`
	// Op is the op name; it must equal the runbook's op in [Lookup].
	Op string `json:"op"`
	// OpHash is the spec op_hash of the approved request, "sha256:<64 hex>".
	OpHash string `json:"op_hash"`
	// RunID is the requesting run (spec run_id). Empty for the orchestrator.
	RunID string `json:"run_id,omitempty"`
	// OrchestratorID is the requesting orchestrator (ADR-007). Empty for a run.
	OrchestratorID string `json:"orchestrator_id,omitempty"`
	// Runbook is the fixed runbook name, a name known to [Lookup].
	Runbook string `json:"runbook"`
	// ScriptSHA256 is "sha256:<64 hex>" of the exact script bytes to run.
	ScriptSHA256 string `json:"script_sha256"`
	// Args are the runbook's arguments; names and value shapes come from the
	// runbook's schema, nothing else is accepted.
	Args map[string]string `json:"args"`
	// Nonce is random, single use, 22 to 64 characters of [A-Za-z0-9_-]
	// (the spec's nonce shape).
	Nonce string `json:"nonce"`
	// IssuedAt and ExpiresAt are Unix seconds.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// Expiry returns exp as a time.
func (g *Grant) Expiry() time.Time { return time.Unix(g.ExpiresAt, 0) }

var (
	hashRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	runIDRe  = regexp.MustCompile(`^r-[0-9a-z]{4,32}$`)
	orchIDRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
	nonceRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
)

// Validate checks the shape of g: version, field patterns, runbook and op
// agreement, arguments against the runbook's schema, and the lifetime bound.
// It does not look at the clock; [Verifier] does.
func (g *Grant) Validate() error {
	if g.Version != Version {
		return fmt.Errorf("version %d, want %d", g.Version, Version)
	}
	spec, ok := Lookup(g.Runbook)
	if !ok {
		return fmt.Errorf("runbook %q is not in the allowlist", g.Runbook)
	}
	if g.Op != spec.Op {
		return fmt.Errorf("op %q does not belong to runbook %q", g.Op, g.Runbook)
	}
	if !hashRe.MatchString(g.OpHash) {
		return errors.New("op_hash is not sha256:<64 lowercase hex>")
	}
	if !hashRe.MatchString(g.ScriptSHA256) {
		return errors.New("script_sha256 is not sha256:<64 lowercase hex>")
	}
	switch {
	case g.RunID != "" && g.OrchestratorID != "":
		return errors.New("run_id and orchestrator_id are both set")
	case g.RunID != "":
		if !runIDRe.MatchString(g.RunID) {
			return errors.New("run_id has the wrong shape")
		}
	case g.OrchestratorID != "":
		if !orchIDRe.MatchString(g.OrchestratorID) {
			return errors.New("orchestrator_id has the wrong shape")
		}
	default:
		return errors.New("neither run_id nor orchestrator_id is set")
	}
	if !nonceRe.MatchString(g.Nonce) {
		return errors.New("nonce has the wrong shape")
	}
	if err := spec.checkArgs(g.Args); err != nil {
		return err
	}
	if g.ExpiresAt <= g.IssuedAt {
		return errors.New("exp is not after iat")
	}
	if time.Duration(g.ExpiresAt-g.IssuedAt)*time.Second > MaxLifetime {
		return fmt.Errorf("exp is more than %v after iat", MaxLifetime)
	}
	return nil
}

// HashBytes returns the tagged hash "sha256:<hex>" of b, the form used for
// OpHash and ScriptSHA256.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hashPrefix + hex.EncodeToString(sum[:])
}

// SameHash reports whether two tagged hashes are equal. Both must be well
// formed; a malformed value never matches.
func SameHash(a, b string) bool {
	return hashRe.MatchString(a) && a == b
}

// Requester returns "run:<id>" or "orchestrator:<id>" for logs.
func (g *Grant) Requester() string {
	if g.RunID != "" {
		return "run:" + g.RunID
	}
	return "orchestrator:" + g.OrchestratorID
}
