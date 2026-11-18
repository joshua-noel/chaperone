package runtoken

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// MaxInterimSeconds is the longest an interim token may live (ADR-005: "exp at
// most 2 hours").
const MaxInterimSeconds = 2 * 60 * 60

// HostInterimCeiling is the op ceiling of the host-interim profile (ADR-005):
// the routine and gated kinds of spec section 5 plus the high-class kinds,
// which always need an approval. It leaves out every critical kind
// (approvers.enroll, policy.activate, repo.settings, host.scripts.refresh) and the
// secrets.* family: an agent token never asks for them. It matches the
// host-interim profile of the policy baseline for every op it names. A
// key-set entry may narrow this list, never widen it.
var HostInterimCeiling = []string{
	"pr.open", "pr.update", "pr.merge", "branch.push", "health", "logs",
	"deploy", "data.apply", "mail.send", "drive.share", "notion.write",
}

// maxKeySetBytes bounds the key-set file: a pinned set is a handful of keys.
const maxKeySetBytes = 64 << 10

var (
	kidRe             = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	runnerIssuerRe    = regexp.MustCompile(`^runner\.[a-z0-9][a-z0-9._-]{0,62}$`)
	chaperoneIssuerRe = regexp.MustCompile(`^chaperone\.[a-z0-9][a-z0-9._-]{0,62}$`)
)

// InterimLimits are the restrictions of an interim issuer key (ADR-005).
type InterimLimits struct {
	MaxSeconds int64    // longest exp - iat; at most MaxInterimSeconds
	Ops        []string // op ceiling; a subset of HostInterimCeiling
}

// Key is one pinned issuer key.
type Key struct {
	KID    string
	Issuer string // the only iss this key may sign for
	Public ed25519.PublicKey
	// Interim is non-nil for the interim issuer's key: it signs isolation
	// "host" tokens under these limits and only while the key set allows
	// interim tokens. Every other key signs runner.* tokens and control
	// tokens.
	Interim *InterimLimits
}

// KeySet is the pinned set of issuer keys. It is immutable: keys never come
// from a token, and changing the set (L1-18 flips AllowInterim at cut-over)
// means writing the file and restarting chapd.
type KeySet struct {
	keys         map[string]*Key
	allowInterim bool
	digest       string
}

// Lookup returns the key pinned under kid.
func (s *KeySet) Lookup(kid string) (*Key, bool) {
	k, ok := s.keys[kid]
	return k, ok
}

// AllowInterim reports the allow_interim flag: false rejects every interim
// token and stops the interim issuer.
func (s *KeySet) AllowInterim() bool { return s.allowInterim }

// Digest is "sha256:<hex>" of the file the set was parsed from, for the
// ledger and for `chap doctor`.
func (s *KeySet) Digest() string { return s.digest }

type keyFile struct {
	Version      int        `json:"version"`
	AllowInterim *bool      `json:"allow_interim"`
	Keys         []keyEntry `json:"keys"`
}

type keyEntry struct {
	KID       string        `json:"kid"`
	Issuer    string        `json:"issuer"`
	PublicKey string        `json:"public_key"` // base64url, 32 bytes
	Interim   *interimEntry `json:"interim,omitempty"`
}

type interimEntry struct {
	MaxSeconds int64    `json:"max_seconds,omitempty"`
	Ops        []string `json:"ops,omitempty"`
}

// LoadKeySet reads and parses the pinned key-set file.
func LoadKeySet(path string) (*KeySet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("runtoken: key set: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxKeySetBytes+1))
	if err != nil {
		return nil, fmt.Errorf("runtoken: key set: %w", err)
	}
	return ParseKeySet(data)
}

// ParseKeySet parses a key set:
//
//	{"version": 1, "allow_interim": true, "keys": [
//	  {"kid": "runner-1", "issuer": "runner.host-1", "public_key": "<base64url, 32 bytes>"},
//	  {"kid": "interim-1", "issuer": "chaperone.interim", "public_key": "...",
//	   "interim": {"max_seconds": 7200, "ops": ["pr.open"]}}]}
//
// It refuses what it does not understand: duplicate or unknown members, an
// absent allow_interim, a kid or issuer of the wrong shape, an interim key
// with a runner.* issuer or a runner key with a chaperone.* issuer, two
// entries with the same kid or the same key, a public key that is not 32
// bytes, and interim limits that widen the ceiling.
func ParseKeySet(data []byte) (*KeySet, error) {
	if len(data) > maxKeySetBytes {
		return nil, fmt.Errorf("runtoken: key set is larger than %d bytes", maxKeySetBytes)
	}
	if _, err := spec.ParseStrict(data); err != nil {
		return nil, fmt.Errorf("runtoken: key set: %w", err)
	}
	var f keyFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("runtoken: key set: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("runtoken: key set version %d is not supported (want 1)", f.Version)
	}
	if f.AllowInterim == nil {
		return nil, fmt.Errorf("runtoken: key set: allow_interim must be present (true or false)")
	}
	sum := sha256.Sum256(data)
	set := &KeySet{
		keys:         make(map[string]*Key, len(f.Keys)),
		allowInterim: *f.AllowInterim,
		digest:       "sha256:" + hex.EncodeToString(sum[:]),
	}
	seenPub := map[string]string{}
	for i, e := range f.Keys {
		k, err := e.key()
		if err != nil {
			return nil, fmt.Errorf("runtoken: key set: keys[%d]: %w", i, err)
		}
		if _, dup := set.keys[k.KID]; dup {
			return nil, fmt.Errorf("runtoken: key set: keys[%d]: duplicate kid %q", i, k.KID)
		}
		if other, dup := seenPub[string(k.Public)]; dup {
			return nil, fmt.Errorf("runtoken: key set: keys[%d]: kid %q repeats the public key of %q", i, k.KID, other)
		}
		seenPub[string(k.Public)] = k.KID
		set.keys[k.KID] = k
	}
	return set, nil
}

func (e keyEntry) key() (*Key, error) {
	if !kidRe.MatchString(e.KID) {
		return nil, fmt.Errorf("kid %q must match %s", e.KID, kidRe)
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(e.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("kid %q: public_key is not unpadded base64url: %w", e.KID, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("kid %q: public_key is %d bytes, an Ed25519 key is %d", e.KID, len(pub), ed25519.PublicKeySize)
	}
	k := &Key{KID: e.KID, Issuer: e.Issuer, Public: ed25519.PublicKey(pub)}
	if e.Interim == nil {
		if !runnerIssuerRe.MatchString(e.Issuer) {
			return nil, fmt.Errorf("kid %q: issuer %q must match %s (an interim key has an \"interim\" member)", e.KID, e.Issuer, runnerIssuerRe)
		}
		return k, nil
	}
	if !chaperoneIssuerRe.MatchString(e.Issuer) {
		return nil, fmt.Errorf("kid %q: interim issuer %q must match %s", e.KID, e.Issuer, chaperoneIssuerRe)
	}
	chap := &InterimLimits{MaxSeconds: e.Interim.MaxSeconds, Ops: slices.Clone(e.Interim.Ops)}
	if chap.MaxSeconds == 0 {
		chap.MaxSeconds = MaxInterimSeconds
	}
	if chap.MaxSeconds < 1 || chap.MaxSeconds > MaxInterimSeconds {
		return nil, fmt.Errorf("kid %q: interim max_seconds %d must be 1..%d", e.KID, chap.MaxSeconds, MaxInterimSeconds)
	}
	if chap.Ops == nil {
		chap.Ops = slices.Clone(HostInterimCeiling)
	}
	for _, op := range chap.Ops {
		if !slices.Contains(HostInterimCeiling, op) {
			return nil, fmt.Errorf("kid %q: interim op %q is outside the host-interim ceiling", e.KID, op)
		}
	}
	k.Interim = chap
	return k, nil
}
