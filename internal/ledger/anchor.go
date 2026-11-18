package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// AnchorKindOffline is the only anchor kind Phase 1 writes (ADR-006): the head
// is copied to the operator's phone (ntfy) and to the nightly backup set, two
// places chapd cannot edit afterwards.
const AnchorKindOffline = "offline-copy"

const (
	anchorRecordVersion = 1
	// anchorDomain separates the anchor signature from every other use of the
	// ledger key.
	anchorDomain = "chaperone.ledger-anchor.v1\x00"
	// maxAnchorRecordBytes bounds one record line; a real one is under 600.
	maxAnchorRecordBytes = 2 << 10
	anchorsDirName       = "anchors"
)

var (
	hashRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	keyIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)
	sigRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
	nanoRE  = regexp.MustCompile(`^[0-9]{1,19}$`)
)

// AnchorRecord is the off-box copy of one ledger.anchor event: what the phone
// and the backup set hold. It names the head the anchor covers (HeadSeq,
// HeadHash) and the anchor event itself (AnchorSeq, AnchorHash), and carries
// the ledger key's signature over all of it. Rewriting any event up to the
// anchor changes HeadHash (every hash covers its predecessor), so a rewritten
// chain no longer matches a record it did not write.
type AnchorRecord struct {
	Chain        string
	HeadSeq      int64
	HeadHash     string
	AnchorSeq    int64
	AnchorHash   string
	TimeUnixNano string // the anchor event's time, decimal text like the spec's
	KeyID        string // KeyID of the signing public key
	Sig          string // base64url, no padding
}

// AnchorsPath is where chapd keeps the signed records of chain: inside the export
// root, so the nightly backup set that holds the export holds them too.
func AnchorsPath(exportDir, chain string) string {
	return filepath.Join(exportDir, anchorsDirName, chain+".jsonl")
}

func (r AnchorRecord) tree(withSig bool) map[string]any {
	m := map[string]any{
		"v":              float64(anchorRecordVersion),
		"chain":          r.Chain,
		"head_seq":       float64(r.HeadSeq),
		"head_hash":      r.HeadHash,
		"anchor_seq":     float64(r.AnchorSeq),
		"anchor_hash":    r.AnchorHash,
		"time_unix_nano": r.TimeUnixNano,
		"key_id":         r.KeyID,
	}
	if withSig {
		m["sig"] = r.Sig
	}
	return m
}

// signedBytes is what the ledger key signs: a domain tag and the canonical
// (RFC 8785) form of the record without its signature.
func (r AnchorRecord) signedBytes() ([]byte, error) {
	c, err := spec.JCS(r.tree(false))
	if err != nil {
		return nil, err
	}
	return append([]byte(anchorDomain), c...), nil
}

// Line is the record as one canonical JSON line (without the newline).
func (r AnchorRecord) Line() ([]byte, error) { return spec.JCS(r.tree(true)) }

// Verify reports whether Sig is a valid signature by pub over the record.
func (r AnchorRecord) Verify(pub ed25519.PublicKey) bool {
	sig, err := base64.RawURLEncoding.Strict().DecodeString(r.Sig)
	if err != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := r.signedBytes()
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// ParseAnchorRecord reads one record line. The record is a closed shape: an
// unknown member, a wrong type or a malformed value is an error.
func ParseAnchorRecord(line []byte) (AnchorRecord, error) {
	var zero AnchorRecord
	if len(line) > maxAnchorRecordBytes {
		return zero, errors.New("anchor record is too long")
	}
	tree, err := spec.ParseStrict(line)
	if err != nil {
		return zero, fmt.Errorf("anchor record is not strict JSON: %w", err)
	}
	m, ok := tree.(map[string]any)
	if !ok {
		return zero, errors.New("anchor record is not a JSON object")
	}
	if len(m) != 9 {
		return zero, errors.New("anchor record has the wrong set of members")
	}
	str := func(k string, re *regexp.Regexp) (string, error) {
		s, ok := m[k].(string)
		if !ok || !re.MatchString(s) {
			return "", fmt.Errorf("anchor record member %q is missing or malformed", k)
		}
		return s, nil
	}
	num := func(k string) (int64, error) {
		f, ok := m[k].(float64)
		if !ok || f < 0 || f != float64(int64(f)) {
			return 0, fmt.Errorf("anchor record member %q is missing or not a count", k)
		}
		return int64(f), nil
	}
	var r AnchorRecord
	if v, err := num("v"); err != nil || v != anchorRecordVersion {
		return zero, errors.New("anchor record has an unknown version")
	}
	chain, ok := m["chain"].(string)
	if !ok || !chainRE.MatchString(chain) {
		return zero, errors.New(`anchor record member "chain" is missing or malformed`)
	}
	r.Chain = chain
	steps := []func() error{
		func() (err error) { r.HeadSeq, err = num("head_seq"); return },
		func() (err error) { r.HeadHash, err = str("head_hash", hashRE); return },
		func() (err error) { r.AnchorSeq, err = num("anchor_seq"); return },
		func() (err error) { r.AnchorHash, err = str("anchor_hash", hashRE); return },
		func() (err error) { r.TimeUnixNano, err = str("time_unix_nano", nanoRE); return },
		func() (err error) { r.KeyID, err = str("key_id", keyIDRE); return },
		func() (err error) { r.Sig, err = str("sig", sigRE); return },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return zero, err
		}
	}
	return r, nil
}

var chainRE = regexp.MustCompile(`^chaperone\.[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)

// KeyID names a ledger public key: the first 16 hex characters of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParsePublicKey reads the unpadded base64url public key `chapd ledger keygen`
// prints.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("ledger: a public key is 43 base64url characters (an Ed25519 key)")
	}
	return ed25519.PublicKey(raw), nil
}

// AnchorSigner signs anchor records with the ledger key.
type AnchorSigner interface {
	// KeyID is the KeyID of the public half. Fixed for the signer's life.
	KeyID() string
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// SecretUser is the vault's Use method (internal/vault.Vault satisfies it): the
// secret is handed to fn and never returned.
type SecretUser interface {
	Use(ctx context.Context, id string, fn func(secret []byte) error) error
}

// VaultAnchorSigner signs with an Ed25519 seed held in the vault. The seed
// exists only inside one Use call.
type VaultAnchorSigner struct {
	vault SecretUser
	id    string
	pub   ed25519.PublicKey
}

var _ AnchorSigner = (*VaultAnchorSigner)(nil)

// NewVaultAnchorSigner reads the seed once to learn the public key, and fails
// when the secret is not the unpadded base64url text of a 32-byte Ed25519 seed
// (`chapd ledger keygen` writes one).
func NewVaultAnchorSigner(ctx context.Context, v SecretUser, secretID string) (*VaultAnchorSigner, error) {
	s := &VaultAnchorSigner{vault: v, id: secretID}
	err := s.withKey(ctx, func(key ed25519.PrivateKey) error {
		s.pub = append(ed25519.PublicKey(nil), key.Public().(ed25519.PublicKey)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *VaultAnchorSigner) withKey(ctx context.Context, fn func(ed25519.PrivateKey) error) error {
	return s.vault.Use(ctx, s.id, func(secret []byte) error {
		// Check the length before decoding: Decode writes up to DecodedLen(len)
		// bytes, so a longer secret would run past the seed buffer.
		if len(secret) != base64.RawURLEncoding.EncodedLen(ed25519.SeedSize) {
			return errors.New("the ledger key secret is not a base64url Ed25519 seed")
		}
		seed := make([]byte, ed25519.SeedSize)
		defer clear(seed)
		if n, err := base64.RawURLEncoding.Strict().Decode(seed, secret); err != nil || n != ed25519.SeedSize {
			return errors.New("the ledger key secret is not a base64url Ed25519 seed")
		}
		key := ed25519.NewKeyFromSeed(seed)
		defer clear(key)
		return fn(key)
	})
}

// Public returns the public half, to be kept somewhere other than the server.
func (s *VaultAnchorSigner) Public() ed25519.PublicKey { return s.pub }

// KeyID implements [AnchorSigner].
func (s *VaultAnchorSigner) KeyID() string { return KeyID(s.pub) }

// Sign implements [AnchorSigner].
func (s *VaultAnchorSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	var sig []byte
	err := s.withKey(ctx, func(key ed25519.PrivateKey) error {
		if !bytes.Equal(key.Public().(ed25519.PublicKey), s.pub) {
			return errors.New("the ledger key secret changed since chapd started: restart chapd after a rotation")
		}
		sig = ed25519.Sign(key, msg)
		return nil
	})
	return sig, err
}

// sign fills KeyID and Sig of r.
func signAnchor(ctx context.Context, s AnchorSigner, r AnchorRecord) (AnchorRecord, error) {
	r.KeyID = s.KeyID()
	r.Sig = ""
	msg, err := r.signedBytes()
	if err != nil {
		return r, fmt.Errorf("ledger: anchor record: %w", err)
	}
	sig, err := s.Sign(ctx, msg)
	if err != nil {
		return r, fmt.Errorf("ledger: sign anchor: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return r, errors.New("ledger: the anchor signer returned a signature of the wrong size")
	}
	r.Sig = base64.RawURLEncoding.EncodeToString(sig)
	return r, nil
}

// ReadAnchorRecords reads the records file. A missing file is no records. Lines
// that are not records are returned in bad (with their line number) instead of
// failing the read, so the verifier can name them; torn is true when the last
// line has no newline (a crash during a write; the next append repairs it).
func ReadAnchorRecords(path string) (recs []AnchorRecord, bad []string, torn bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("ledger: read anchor records: %w", err)
	}
	torn = len(data) > 0 && data[len(data)-1] != '\n'
	for n := 1; len(data) > 0; n++ {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			bad = append(bad, "line "+strconv.Itoa(n)+": incomplete (no newline)")
			break
		}
		line := data[:i]
		data = data[i+1:]
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		r, perr := ParseAnchorRecord(line)
		if perr != nil {
			bad = append(bad, "line "+strconv.Itoa(n)+": "+perr.Error())
			continue
		}
		recs = append(recs, r)
	}
	return recs, bad, torn, nil
}

// ExportDir returns the export root the ledger was configured with.
func (l *Ledger) ExportDir() string { return l.cfg.ExportDir }
