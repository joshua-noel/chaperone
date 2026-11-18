package grant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Refusal is why a grant was not accepted. Code is stable and safe to log or
// send back to chapd; Detail is for the local log only.
type Refusal struct {
	Code   string
	Detail string
}

// Refusal codes.
var (
	ErrMalformed = &Refusal{Code: "GRANT_MALFORMED"}       // not a grant at all
	ErrSignature = &Refusal{Code: "GRANT_SIGNATURE"}       // not signed by the pinned key
	ErrInvalid   = &Refusal{Code: "GRANT_INVALID"}         // signed, but fields break the schema
	ErrNotYet    = &Refusal{Code: "GRANT_NOT_YET_VALID"}   // iat is in the future
	ErrExpired   = &Refusal{Code: "GRANT_EXPIRED"}         // exp has passed
	ErrReplay    = &Refusal{Code: "GRANT_REPLAYED"}        // nonce already used
	ErrStore     = &Refusal{Code: "GRANT_NONCE_STORE"}     // could not record the nonce: fail closed
	ErrScript    = &Refusal{Code: "GRANT_SCRIPT_MISMATCH"} // script on disk differs from script_sha256
)

func (r *Refusal) Error() string {
	if r.Detail == "" {
		return r.Code
	}
	return r.Code + ": " + r.Detail
}

// Is makes errors.Is(err, ErrExpired) true for any Refusal with that code.
func (r *Refusal) Is(target error) bool {
	t, ok := target.(*Refusal)
	return ok && t.Code == r.Code
}

// Refuse returns a Refusal with the given code and detail.
func Refuse(base *Refusal, format string, a ...any) *Refusal {
	return &Refusal{Code: base.Code, Detail: fmt.Sprintf(format, a...)}
}

// CodeOf returns the refusal code in err, or "" if err holds none.
func CodeOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

var b64 = base64.RawURLEncoding.Strict()

// NewNonce returns a fresh 128-bit nonce in the grant's nonce shape.
func NewNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// Sign validates g and returns its wire form. It sets the version, and an
// empty argument object when g has none.
func Sign(key ed25519.PrivateKey, g Grant) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("grant: bad private key")
	}
	g.Version = Version
	if g.Args == nil {
		g.Args = map[string]string{}
	}
	if err := g.Validate(); err != nil {
		return "", fmt.Errorf("grant: %w", err)
	}
	payload, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, signedBytes(payload))
	token := tokenPrefix + "." + b64.EncodeToString(payload) + "." + b64.EncodeToString(sig)
	if len(token) > MaxTokenBytes {
		return "", errors.New("grant: token too large")
	}
	return token, nil
}

func signedBytes(payload []byte) []byte {
	msg := make([]byte, 0, len(sigDomain)+len(payload))
	msg = append(msg, sigDomain...)
	return append(msg, payload...)
}

// Verifier accepts grants signed by one pinned chapd key, once each.
type Verifier struct {
	key    ed25519.PublicKey
	nonces NonceStore
	// Now is the clock; nil means time.Now. Tests set it.
	Now func() time.Time
}

// NewVerifier pins key and records used nonces in store.
func NewVerifier(key ed25519.PublicKey, store NonceStore) (*Verifier, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, errors.New("grant: public key must be 32 bytes")
	}
	if store == nil {
		return nil, errors.New("grant: a nonce store is required")
	}
	return &Verifier{key: bytes.Clone(key), nonces: store}, nil
}

// Verify checks, in this order, and stops at the first failure: size and
// shape of the wire form; the signature; the payload schema and lifetime;
// iat and exp against the clock; the nonce (recorded here, so a grant is
// accepted at most once even if the caller then fails). It returns the grant.
// The caller must still compare script_sha256 with the file it will run.
func (v *Verifier) Verify(token string) (*Grant, error) {
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return nil, Refuse(ErrMalformed, "length %d", len(token))
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return nil, Refuse(ErrMalformed, "not %s.<payload>.<signature>", tokenPrefix)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, Refuse(ErrMalformed, "payload encoding")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, Refuse(ErrMalformed, "signature encoding")
	}
	if !ed25519.Verify(v.key, signedBytes(payload), sig) {
		return nil, Refuse(ErrSignature, "signature does not verify under the pinned key")
	}

	var g Grant
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return nil, Refuse(ErrInvalid, "payload: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, Refuse(ErrInvalid, "payload: trailing data")
	}
	if err := g.Validate(); err != nil {
		return nil, Refuse(ErrInvalid, "%v", err)
	}

	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	t := now()
	if !t.Before(g.Expiry()) {
		return nil, Refuse(ErrExpired, "expired at %s", g.Expiry().UTC().Format(time.RFC3339))
	}
	if time.Unix(g.IssuedAt, 0).After(t.Add(MaxClockSkew)) {
		return nil, Refuse(ErrNotYet, "issued in the future")
	}

	if err := v.nonces.Consume(g.Nonce, g.Expiry(), t); err != nil {
		if errors.Is(err, ErrReplay) {
			return nil, Refuse(ErrReplay, "nonce already used")
		}
		return nil, Refuse(ErrStore, "%v", err)
	}
	return &g, nil
}
