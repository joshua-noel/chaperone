package runtoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/joshua-noel/chaperone/internal/spec"
)

// The JWS profile of ADR-005 / RFC 8725. Nothing here uses a JWT library: the
// header is three members and the algorithm is one string, so the parser is
// the profile.
const (
	algEdDSA = "EdDSA"
	typRun   = "factory-run+jwt"
	typCtl   = "factory-ctl+jwt"

	maxTokenBytes = 16 << 10
)

// forbiddenHeaders are the members RFC 8725 section 3 says a verifier must not
// follow: they let the token choose its own key or change how it is decoded.
var forbiddenHeaders = []string{"jku", "jwk", "x5u", "x5c", "crit", "zip"}

type verifiedJWS struct {
	Key     *Key
	Payload []byte
}

func isB64URL(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// verifyJWS runs steps 1 to 4 of ADR-005 up to and including the signature
// check: compact form, header profile, pinned key, alg, typ, signature. The
// payload is returned only after the signature held; the caller checks iss.
// Every refusal is TOKEN_INVALID; a bad signature also names the TOKEN_MISUSE
// stop.
func verifyJWS(token, wantTyp string, keys *KeySet) (*verifiedJWS, *Error) {
	if len(token) > maxTokenBytes {
		return nil, refuse(CauseTokenInvalid, "token is longer than %d bytes", maxTokenBytes)
	}
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return nil, refuse(CauseTokenInvalid, "token is not three dot-separated segments")
	}
	for i, s := range segs {
		if !isB64URL(s) {
			return nil, refuse(CauseTokenInvalid, "segment %d is not unpadded base64url", i+1)
		}
	}
	rawHeader, err := base64.RawURLEncoding.Strict().DecodeString(segs[0])
	if err != nil {
		return nil, refuse(CauseTokenInvalid, "header is not base64url")
	}
	tree, err := spec.ParseStrict(rawHeader)
	if err != nil {
		return nil, refuse(CauseTokenInvalid, "header is not strict JSON: %v", err)
	}
	hdr, ok := tree.(map[string]any)
	if !ok {
		return nil, refuse(CauseTokenInvalid, "header is not a JSON object")
	}
	// Step 1: forbidden members, then closed set, then the pinned key.
	for _, name := range forbiddenHeaders {
		if _, present := hdr[name]; present {
			return nil, refuse(CauseTokenInvalid, "header has a %q member", name)
		}
	}
	for name := range hdr {
		if name != "alg" && name != "typ" && name != "kid" {
			return nil, refuse(CauseTokenInvalid, "header has an unexpected %q member", name)
		}
	}
	kid, _ := hdr["kid"].(string)
	if !kidRe.MatchString(kid) {
		return nil, refuse(CauseTokenInvalid, "header kid is missing or malformed")
	}
	key, ok := keys.Lookup(kid)
	if !ok {
		return nil, refuse(CauseTokenInvalid, "kid %q is not in the pinned key set", kid)
	}
	// Step 2: exactly EdDSA. none, HS*, RS*, ES* and Ed25519 all fail here.
	if alg, _ := hdr["alg"].(string); alg != algEdDSA {
		return nil, refuse(CauseTokenInvalid, "alg is not %s", algEdDSA)
	}
	// Step 3: explicit typing.
	if typ, _ := hdr["typ"].(string); typ != wantTyp {
		return nil, refuse(CauseTokenInvalid, "typ is not %s", wantTyp)
	}
	// Step 4: signature under the pinned key.
	sig, err := base64.RawURLEncoding.Strict().DecodeString(segs[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, misuse(refuse(CauseTokenInvalid, "signature is not an Ed25519 signature"))
	}
	if !ed25519.Verify(key.Public, []byte(segs[0]+"."+segs[1]), sig) {
		return nil, misuse(refuse(CauseTokenInvalid, "signature does not verify under kid %q", kid))
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(segs[1])
	if err != nil {
		return nil, refuse(CauseTokenInvalid, "payload is not base64url")
	}
	return &verifiedJWS{Key: key, Payload: payload}, nil
}

// signJWS builds a compact JWS with the profile's header. sign receives the
// signing input and returns an Ed25519 signature.
func signJWS(typ, kid string, payload []byte, sign func(msg []byte) ([]byte, error)) (string, error) {
	hdr, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{algEdDSA, kid, typ})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(hdr) + "." + enc.EncodeToString(payload)
	sig, err := sign([]byte(input))
	if err != nil {
		return "", fmt.Errorf("runtoken: sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("runtoken: signer returned %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return input + "." + enc.EncodeToString(sig), nil
}
