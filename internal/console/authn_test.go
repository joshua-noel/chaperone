package console

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// authenticator is a software platform authenticator: just enough of CTAP2
// and the browser's WebAuthn layer to make registrations and assertions the
// way Edge and Windows Hello do, so tests can also make them the way an
// attacker or a broken device would (wrong origin, wrong challenge, UV off).
type authenticator struct {
	t          *testing.T
	key        *ecdsa.PrivateKey
	credID     []byte
	rpID       string
	signCount  uint32
	userHandle []byte
}

func newAuthenticator(t *testing.T, rpID string) *authenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &authenticator{t: t, key: k, credID: id, rpID: rpID}
}

// assertion knobs; the zero value is an honest browser with user verification.
type opts struct {
	origin    string // clientDataJSON.origin; "" means honest (the page's origin)
	challenge string // override the challenge the browser reports
	noUV      bool   // clear the UV flag
	noUP      bool   // clear the UP flag
	signCount *uint32
	wrongKey  bool // sign with a key the server never saw
	// crossOrigin and topOrigin make the assertion as a page in a frame: crossOrigin true, topOrigin the framing page's origin
	crossOrigin bool
	topOrigin   string
}

// ---- minimal CBOR (only what a "none" attestation needs) ----

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}
func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }
func cborInt(n int64) []byte {
	if n >= 0 {
		return cborHead(0, uint64(n))
	}
	return cborHead(1, uint64(-1-n))
}
func cborMap(pairs ...[]byte) []byte {
	out := cborHead(5, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

func (a *authenticator) coseKey() []byte {
	pad := func(b []byte) []byte {
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return out
	}
	return cborMap(
		cborInt(1), cborInt(2), // kty EC2
		cborInt(3), cborInt(-7), // alg ES256
		cborInt(-1), cborInt(1), // crv P-256
		cborInt(-2), cborBytes(pad(a.key.PublicKey.X.Bytes())),
		cborInt(-3), cborBytes(pad(a.key.PublicKey.Y.Bytes())),
	)
}

func (a *authenticator) authData(attested bool, o opts) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	flags := byte(0x01) // UP
	if o.noUP {
		flags = 0
	}
	if !o.noUV {
		flags |= 0x04
	}
	if attested {
		flags |= 0x40
	}
	cnt := a.signCount
	if o.signCount != nil {
		cnt = *o.signCount
	}
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, cnt)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID zero
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		out = append(out, a.coseKey()...)
	}
	return out
}

func clientData(typ, challenge, origin string) []byte {
	return clientDataFor(typ, challenge, origin, opts{})
}

// clientDataFor is clientData as a frame would report it when o.crossOrigin is set: crossOrigin true and the
// top-level origin the browser signs in.
func clientDataFor(typ, challenge, origin string, o opts) []byte {
	m := map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": o.crossOrigin}
	if o.topOrigin != "" {
		m["topOrigin"] = o.topOrigin
	}
	b, _ := json.Marshal(m)
	return b
}

// create answers the options JSON the server sent for a registration.
// pageOrigin is the origin of the page that called navigator.credentials.create.
func (a *authenticator) create(options json.RawMessage, pageOrigin string, o opts) []byte {
	a.t.Helper()
	var creation struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &creation); err != nil {
		a.t.Fatal(err)
	}
	a.userHandle, _ = b64.DecodeString(creation.PublicKey.User.ID)
	challenge := creation.PublicKey.Challenge
	if o.challenge != "" {
		challenge = o.challenge
	}
	origin := pageOrigin
	if o.origin != "" {
		origin = o.origin
	}
	cd := clientData("webauthn.create", challenge, origin)
	att := cborMap(
		cborText("fmt"), cborText("none"),
		cborText("attStmt"), cborMap(),
		cborText("authData"), cborBytes(a.authData(true, o)),
	)
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"attestationObject": b64.EncodeToString(att),
			"clientDataJSON":    b64.EncodeToString(cd),
		},
	})
	return out
}

// get answers the options JSON the server sent for a login.
func (a *authenticator) get(options json.RawMessage, pageOrigin string, o opts) []byte {
	a.t.Helper()
	var req struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &req); err != nil {
		a.t.Fatal(err)
	}
	challenge := req.PublicKey.Challenge
	if o.challenge != "" {
		challenge = o.challenge
	}
	origin := pageOrigin
	if o.origin != "" {
		origin = o.origin
	}
	a.signCount++
	ad := a.authData(false, o)
	cd := clientDataFor("webauthn.get", challenge, origin, o)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	key := a.key
	if o.wrongKey {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"authenticatorData": b64.EncodeToString(ad),
			"clientDataJSON":    b64.EncodeToString(cd),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(a.userHandle),
		},
	})
	return out
}
