package vault

import "errors"

// KeyWrapper protects the vault's own long-lived keys (the age service
// identity and the fingerprint key) at rest. It is the one part of the vault
// that is tied to an operating system or to a person; the age file format is
// not. The wrappers are:
//
//	dpapi-user       Windows DPAPI, current-user scope ([NewDPAPI])
//	keychain-macos   the macOS login keychain, through `security`
//	secret-service   a Linux Secret Service keyring, through `secret-tool`
//	age-passphrase   a passphrase, through age's scrypt recipient
//
// [NewWrapper] picks one by name. A TPM sealed key, systemd-creds or a cloud
// KMS plug in here without touching the on-disk format (ADR-003, item 3).
//
// An implementation MUST bind the output to a principal that the agents and
// the operator's account are not where the system allows it (for DPAPI: the
// service account's user scope, never the machine scope) and MUST return an
// error, never partial plaintext, when the caller is not that principal. It
// MUST NOT fall back to storing a key unprotected.
//
// The macOS and Linux wrappers cannot separate two programs of one user:
// whatever runs as that user can ask the keychain. See ADR-003, amendment 6,
// for what each wrapper does and does not protect against.
type KeyWrapper interface {
	// Name is a stable label stored in the vault index ("dpapi-user"), so a
	// vault opened with a different wrapper fails with a clear error.
	Name() string
	// Wrap returns an opaque blob that only this principal can unwrap.
	// plaintext is not retained.
	Wrap(plaintext []byte) ([]byte, error)
	// Unwrap returns the plaintext of a blob made by Wrap. The caller zeroes
	// the result when done.
	Unwrap(wrapped []byte) ([]byte, error)
}

// ErrUnsupported is returned by a wrapper that does not exist on this
// operating system (dpapi-user outside Windows, keychain-macos outside macOS,
// secret-service outside Linux).
var ErrUnsupported = errors.New("vault: key wrapper is not supported on this operating system")

// DPAPIName is the [KeyWrapper.Name] of the Windows DPAPI implementation.
const DPAPIName = "dpapi-user"

// dpapiEntropy is Chaperone's own pOptionalEntropy for CryptProtectData. A
// process that can call DPAPI as the same user but does not know this blob
// (and the file layout) cannot unwrap by accident; it is not a secret, and
// the defence against anything running as svc-chaperone is the account
// boundary (ADR-003, "honest limits").
var dpapiEntropy = []byte("chaperone/vault/dpapi-user/v1")

// NewDPAPI returns the Windows wrapper: Windows DPAPI, current-user scope,
// Chaperone's own entropy. It never sets CRYPTPROTECT_LOCAL_MACHINE, which
// would let any user on the server decrypt.
func NewDPAPI() KeyWrapper { return newDPAPIUser(dpapiEntropy) }
