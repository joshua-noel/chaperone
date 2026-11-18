package notify

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ErrInvalidAnchor is returned (wrapped) when an [Anchor] field is outside its
// allowlist pattern. Nothing is sent.
var ErrInvalidAnchor = errors.New("notify: invalid anchor")

// Anchor is everything an anchor push may be made from (ticket L1-21, ADR-006
// "Anchors"): the chain, the head the ledger.anchor event covers, and the
// ledger key's signature over them. It is a copy of the ledger head on a device
// outside the server, so a later rewrite of the whole chain on the server can be shown
// against it. It carries no authority and nothing secret: hashes, a counter and
// a public key id.
type Anchor struct {
	// Chain is the ledger chain id, "chaperone.<instance>".
	Chain string
	// HeadSeq is the seq of the newest event the anchor covers.
	HeadSeq int64
	// HeadHash is that event's hash, "sha256:<64 hex>".
	HeadHash string
	// KeyID names the ledger key that signed: 16 lowercase hex characters.
	KeyID string
	// Sig is the unpadded base64url Ed25519 signature of the anchor record
	// (86 characters).
	Sig string
}

// AnchorNotifier sends one anchor to the operator's phone. [Ntfy] implements it.
type AnchorNotifier interface {
	NotifyAnchor(ctx context.Context, a Anchor) error
}

const (
	anchorTitle    = "Chaperone: ledger anchor"
	anchorPriority = 3 // ntfy "default": a daily receipt, not a wake-up
	maxAnchorSeq   = 1<<53 - 1
)

var (
	anchorChainRE = regexp.MustCompile(`^chaperone\.[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$`)
	anchorHashRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	anchorKeyRE   = regexp.MustCompile(`^[0-9a-f]{16}$`)
	anchorSigRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
)

func (a Anchor) validate() error {
	switch {
	case !anchorChainRE.MatchString(a.Chain):
		return fmt.Errorf("%w: chain", ErrInvalidAnchor)
	case a.HeadSeq < 0 || a.HeadSeq > maxAnchorSeq:
		return fmt.Errorf("%w: head seq", ErrInvalidAnchor)
	case !anchorHashRE.MatchString(a.HeadHash):
		return fmt.Errorf("%w: head hash", ErrInvalidAnchor)
	case !anchorKeyRE.MatchString(a.KeyID):
		return fmt.Errorf("%w: key id", ErrInvalidAnchor)
	case !anchorSigRE.MatchString(a.Sig):
		return fmt.Errorf("%w: signature", ErrInvalidAnchor)
	}
	return nil
}

// BuildAnchor makes the push for a. It is pure and the only place anchor text
// is made: a fixed template over five fields, each checked against its pattern
// first, so nothing else can reach the phone.
//
// Example message:
//
//	chaperone.pc
//	head seq 1234
//	sha256:<64 hex>
//	key 0123456789abcdef
//	sig <86 characters>
func BuildAnchor(a Anchor) (Push, error) {
	if err := a.validate(); err != nil {
		return Push{}, err
	}
	var b strings.Builder
	b.WriteString(a.Chain)
	b.WriteString("\nhead seq ")
	b.WriteString(strconv.FormatInt(a.HeadSeq, 10))
	b.WriteByte('\n')
	b.WriteString(a.HeadHash)
	b.WriteString("\nkey ")
	b.WriteString(a.KeyID)
	b.WriteString("\nsig ")
	b.WriteString(a.Sig)
	return Push{Title: anchorTitle, Message: b.String(), Priority: anchorPriority}, nil
}

var _ AnchorNotifier = (*Ntfy)(nil)

// NotifyAnchor builds the push for a ([BuildAnchor]) and publishes it once. It
// returns [ErrInvalidAnchor] without any request if a is outside the allowlist.
func (n *Ntfy) NotifyAnchor(ctx context.Context, a Anchor) error {
	p, err := BuildAnchor(a)
	if err != nil {
		return err
	}
	return n.publish(ctx, p)
}
