package honeypot

import (
	"crypto/mldsa"
	"errors"
	"io"
	"math"
)

var (
	// ErrClaimed is a box that the ledger has already given to someone else.
	ErrClaimed = errors.New("honeypot: box already claimed by another owner")
	// ErrNotOwner is a claim by someone other than the box's userId.
	ErrNotOwner = errors.New("honeypot: box is assigned to another user")
	// ErrStale is an old revision of a box: its properties have been rewritten.
	ErrStale = errors.New("honeypot: a newer revision of this box exists")
)

// Issuer holds a main key: it seals and draws boxes, rewrites their properties
// and derives their open keys.
type Issuer struct {
	KeyID uint8
	sign  *mldsa.PrivateKey
	root  []byte
}

// NewIssuer splits a main key, 32 bytes from a CSPRNG, into the signing key and
// the root of the open keys (spec "Keys"). keyID names the main key in its
// boxes, so it can be rotated.
func NewIssuer(keyID uint8, main []byte) (*Issuer, error) {
	if len(main) != KeySize {
		return nil, ErrKeySize
	}
	sign, _ := mldsa.NewPrivateKey(mldsa.MLDSA65(), kdf(main, tagSign)) // 32 bytes cannot fail
	return &Issuer{KeyID: keyID, sign: sign, root: kdf(main, tagRoot)}, nil
}

// Public is the public key verifiers pin under KeyID.
func (is *Issuer) Public() []byte { return is.sign.PublicKey().Bytes() }

func (is *Issuer) keys() map[uint8][]byte { return map[uint8][]byte{is.KeyID: is.Public()} }

// Spec is what a box shows before it is opened.
type Spec struct {
	Series string            // namespace and kind of box, signed, public, fixed
	Meta   []byte            // anything else public and fixed, opaque to the protocol
	Props  map[string]string // public, readable, only the issuer can rewrite them
	Size   int               // plaintext size, one per series, at least payload + 2 bytes
}

// Seal creates a box at revision 0. rng is crypto/rand.Reader outside of tests.
func (is *Issuer) Seal(rng io.Reader, spec Spec, payload []byte) (Box, error) {
	if len(spec.Series) > math.MaxUint8 || len(spec.Meta) > math.MaxUint16 {
		return Box{}, ErrTooLong
	}
	if err := checkProps(spec.Props); err != nil {
		return Box{}, err
	}
	plain, err := pad(payload, spec.Size)
	if err != nil {
		return Box{}, err
	}
	var entropy [32]byte
	if _, err := io.ReadFull(rng, entropy[:]); err != nil {
		return Box{}, err
	}
	return is.seal(entropy, spec, plain), nil
}

// seal derives the nonce from the plaintext as well as the entropy, so a broken
// RNG can repeat a box but never reuse an open key for a second plaintext.
func (is *Issuer) seal(entropy [32]byte, spec Spec, plain []byte) Box {
	b := Box{KeyID: is.KeyID, Series: spec.Series, Meta: spec.Meta, Props: spec.Props}
	copy(b.Nonce[:], kdf(is.root, tagNonce, entropy[:], b.prefix(), plain))
	openKey := is.Key(b)
	copy(b.KeyCommit[:], kdf(openKey, tagCommit))
	in := b.keyInput()
	b.Ciphertext = aead(openKey).Seal(nil, zeroNonce, plain, in[:])
	b.Sig = is.signBox(b)
	return b
}

// signBox signs deterministically: one box at one revision has one signature.
func (is *Issuer) signBox(b Box) []byte {
	sig, _ := is.sign.SignDeterministic(b.signed(), nil) // an empty context cannot fail
	return sig
}

// Rewrite replaces the properties of a box and returns its next revision. The
// contents, the id and the open key stay the same. It takes the whole new set of
// properties, and any earlier revision of the box as its base: after a lost
// response, rewriting again just takes the next revision.
func (is *Issuer) Rewrite(l Ledger, b Box, props map[string]string) (Box, error) {
	if err := b.Verify(is.keys()); err != nil {
		return Box{}, err
	}
	if err := checkProps(props); err != nil {
		return Box{}, err
	}
	rev, err := l.Advance(b.ID(), b.Revision)
	if err != nil {
		return Box{}, err
	}
	b.Revision, b.Props = rev, props
	b.Sig = is.signBox(b)
	return b, nil
}

// Key derives the open key of a box. It is not stored anywhere and is the same
// every time. It answers for any box, so never expose it without a check that
// the caller may have the key: that is Release.
func (is *Issuer) Key(b Box) []byte {
	in := b.keyInput()
	return kdf(is.root, tagKey, in[:])
}

// Ledger is the state that signatures and derivation cannot provide: who claimed
// which box, and which revision is current. Open keys are not stored; this is one
// row per box that was rewritten or opened.
type Ledger interface {
	// Claim atomically records owner for the box and returns the owner on
	// record, which is an earlier one if a claim exists. It returns ErrStale,
	// and records nothing, if a revision above rev is on record.
	Claim(id [32]byte, rev uint32, owner string) (string, error)
	// Advance atomically raises the revision on record above both its current
	// value and rev, and returns it. A box never rewritten is at revision 0.
	Advance(id [32]byte, rev uint32) (uint32, error)
}

// Release gives owner the open key of a box the first time it is claimed, and
// again only to the same owner, so a retry after a lost response is safe. A box
// with a userId goes to that user only, and an old revision is refused, so a
// previous owner cannot come back with the copy they kept.
func (is *Issuer) Release(l Ledger, b Box, owner string) ([]byte, error) {
	if err := b.Verify(is.keys()); err != nil {
		return nil, err
	}
	if user, ok := b.Props[PropUser]; ok && user != owner {
		return nil, ErrNotOwner
	}
	claimant, err := l.Claim(b.ID(), b.Revision, owner)
	if err != nil {
		return nil, err
	}
	if claimant != owner {
		return nil, ErrClaimed
	}
	return is.Key(b), nil
}
