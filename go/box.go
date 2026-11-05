package honeypot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/sha256"
	"errors"
	"maps"
	"math"
	"slices"
	"unicode/utf8"
)

// TagBox starts every box (spec "Naming"). A changed layout gets a new tag.
const TagBox = "HPBOX001"

// Derivation tags (spec "Keys").
const (
	tagSign   = "HPSIGN01"
	tagRoot   = "HPROOT01"
	tagNonce  = "HPNONC01"
	tagKey    = "HPKEY001"
	tagEnc    = "HPENC001"
	tagCommit = "HPCOMT01"
	tagInput  = "HPINPT01"
	tagRoll   = "HPROLL01"
)

const (
	// KeySize is the size of a main key and of an open key.
	KeySize = 32
	// PublicKeySize is the size of an issuer public key (ML-DSA-65).
	PublicKeySize = mldsa.MLDSA65PublicKeySize
	// SigSize is the size of a signature (ML-DSA-65).
	SigSize = mldsa.MLDSA65SignatureSize
	// MaxSize is the largest plaintext a box can hold: the ciphertext, with
	// its 16-byte tag, has a u16 length.
	MaxSize = math.MaxUint16 - 16
	// PropUser is the property that assigns a box to a user: Release gives the
	// open key to this user only.
	PropUser = "userId"
)

var (
	ErrTag        = errors.New("honeypot: wrong message tag")
	ErrTrailing   = errors.New("honeypot: bytes after the message")
	ErrDrawField  = errors.New("honeypot: malformed draw fields")
	ErrTooLong    = errors.New("honeypot: series longer than 255 bytes or meta longer than 65535")
	ErrProperty   = errors.New("honeypot: malformed properties")
	ErrSize       = errors.New("honeypot: payload does not fit the series size")
	ErrKeySize    = errors.New("honeypot: key must be 32 bytes")
	ErrUnknownKey = errors.New("honeypot: unknown issuer key")
	ErrSignature  = errors.New("honeypot: bad signature")
	ErrWrongKey   = errors.New("honeypot: open key does not belong to this box")
	ErrCiphertext = errors.New("honeypot: ciphertext does not decrypt")
	ErrPadding    = errors.New("honeypot: malformed plaintext")
)

// Box is a sealed box (spec "Sealing a box"). Everything but the payload is
// public. Revision and Props are the only part that can change, and only the
// issuer can change them.
type Box struct {
	KeyID      uint8
	Series     string
	Meta       []byte
	Draw       *Draw // set if the contents were drawn from a blueprint
	Nonce      [16]byte
	KeyCommit  [32]byte
	Ciphertext []byte
	Revision   uint32
	Props      map[string]string
	Sig        []byte
}

// prefix is the header up to the nonce; the nonce is derived from it.
func (b Box) prefix() []byte {
	out := append([]byte(TagBox), b.KeyID, byte(len(b.Series)))
	out = append(out, b.Series...)
	out = appendU16(out, uint16(len(b.Meta)))
	out = append(out, b.Meta...)
	if b.Draw == nil {
		return append(out, 0)
	}
	out = append(out, 1)
	out = append(out, b.Draw.BlueprintID[:]...)
	out = append(out, b.Draw.InputCommit[:]...)
	out = appendU16(out, uint16(len(b.Draw.SoldOut)))
	for _, i := range b.Draw.SoldOut {
		out = appendU16(out, i)
	}
	return out
}

func (b Box) header() []byte { return append(b.prefix(), b.Nonce[:]...) }

// keyInput is the hash of the header: the open key comes from it, since the
// ciphertext cannot exist before the key.
func (b Box) keyInput() [32]byte { return sha256.Sum256(b.header()) }

// sealed is everything that never changes.
func (b Box) sealed() []byte {
	out := append(b.header(), b.KeyCommit[:]...)
	if b.Draw != nil {
		out = append(out, b.Draw.Input[:]...)
	}
	out = appendU16(out, uint16(len(b.Ciphertext)))
	return append(out, b.Ciphertext...)
}

// ID identifies a box: the hash of its sealed part, and so of its contents. A
// rewrite keeps it. It leaves out the revision and the properties, which
// change, and the signature, which a dishonest signer can vary.
func (b Box) ID() [32]byte { return sha256.Sum256(b.sealed()) }

func (b Box) signed() []byte {
	return appendProps(appendU32(b.sealed(), b.Revision), b.Props)
}

// Encode is the box as it travels: the signed part and the signature.
func (b Box) Encode() []byte { return append(b.signed(), b.Sig...) }

// readHeader reads the fields of the header, which a ticket carries too.
func readHeader(r *reader) Box {
	r.tag(TagBox)
	b := Box{KeyID: r.u8(), Series: string(r.take(int(r.u8())))}
	b.Meta = r.take(int(r.u16()))
	switch r.u8() {
	case 0:
	case 1:
		b.Draw = &Draw{BlueprintID: r.array32(), InputCommit: r.array32(), SoldOut: readSoldOut(r)}
	default:
		r.err = ErrDrawField
	}
	b.Nonce = r.array16()
	return b
}

// DecodeBox decodes one box. A box has exactly one byte form: anything after
// the signature is an error.
func DecodeBox(raw []byte) (Box, error) {
	r := &reader{b: raw}
	b := readHeader(r)
	b.KeyCommit = r.array32()
	if b.Draw != nil {
		b.Draw.Input = r.array32()
	}
	b.Ciphertext = r.take(int(r.u16()))
	b.Revision = r.u32()
	b.Props = readProps(r)
	b.Sig = r.take(SigSize)
	if r.err == nil && len(r.b) != 0 {
		r.err = ErrTrailing
	}
	if r.err != nil {
		return Box{}, r.err
	}
	return b, nil
}

// Verify checks the box against the pinned public keys of the issuer. It says
// who sealed the box and that the issuer stated these properties at this
// revision, and nothing about what is inside. It cannot say the revision is
// still the latest: a signature does not expire (spec "Old revisions").
func (b Box) Verify(keys map[uint8][]byte) error {
	return verifyFrom(keys, b.KeyID, b.signed(), b.Sig)
}

// VerifyKey checks an open key against the box without decrypting. Only the
// one key the box was sealed with passes.
func (b Box) VerifyKey(openKey []byte) error {
	if len(openKey) != KeySize {
		return ErrKeySize
	}
	if !hmac.Equal(kdf(openKey, tagCommit), b.KeyCommit[:]) {
		return ErrWrongKey
	}
	return nil
}

// Supersedes reports whether b is a later revision of old: the same box, so the
// same contents and the same open key, with newer properties. Verify both first.
func (b Box) Supersedes(old Box) bool {
	return b.ID() == old.ID() && b.Revision > old.Revision
}

// Open verifies the box and the open key and returns the payload.
func (b Box) Open(keys map[uint8][]byte, openKey []byte) ([]byte, error) {
	if err := b.Verify(keys); err != nil {
		return nil, err
	}
	if err := b.VerifyKey(openKey); err != nil {
		return nil, err
	}
	in := b.keyInput()
	plain, err := aead(openKey).Open(nil, zeroNonce, b.Ciphertext, in[:])
	if err != nil {
		return nil, ErrCiphertext
	}
	return unpad(plain)
}

// validProp is the rule for one property: a name and readable text.
func validProp(name, value string) bool {
	return name != "" && len(name) <= math.MaxUint8 && len(value) <= math.MaxUint16 &&
		utf8.ValidString(name) && utf8.ValidString(value)
}

func checkProps(props map[string]string) error {
	if len(props) > math.MaxUint8 {
		return ErrProperty
	}
	for name, value := range props {
		if !validProp(name, value) {
			return ErrProperty
		}
	}
	return nil
}

// appendProps writes the properties sorted by name, so they have one byte form.
func appendProps(out []byte, props map[string]string) []byte {
	out = append(out, byte(len(props)))
	for _, name := range slices.Sorted(maps.Keys(props)) {
		out = append(append(out, byte(len(name))), name...)
		out = append(appendU16(out, uint16(len(props[name]))), props[name]...)
	}
	return out
}

func readProps(r *reader) map[string]string {
	n := int(r.u8())
	props := make(map[string]string, n)
	last := ""
	for range n {
		name := string(r.take(int(r.u8())))
		value := string(r.take(int(r.u16())))
		if r.err == nil && (name <= last || !validProp(name, value)) {
			r.err = ErrProperty
		}
		last = name
		props[name] = value
	}
	return props
}

// kdf is HMAC-SHA-256 over a tag and the data, the only derivation in the
// protocol. Every input but the last has a fixed length or delimits itself.
func kdf(key []byte, tag string, data ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(tag))
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// zeroNonce is safe because an open key encrypts exactly one plaintext.
var zeroNonce = make([]byte, 12)

// aead is AES-256-GCM under the encryption key of an open key.
func aead(openKey []byte) cipher.AEAD {
	block, _ := aes.NewCipher(kdf(openKey, tagEnc)) // 32 bytes cannot fail
	gcm, _ := cipher.NewGCM(block)                  // AES cannot fail
	return gcm
}

// pad gives every plaintext of a series the same length, so the size of a box
// says nothing about what it holds.
func pad(payload []byte, size int) ([]byte, error) {
	if size > MaxSize || len(payload)+2 > size {
		return nil, ErrSize
	}
	plain := appendU16(make([]byte, 0, size), uint16(len(payload)))
	plain = append(plain, payload...)
	return plain[:size], nil
}

func unpad(plain []byte) ([]byte, error) {
	r := &reader{b: plain}
	payload := r.take(int(r.u16()))
	if r.err != nil {
		return nil, ErrPadding
	}
	for _, c := range r.b {
		if c != 0 {
			return nil, ErrPadding
		}
	}
	return payload, nil
}

func verifyFrom(keys map[uint8][]byte, keyID uint8, msg, sig []byte) error {
	pub, ok := keys[keyID]
	if !ok {
		return ErrUnknownKey
	}
	if !verifySig(pub, msg, sig) {
		return ErrSignature
	}
	return nil
}

// verifySig checks an ML-DSA-65 signature (FIPS 204, empty context).
func verifySig(pub, msg, sig []byte) bool {
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub)
	if err != nil {
		return false
	}
	return mldsa.Verify(pk, msg, sig, nil) == nil
}
