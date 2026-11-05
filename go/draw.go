package honeypot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"slices"
)

// TagTicket starts every ticket (spec "Naming").
const TagTicket = "HPTKT001"

var (
	// ErrNotDrawn is a box sealed by hand, with no blueprint behind it.
	ErrNotDrawn = errors.New("honeypot: box was not drawn from a blueprint")
	// ErrWrongBlueprint is a blueprint other than the one named by the box.
	ErrWrongBlueprint = errors.New("honeypot: not the blueprint of this box")
	// ErrInput is an input that does not match its commitment, or a commitment
	// that is not the player's.
	ErrInput = errors.New("honeypot: input does not match its commitment")
	// ErrTicket is a box other than the one the ticket promised.
	ErrTicket = errors.New("honeypot: box does not match the ticket")
	// ErrDraw is a box whose contents are not what its draw gives: proof that the
	// issuer cheated.
	ErrDraw = errors.New("honeypot: contents are not what the draw gives")
	// ErrNoCaps is a blueprint with caps and no Caps to keep count.
	ErrNoCaps = errors.New("honeypot: this blueprint has caps and needs Caps")
	// ErrSoldOut is a draw that landed on an item whose cap has been reached since
	// the ticket was signed, or a blueprint with every item sold out. The issuer
	// may not give something else instead: the ticket is refunded.
	ErrSoldOut = errors.New("honeypot: sold out")
)

// Draw says where the contents of a box came from. All of it is public, and none
// of it says what the item is without the open key.
type Draw struct {
	BlueprintID [32]byte
	InputCommit [32]byte
	SoldOut     []uint16 // positions of the items left out of this draw, ascending
	Input       [32]byte
}

// Caps counts the items of a blueprint with caps (spec "Caps"). A blueprint with
// no caps never touches it.
type Caps interface {
	// SoldOut lists the items of a blueprint whose cap has been reached.
	SoldOut(blueprintID [32]byte) ([]string, error)
	// Take atomically gives a draw the next serial of an item, starting at 1, and
	// reports false if the cap has been reached. A cap of 0 has no limit. The same
	// draw always gets the same answer, so a retry keeps its serial.
	Take(blueprintID [32]byte, item string, cap uint32, draw [32]byte) (uint64, bool, error)
}

// Drawn is what a drawn box held. Serial is 0 if its blueprint has no caps.
type Drawn struct {
	Item   Item
	Serial uint64
}

func readSoldOut(r *reader) []uint16 {
	n := int(r.u16())
	var out []uint16
	for i := 0; i < n && r.err == nil; i++ {
		v := r.u16()
		if r.err == nil && i > 0 && v <= out[i-1] {
			r.err = ErrDrawField
		}
		out = append(out, v)
	}
	return out
}

// checkSoldOut says a sold out list is possible at all: only items with a cap can
// sell out, and something must be left to draw.
func checkSoldOut(bp Blueprint, soldOut []uint16) error {
	if len(soldOut) >= len(bp.Items) {
		return ErrDrawField
	}
	for i, pos := range soldOut {
		if int(pos) >= len(bp.Items) || bp.Items[pos].Cap == 0 || (i > 0 && pos <= soldOut[i-1]) {
			return ErrDrawField
		}
	}
	return nil
}

// validSerial is the scarcity rule: a capped item has a serial from 1 to its cap.
func validSerial(bp Blueprint, it Item, serial uint64) bool {
	switch {
	case !bp.capped():
		return serial == 0
	case it.Cap > 0:
		return serial >= 1 && serial <= uint64(it.Cap)
	default:
		return serial >= 1
	}
}

// DrawRequest is the player's part of a draw. Make a new one for every draw:
// once an input is known, an issuer can choose a nonce that suits it.
type DrawRequest struct {
	Input  [32]byte // secret until the ticket arrives
	Commit [32]byte // goes to the issuer first
}

// NewDrawRequest draws an input and commits to it. rng is crypto/rand.Reader
// outside of tests.
func NewDrawRequest(rng io.Reader) (DrawRequest, error) {
	var req DrawRequest
	if _, err := io.ReadFull(rng, req.Input[:]); err != nil {
		return DrawRequest{}, err
	}
	req.Commit = commitInput(req.Input)
	return req, nil
}

func commitInput(input [32]byte) (c [32]byte) {
	copy(c[:], kdf(input[:], tagInput))
	return c
}

// roll gives a number that is exactly uniform in [0, total), if the KDF output
// is uniform. It takes 64 bits and drops the 2^64 mod total lowest values, so
// what is left divides evenly by total and x % total has no bias.
func roll(openKey []byte, blueprintID, input [32]byte, total uint64) uint64 {
	reject := -total % total // 2^64 mod total, in 64-bit arithmetic
	for j := uint32(0); ; j++ {
		x := binary.BigEndian.Uint64(kdf(openKey, tagRoll, blueprintID[:], input[:], appendU32(nil, j)))
		if x >= reject {
			return x % total
		}
	}
}

// Ticket is what the issuer promises before it sees the player's input: the box
// it will fill, down to the open key (spec "Drawing"). A box has to match it.
type Ticket struct {
	KeyID       uint8
	Series      string
	Meta        []byte
	BlueprintID [32]byte
	InputCommit [32]byte
	SoldOut     []uint16 // positions of the items this draw cannot give
	Nonce       [16]byte
	KeyCommit   [32]byte
	Props       map[string]string
	Sig         []byte
}

// box is the box a ticket promises, without the input and the contents.
func (t Ticket) box() Box {
	return Box{KeyID: t.KeyID, Series: t.Series, Meta: t.Meta, Nonce: t.Nonce, KeyCommit: t.KeyCommit, Props: t.Props,
		Draw: &Draw{BlueprintID: t.BlueprintID, InputCommit: t.InputCommit, SoldOut: t.SoldOut}}
}

// Available is what this draw can give, with its exact odds: each Weight out of
// the sum of the Weights. Read it before giving up the input.
func (t Ticket) Available(bp Blueprint) []Item { return bp.available(t.SoldOut) }

func (t Ticket) signed() []byte {
	out := append([]byte(TagTicket), t.box().header()...)
	out = append(out, t.KeyCommit[:]...)
	return appendProps(out, t.Props)
}

// Encode is the ticket as it travels.
func (t Ticket) Encode() []byte { return append(t.signed(), t.Sig...) }

// DecodeTicket decodes one ticket.
func DecodeTicket(raw []byte) (Ticket, error) {
	r := &reader{b: raw}
	r.tag(TagTicket)
	b := readHeader(r)
	if r.err == nil && b.Draw == nil {
		r.err = ErrDrawField
	}
	keyCommit := r.array32()
	props := readProps(r)
	sig := r.take(SigSize)
	if r.err == nil && len(r.b) != 0 {
		r.err = ErrTrailing
	}
	if r.err != nil {
		return Ticket{}, r.err
	}
	return Ticket{KeyID: b.KeyID, Series: b.Series, Meta: b.Meta, BlueprintID: b.Draw.BlueprintID, InputCommit: b.Draw.InputCommit,
		SoldOut: b.Draw.SoldOut, Nonce: b.Nonce, KeyCommit: keyCommit, Props: props, Sig: sig}, nil
}

// Verify is the player's check before giving up the input: the issuer signed
// this, for this blueprint, against this player's commitment.
func (t Ticket) Verify(keys map[uint8][]byte, bp Blueprint, inputCommit [32]byte) error {
	if err := verifyFrom(keys, t.KeyID, t.signed(), t.Sig); err != nil {
		return err
	}
	if err := t.box().checkBlueprint(bp); err != nil {
		return err
	}
	if t.InputCommit != inputCommit {
		return ErrInput
	}
	return nil
}

// checkBlueprint says the box was drawn from this blueprint.
func (b Box) checkBlueprint(bp Blueprint) error {
	if b.Draw == nil {
		return ErrNotDrawn
	}
	if err := bp.check(); err != nil {
		return err
	}
	if b.Draw.BlueprintID != bp.ID() || b.Series != bp.Series || !bytes.Equal(b.Meta, bp.Meta) {
		return ErrWrongBlueprint
	}
	return checkSoldOut(bp, b.Draw.SoldOut)
}

// VerifyTicket is the player's check on a box that came for a ticket: it is the
// promised box, so the issuer did not choose the key after seeing the input.
// Check the ticket with Ticket.Verify first.
func (b Box) VerifyTicket(keys map[uint8][]byte, t Ticket) error {
	if err := b.Verify(keys); err != nil {
		return err
	}
	if b.Draw == nil {
		return ErrNotDrawn
	}
	if !bytes.Equal(b.header(), t.box().header()) || b.KeyCommit != t.KeyCommit {
		return ErrTicket
	}
	if b.Revision == 0 && !maps.Equal(b.Props, t.Props) {
		return ErrTicket
	}
	if commitInput(b.Draw.Input) != b.Draw.InputCommit {
		return ErrInput
	}
	return nil
}

// OpenItem opens a drawn box and checks the draw: anyone can recompute that the
// open key and the input give exactly the item inside, under the published odds,
// and that its serial is within the item's cap.
func (b Box) OpenItem(keys map[uint8][]byte, bp Blueprint, openKey []byte) (Drawn, error) {
	payload, err := b.Open(keys, openKey)
	if err != nil {
		return Drawn{}, err
	}
	if err := b.checkBlueprint(bp); err != nil {
		return Drawn{}, err
	}
	if commitInput(b.Draw.Input) != b.Draw.InputCommit {
		return Drawn{}, ErrInput
	}
	if len(payload) < 8 {
		return Drawn{}, ErrDraw
	}
	serial := binary.BigEndian.Uint64(payload)
	item := bp.pick(openKey, b.Draw.Input, b.Draw.SoldOut)
	if item.ID != string(payload[8:]) || !validSerial(bp, item, serial) {
		return Drawn{}, ErrDraw
	}
	return Drawn{Item: item, Serial: serial}, nil
}

// prepare builds an unsigned ticket. The nonce leaves out the plaintext, which
// does not exist yet; one input gives one plaintext, so a key still encrypts only
// one thing. It fixes what is sold out now, before anyone can know the result.
func (is *Issuer) prepare(rng io.Reader, caps Caps, bp Blueprint, inputCommit [32]byte, props map[string]string) (Ticket, error) {
	if err := bp.check(); err != nil {
		return Ticket{}, err
	}
	if err := checkProps(props); err != nil {
		return Ticket{}, err
	}
	var soldOut []uint16
	if bp.capped() {
		if caps == nil {
			return Ticket{}, ErrNoCaps
		}
		ids, err := caps.SoldOut(bp.ID())
		if err != nil {
			return Ticket{}, err
		}
		for i, it := range bp.Items {
			if it.Cap > 0 && slices.Contains(ids, it.ID) {
				soldOut = append(soldOut, uint16(i))
			}
		}
		if len(soldOut) == len(bp.Items) {
			return Ticket{}, ErrSoldOut
		}
	}
	var entropy [32]byte
	if _, err := io.ReadFull(rng, entropy[:]); err != nil {
		return Ticket{}, err
	}
	t := Ticket{KeyID: is.KeyID, Series: bp.Series, Meta: bp.Meta, BlueprintID: bp.ID(), InputCommit: inputCommit, SoldOut: soldOut, Props: props}
	copy(t.Nonce[:], kdf(is.root, tagNonce, entropy[:], t.box().prefix()))
	copy(t.KeyCommit[:], kdf(is.Key(t.box()), tagCommit))
	return t, nil
}

// draw fills the box a ticket promised. The same ticket and input always give the
// same box. Every draw of a capped blueprint takes a serial, whatever the item, so
// the time it takes does not tell a capped item from any other.
func (is *Issuer) draw(caps Caps, t Ticket, bp Blueprint, input [32]byte) (Box, error) {
	b := t.box()
	b.Draw.Input = input
	openKey := is.Key(b)
	item := bp.pick(openKey, input, t.SoldOut)
	in := b.keyInput()
	var serial uint64
	if bp.capped() {
		if caps == nil {
			return Box{}, ErrNoCaps
		}
		next, ok, err := caps.Take(t.BlueprintID, item.ID, item.Cap, in)
		if err != nil {
			return Box{}, err
		}
		if !ok {
			return Box{}, ErrSoldOut
		}
		serial = next
	}
	payload := append(binary.BigEndian.AppendUint64(nil, serial), item.ID...)
	plain, _ := pad(payload, bp.size()) // size fits every id
	b.Ciphertext = aead(openKey).Seal(nil, zeroNonce, plain, in[:])
	b.Sig = is.signBox(b)
	return b, nil
}

// Mint creates a box with an item drawn from the blueprint, in one call, with no
// player involved. The odds are exact and nobody without the main key can predict
// the item, but the issuer is trusted not to mint again until it likes the result.
// When a player is there to take part, use Ticket and Redeem instead, which take
// that choice away. caps may be nil if the blueprint has no caps. An item that sells
// out during the call is simply left out of a new draw. rng is crypto/rand.Reader
// outside of tests.
func (is *Issuer) Mint(rng io.Reader, caps Caps, bp Blueprint, props map[string]string) (Box, error) {
	// Each new try has one more item sold out, so this many are enough.
	for range len(bp.Items) + 1 {
		req, err := NewDrawRequest(rng)
		if err != nil {
			return Box{}, err
		}
		t, err := is.prepare(rng, caps, bp, req.Commit, props)
		if err != nil {
			return Box{}, err
		}
		b, err := is.draw(caps, t, bp, req.Input)
		if !errors.Is(err, ErrSoldOut) {
			return b, err
		}
	}
	return Box{}, ErrSoldOut
}

// Ticket answers a player's commitment with a signed promise of one box. It holds
// no state. Each ticket is one box, so give out one per purchase. props are the
// box's properties at revision 0. caps may be nil if the blueprint has no caps.
func (is *Issuer) Ticket(rng io.Reader, caps Caps, bp Blueprint, inputCommit [32]byte, props map[string]string) (Ticket, error) {
	t, err := is.prepare(rng, caps, bp, inputCommit, props)
	if err != nil {
		return Ticket{}, err
	}
	t.Sig, _ = is.sign.SignDeterministic(t.signed(), nil) // an empty context cannot fail
	return t, nil
}

// Redeem turns a ticket and the player's input into the box. The commitment admits
// one input, and asking again returns the same box, so a retry is safe and a ticket
// cannot give two boxes. With no caps it holds no state at all. With caps, an item
// that sold out since the ticket gives ErrSoldOut, and the ticket is refunded.
func (is *Issuer) Redeem(caps Caps, t Ticket, bp Blueprint, input [32]byte) (Box, error) {
	if err := verifyFrom(is.keys(), t.KeyID, t.signed(), t.Sig); err != nil {
		return Box{}, err
	}
	if err := t.box().checkBlueprint(bp); err != nil {
		return Box{}, err
	}
	if commitInput(input) != t.InputCommit {
		return Box{}, ErrInput
	}
	return is.draw(caps, t, bp, input)
}
