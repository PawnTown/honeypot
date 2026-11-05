package honeypot

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
)

func TestNewBlueprint(t *testing.T) {
	a := gold(t)
	b, err := NewBlueprint(chest.Series, chest.Meta, []Item{{"legendary sword of the first dawn", 1, 0}, {"wooden sword", 900, 0}, {"silver shield", 99, 0}})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != b.ID() {
		t.Fatal("the order of the items must not matter")
	}
	if a.Total() != 1000 {
		t.Fatal(a.Total())
	}
	got, err := DecodeBlueprint(a.Encode())
	if err != nil || got.ID() != a.ID() || !bytes.Equal(got.Encode(), a.Encode()) {
		t.Fatalf("%v", err)
	}
	// Other odds, other id.
	c, _ := NewBlueprint(chest.Series, chest.Meta, []Item{{"legendary sword of the first dawn", 2, 0}, {"wooden sword", 900, 0}, {"silver shield", 99, 0}})
	if a.ID() == c.ID() {
		t.Fatal("the id must cover the odds")
	}
}

func TestBlueprintRejects(t *testing.T) {
	ok := []Item{{"a", 1, 0}}
	for name, items := range map[string][]Item{
		"no items":    nil,
		"empty id":    {{"", 1, 0}},
		"long id":     {{strings.Repeat("x", 256), 1, 0}},
		"binary id":   {{"\xff", 1, 0}},
		"duplicate":   {{"a", 1, 0}, {"a", 2, 0}},
		"zero weight": {{"a", 0, 0}},
		"too many":    make([]Item, 65536),
	} {
		if _, err := NewBlueprint("s", nil, items); !errors.Is(err, ErrBlueprint) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_, err := NewBlueprint(strings.Repeat("s", 256), nil, ok)
	want(t, err, ErrTooLong)
	_, err = NewBlueprint("s", make([]byte, 65536), ok)
	want(t, err, ErrTooLong)

	raw := gold(t).Encode()
	_, err = DecodeBlueprint(nil)
	want(t, err, ErrShort)
	_, err = DecodeBlueprint(append([]byte("HPBLP999"), raw[8:]...))
	want(t, err, ErrTag)
	_, err = DecodeBlueprint(append(bytes.Clone(raw), 0))
	want(t, err, ErrTrailing)
	for n := range raw {
		if _, err := DecodeBlueprint(raw[:n]); err == nil {
			t.Fatalf("truncated to %d bytes and decoded", n)
		}
	}
	unsorted := Blueprint{Series: "s", Items: []Item{{"b", 1, 0}, {"a", 1, 0}}}
	_, err = DecodeBlueprint(unsorted.Encode())
	want(t, err, ErrBlueprint)
	zero := Blueprint{Series: "s", Items: []Item{{"a", 0, 0}}}
	_, err = DecodeBlueprint(zero.Encode())
	want(t, err, ErrBlueprint)
}

// Every item covers exactly its weight of the numbers: the odds are exact, not
// close. Checked over all numbers.
func TestItemsCoverExactlyTheirWeight(t *testing.T) {
	bp := gold(t)
	counts := map[string]uint64{}
	for r := range bp.Total() {
		counts[at(bp.Items, r).ID]++
	}
	for _, it := range bp.Items {
		if counts[it.ID] != uint64(it.Weight) {
			t.Fatalf("%s covers %d, weight %d", it.ID, counts[it.ID], it.Weight)
		}
	}
}

// What is left after rejecting divides evenly by total, for any total, so
// x % total is exactly uniform. Checked with big numbers, not with the same
// 64-bit arithmetic.
func TestRejectionRemovesTheModuloBias(t *testing.T) {
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	for _, total := range []uint64{1, 2, 3, 7, 10, 1000, 1 << 32, 1<<32 - 1, 281470681677825, 1<<63 + 1, 1<<64 - 1} {
		reject := -total % total
		kept := new(big.Int).Sub(two64, new(big.Int).SetUint64(reject))
		if new(big.Int).Mod(kept, new(big.Int).SetUint64(total)).Sign() != 0 {
			t.Fatalf("total %d leaves a bias", total)
		}
	}
}

// Past half of all values are rejected at this total, so the retry runs and the
// result still stays in range.
func TestRollRetriesOnRejection(t *testing.T) {
	total := uint64(1<<63 + 1)
	key, id := seed("roll key"), sha256.Sum256([]byte("blueprint"))
	retried := false
	for i := range 64 {
		input := entropyOf(fmt.Sprint(i))
		first := kdf(key, tagRoll, id[:], input[:], appendU32(nil, 0))
		if new(big.Int).SetBytes(first[:8]).Cmp(new(big.Int).SetUint64(-total%total)) < 0 {
			retried = true
		}
		if r := roll(key, id, input, total); r >= total {
			t.Fatal(r)
		}
	}
	if !retried {
		t.Fatal("no draw was rejected")
	}
}

// chiSquare of the observed counts against the weights.
func chiSquare(bp Blueprint, counts map[string]int, n int) float64 {
	var chi float64
	for _, it := range bp.Items {
		expected := float64(n) * float64(it.Weight) / float64(bp.Total())
		d := float64(counts[it.ID]) - expected
		chi += d * d / expected
	}
	return chi
}

// A draw is fair if either side is honest: with the key fixed by a dishonest
// issuer and the input random, and with the input fixed by a dishonest player and
// the key random. The seeds are fixed, so this test cannot flake. 13.82 is the
// 99.9 % point of chi-square with 2 degrees of freedom.
func TestDrawMatchesTheOddsIfEitherSideIsHonest(t *testing.T) {
	bp := gold(t)
	const n = 200_000
	fixedKey, fixedInput := seed("issuer fixes this key"), entropyOf("player fixes this input")
	for name, next := range map[string]func(i int) ([]byte, [32]byte){
		"issuer fixes the key":   func(i int) ([]byte, [32]byte) { return fixedKey, entropyOf(fmt.Sprint("in", i)) },
		"player fixes the input": func(i int) ([]byte, [32]byte) { return seed(fmt.Sprint("key", i)), fixedInput },
	} {
		counts := map[string]int{}
		for i := range n {
			key, input := next(i)
			counts[bp.pick(key, input, nil).ID]++
		}
		if chi := chiSquare(bp, counts, n); chi > 13.82 {
			t.Fatalf("%s: chi-square %.2f, counts %v", name, chi, counts)
		}
	}
}

func TestMint(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	bp := gold(t)
	counts := map[string]int{}
	size := -1
	for range 300 {
		b, err := is.Mint(rand.Reader, nil, bp, map[string]string{PropUser: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		raw := b.Encode()
		if size != -1 && len(raw) != size {
			t.Fatal("the size of a box says which item it holds")
		}
		size = len(raw)
		got, err := DecodeBox(raw)
		if err != nil {
			t.Fatal(err)
		}
		item, err := got.OpenItem(keys, bp, is.Key(got))
		if err != nil {
			t.Fatal(err)
		}
		// Nothing public says which it is.
		for _, it := range bp.Items {
			if bytes.Contains(raw, []byte(it.ID)) {
				t.Fatal("item visible in the box")
			}
		}
		if got.Props[PropUser] != "alice" || got.Draw.BlueprintID != bp.ID() || got.Series != bp.Series {
			t.Fatal("public fields lost")
		}
		// The key decrypts the payload, and the payload names the item.
		payload, err := got.Open(keys, is.Key(got))
		if err != nil || string(payload[8:]) != item.Item.ID || item.Serial != 0 {
			t.Fatalf("%q %v", payload, err)
		}
		counts[item.Item.ID]++
	}
	if counts["wooden sword"] < 200 {
		t.Fatalf("%v", counts)
	}
}

// oneRead gives one input and then runs dry.
func oneRead() io.Reader { return io.LimitReader(rand.Reader, 32) }

func TestMintAndTicketReject(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	bp := gold(t)
	_, err := NewDrawRequest(failReader{})
	want(t, err, errRNG)
	_, err = is.Mint(failReader{}, nil, bp, nil)
	want(t, err, errRNG)
	_, err = is.Mint(oneRead(), nil, bp, nil)
	want(t, err, io.EOF)
	_, err = is.Ticket(failReader{}, nil, bp, [32]byte{}, nil)
	want(t, err, errRNG)
	_, err = is.Mint(rand.Reader, nil, Blueprint{}, nil)
	want(t, err, ErrBlueprint)
	_, err = is.Ticket(rand.Reader, nil, bp, [32]byte{}, map[string]string{"": "x"})
	want(t, err, ErrProperty)
}

// fairDraw runs the whole exchange.
func fairDraw(t *testing.T, is *Issuer, bp Blueprint, props map[string]string) (DrawRequest, Ticket, Box) {
	t.Helper()
	req, err := NewDrawRequest(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := is.Ticket(rand.Reader, nil, bp, req.Commit, props)
	if err != nil {
		t.Fatal(err)
	}
	box, err := is.Redeem(nil, ticket, bp, req.Input)
	if err != nil {
		t.Fatal(err)
	}
	return req, ticket, box
}

func TestTicketFlow(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	bp := gold(t)
	props := map[string]string{PropUser: "alice"}

	// The player commits, the issuer promises.
	req, err := NewDrawRequest(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := is.Ticket(rand.Reader, nil, bp, req.Commit, props)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTicket(ticket.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Encode(), ticket.Encode()) {
		t.Fatal("a ticket has more than one byte form")
	}
	if err := got.Verify(keys, bp, req.Commit); err != nil {
		t.Fatal(err)
	}

	// The player reveals, the issuer fills the box.
	box, err := is.Redeem(nil, got, bp, req.Input)
	if err != nil {
		t.Fatal(err)
	}
	held, err := DecodeBox(box.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if err := held.VerifyTicket(keys, got); err != nil {
		t.Fatal(err)
	}

	// Asking again gives the very same box, so a ticket is one box, with no state.
	again, err := is.Redeem(nil, got, bp, req.Input)
	if err != nil || !bytes.Equal(again.Encode(), box.Encode()) {
		t.Fatalf("%v", err)
	}

	// Claim and open, as for any box.
	l := newLedger()
	key, err := is.Release(l, held, "alice")
	if err != nil {
		t.Fatal(err)
	}
	item, err := held.OpenItem(keys, bp, key)
	if err != nil || item.Item != bp.pick(key, req.Input, nil) {
		t.Fatalf("%v %v", item, err)
	}

	// A rewrite keeps the draw, and the ticket check still passes.
	moved, err := is.Rewrite(l, held, map[string]string{PropUser: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err := moved.VerifyTicket(keys, got); err != nil {
		t.Fatal(err)
	}
	if item2, err := moved.OpenItem(keys, bp, key); err != nil || item2 != item {
		t.Fatalf("%v %v", item2, err)
	}
}

// The player's guarantees: what comes back has to be what was promised.
func TestTicketRejects(t *testing.T) {
	is, other := mustIssuer(t, 1, mainTag), mustIssuer(t, 1, otherTag)
	keys := is.keys()
	bp := gold(t)
	other2, _ := NewBlueprint(bp.Series, bp.Meta, []Item{{"x", 1, 0}})
	req, ticket, box := fairDraw(t, is, bp, nil)

	// A ticket that is not for this player, this blueprint or this issuer.
	want(t, ticket.Verify(keys, bp, [32]byte{1}), ErrInput)
	want(t, ticket.Verify(keys, other2, req.Commit), ErrWrongBlueprint)
	want(t, ticket.Verify(keys, Blueprint{}, req.Commit), ErrBlueprint)
	want(t, ticket.Verify(other.keys(), bp, req.Commit), ErrSignature)
	want(t, ticket.Verify(map[uint8][]byte{}, bp, req.Commit), ErrUnknownKey)
	otherSeries, _ := NewBlueprint("other", bp.Meta, bp.Items)
	forged := ticket
	forged.BlueprintID = otherSeries.ID()
	forged.Sig = is.signTicket(forged)
	want(t, forged.Verify(keys, otherSeries, req.Commit), ErrWrongBlueprint)

	// The issuer only redeems its own tickets, with the one input.
	_, err := is.Redeem(nil, ticket, bp, [32]byte{1})
	want(t, err, ErrInput)
	_, err = is.Redeem(nil, ticket, other2, req.Input)
	want(t, err, ErrWrongBlueprint)
	_, err = other.Redeem(nil, ticket, bp, req.Input)
	want(t, err, ErrSignature)

	// A box other than the promised one: the issuer changed the key after seeing
	// the input, which is what the ticket exists to stop.
	_, _, otherBox := fairDraw(t, is, bp, nil)
	want(t, otherBox.VerifyTicket(keys, ticket), ErrTicket)
	swapped := box
	swapped.KeyCommit[0] ^= 1
	swapped.Sig = is.signBox(swapped)
	want(t, swapped.VerifyTicket(keys, ticket), ErrTicket)
	assigned := box
	assigned.Props = map[string]string{PropUser: "mallory"}
	assigned.Sig = is.signBox(assigned)
	want(t, assigned.VerifyTicket(keys, ticket), ErrTicket)

	// Input other than the committed one.
	wrong := box
	d := *box.Draw
	d.Input[0] ^= 1
	wrong.Draw = &d
	wrong.Sig = is.signBox(wrong)
	want(t, wrong.VerifyTicket(keys, ticket), ErrInput)
	_, err = wrong.OpenItem(keys, bp, is.Key(wrong))
	want(t, err, ErrInput)

	// Not signed, and not drawn at all.
	want(t, box.VerifyTicket(other.keys(), ticket), ErrSignature)
	hand := sealAt(t, is, "a", chest, []byte("sword"))
	want(t, hand.VerifyTicket(keys, ticket), ErrNotDrawn)
	_, err = hand.OpenItem(keys, bp, is.Key(hand))
	want(t, err, ErrNotDrawn)

	// Opening checks the blueprint and the key.
	_, err = box.OpenItem(keys, other2, is.Key(box))
	want(t, err, ErrWrongBlueprint)
	_, err = box.OpenItem(keys, bp, make([]byte, KeySize))
	want(t, err, ErrWrongKey)
}

// The issuer signs a box whose contents are not what the draw gives: the rare item
// advertised, the common one delivered, or the reverse. Whoever opens it catches
// it, and holds proof.
func TestOpenItemCatchesAnIssuerThatPicksTheItem(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	bp := gold(t)
	_, _, b := fairDraw(t, is, bp, nil)
	key := is.Key(b)
	drawn := bp.pick(key, b.Draw.Input, nil)
	var other Item
	for _, it := range bp.Items {
		if it != drawn {
			other = it
		}
	}
	plain, err := pad(append(make([]byte, 8), other.ID...), bp.size())
	if err != nil {
		t.Fatal(err)
	}
	in := b.keyInput()
	b.Ciphertext = aead(key).Seal(nil, zeroNonce, plain, in[:])
	b.Sig = is.signBox(b)
	if err := b.Verify(is.keys()); err != nil {
		t.Fatal(err)
	}
	_, err = b.OpenItem(is.keys(), bp, key)
	want(t, err, ErrDraw)
}

func TestDecodeRejectsDraws(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	_, ticket, box := fairDraw(t, is, gold(t), nil)
	raw := ticket.Encode()
	_, err := DecodeTicket(nil)
	want(t, err, ErrShort)
	_, err = DecodeTicket(append([]byte("HPTKT999"), raw[8:]...))
	want(t, err, ErrTag)
	_, err = DecodeTicket(append(bytes.Clone(raw), 0))
	want(t, err, ErrTrailing)
	for n := range raw {
		if _, err := DecodeTicket(raw[:n]); err == nil {
			t.Fatalf("truncated to %d bytes and decoded", n)
		}
	}
	// A ticket always has a draw.
	hand := sealAt(t, is, "a", chest, []byte("sword"))
	noDraw := append([]byte(TagTicket), hand.header()...)
	noDraw = append(noDraw, hand.KeyCommit[:]...)
	noDraw = appendProps(noDraw, nil)
	_, err = DecodeTicket(append(noDraw, hand.Sig...))
	want(t, err, ErrDrawField)

	// The flag has two values.
	bad := box.Encode()
	bad[len(box.prefix())-67] = 2 // before two ids and an empty list
	_, err = DecodeBox(bad)
	want(t, err, ErrDrawField)

	// Every byte of a drawn box and of a ticket is covered: flip each one.
	keys := is.keys()
	rawBox := box.Encode()
	for i := range rawBox {
		flipped := bytes.Clone(rawBox)
		flipped[i] ^= 0x01
		got, err := DecodeBox(flipped)
		if err == nil && got.Verify(keys) == nil {
			t.Fatalf("box: flipped byte %d still verifies", i)
		}
	}
	bp := gold(t)
	for i := range raw {
		flipped := bytes.Clone(raw)
		flipped[i] ^= 0x01
		got, err := DecodeTicket(flipped)
		if err == nil && got.Verify(keys, bp, ticket.InputCommit) == nil {
			t.Fatalf("ticket: flipped byte %d still verifies", i)
		}
	}
}
