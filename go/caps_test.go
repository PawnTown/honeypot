package honeypot

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// limited is mostly the capped item, so it sells out quickly.
func limited(t testing.TB, cap uint32) Blueprint {
	t.Helper()
	bp, err := NewBlueprint("acme/limited", nil, []Item{{"plain", 1, 0}, {"rare", 1_000_000, cap}})
	if err != nil {
		t.Fatal(err)
	}
	return bp
}

func TestCapIsPartOfTheBlueprint(t *testing.T) {
	a, b := limited(t, 10), limited(t, 11)
	if a.ID() == b.ID() {
		t.Fatal("the id must cover the cap")
	}
	got, err := DecodeBlueprint(a.Encode())
	if err != nil || got.Items[1].Cap != 10 {
		t.Fatalf("%v %v", got, err)
	}
	if !a.capped() || gold(t).capped() {
		t.Fatal("capped")
	}
}

// A blueprint with no caps never needs state: this is the default, and the rest of
// the draw tests use it with no Caps at all.
func TestNoCapsNeedsNoState(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	bp := gold(t)
	b, err := is.Mint(rand.Reader, nil, bp, nil)
	if err != nil {
		t.Fatal(err)
	}
	drawn, err := b.OpenItem(is.keys(), bp, is.Key(b))
	if err != nil || drawn.Serial != 0 || len(b.Draw.SoldOut) != 0 {
		t.Fatalf("%v %v", drawn, err)
	}
}

func TestCapsAreRequiredIfTheBlueprintHasCaps(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	bp := limited(t, 1)
	_, err := is.Mint(rand.Reader, nil, bp, nil)
	want(t, err, ErrNoCaps)
	_, err = is.Ticket(rand.Reader, nil, bp, [32]byte{}, nil)
	want(t, err, ErrNoCaps)
	req, _ := NewDrawRequest(rand.Reader)
	ticket, err := is.Ticket(rand.Reader, newCaps(), bp, req.Commit, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = is.Redeem(nil, ticket, bp, req.Input)
	want(t, err, ErrNoCaps)
}

// Never more than the cap, under a race, with every serial handed out once. Once
// sold out, boxes come from what is left.
func TestCapHoldsUnderARace(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	caps := newCaps()
	const cap = 5
	bp := limited(t, cap)
	var mu sync.Mutex
	serials := map[uint64]bool{}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				b, err := is.Mint(rand.Reader, caps, bp, nil)
				if err != nil {
					t.Error(err)
					return
				}
				drawn, err := b.OpenItem(keys, bp, is.Key(b))
				if err != nil {
					t.Error(err)
					return
				}
				if drawn.Item.ID != "rare" {
					continue
				}
				mu.Lock()
				if serials[drawn.Serial] || drawn.Serial < 1 || drawn.Serial > cap {
					t.Errorf("serial %d", drawn.Serial)
				}
				serials[drawn.Serial] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(serials) != cap {
		t.Fatalf("%d of %d units handed out", len(serials), cap)
	}
}

func TestTicketFixesWhatIsSoldOutBeforeTheInput(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	caps := newCaps()
	bp := limited(t, 1)

	// Two tickets at once, both still with the rare item in reach.
	first, _ := NewDrawRequest(rand.Reader)
	second, _ := NewDrawRequest(rand.Reader)
	t1, err := is.Ticket(rand.Reader, caps, bp, first.Commit, nil)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := is.Ticket(rand.Reader, caps, bp, second.Commit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(t1.Available(bp)) != 2 {
		t.Fatal(t1.Available(bp))
	}
	b1, err := is.Redeem(caps, t1, bp, first.Input)
	if err != nil {
		t.Fatal(err)
	}
	drawn, err := b1.OpenItem(keys, bp, is.Key(b1))
	if err != nil || drawn.Item.ID != "rare" || drawn.Serial != 1 {
		t.Fatalf("%v %v", drawn, err)
	}

	// A retry keeps the box and takes no second unit.
	again, err := is.Redeem(caps, t1, bp, first.Input)
	if err != nil || !bytes.Equal(again.Encode(), b1.Encode()) || caps.taken["rare"] != 1 {
		t.Fatalf("%v", err)
	}

	// The second draw lands on it too and may not get something else instead.
	_, err = is.Redeem(caps, t2, bp, second.Input)
	want(t, err, ErrSoldOut)

	// The next ticket says so, signed, before the player gives up an input.
	third, _ := NewDrawRequest(rand.Reader)
	t3, err := is.Ticket(rand.Reader, caps, bp, third.Commit, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTicket(t3.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(keys, bp, third.Commit); err != nil {
		t.Fatal(err)
	}
	if av := decoded.Available(bp); len(av) != 1 || av[0].ID != "plain" {
		t.Fatalf("%v", av)
	}
	b3, err := is.Redeem(caps, decoded, bp, third.Input)
	if err != nil {
		t.Fatal(err)
	}
	if err := b3.VerifyTicket(keys, decoded); err != nil {
		t.Fatal(err)
	}
	held, err := DecodeBox(b3.Encode())
	if err != nil {
		t.Fatal(err)
	}
	drawn, err = held.OpenItem(keys, bp, is.Key(held))
	if err != nil || drawn.Item.ID != "plain" || drawn.Serial != 1 {
		t.Fatalf("%v %v", drawn, err)
	}
}

// All boxes of a blueprint are the same size, sold out or not, capped item or not.
func TestCappedBoxesLookAlike(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	caps := newCaps()
	bp := limited(t, 1)
	a, err := is.Mint(rand.Reader, caps, bp, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := is.Mint(rand.Reader, caps, bp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Ciphertext) != len(b.Ciphertext) {
		t.Fatal("the size of the contents says which item")
	}
	if bytes.Contains(a.Encode(), []byte("rare")) {
		t.Fatal("item visible in the box")
	}
}

func TestSoldOutEverywhere(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	caps := newCaps()
	bp, err := NewBlueprint("acme/run", nil, []Item{{"a", 1, 1}, {"b", 1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := is.Mint(rand.Reader, caps, bp, nil); err != nil {
			t.Fatal(err)
		}
	}
	_, err = is.Mint(rand.Reader, caps, bp, nil)
	want(t, err, ErrSoldOut)
	_, err = is.Ticket(rand.Reader, caps, bp, [32]byte{}, nil)
	want(t, err, ErrSoldOut)
}

// A Caps that keeps saying no cannot hang Mint.
func TestMintStopsIfCapsKeepsRefusing(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	caps := newCaps()
	caps.liar = true
	_, err := is.Mint(rand.Reader, caps, limited(t, 1), nil)
	want(t, err, ErrSoldOut)
}

func TestCapsErrors(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	bp := limited(t, 1)
	caps := newCaps()
	req, _ := NewDrawRequest(rand.Reader)
	ticket, err := is.Ticket(rand.Reader, caps, bp, req.Commit, nil)
	if err != nil {
		t.Fatal(err)
	}
	caps.err = errors.New("db down")
	_, err = is.Mint(rand.Reader, caps, bp, nil)
	want(t, err, caps.err)
	_, err = is.Redeem(caps, ticket, bp, req.Input)
	want(t, err, caps.err)
}

// What a dishonest issuer could sign, and what catches it.
func TestCapsCatchADishonestIssuer(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	caps := newCaps()
	bp := limited(t, 3)

	// resealed gives the box another payload, signed.
	resealed := func(b Box, payload []byte) Box {
		plain, err := pad(payload, bp.size())
		if err != nil {
			t.Fatal(err)
		}
		in := b.keyInput()
		b.Ciphertext = aead(is.Key(b)).Seal(nil, zeroNonce, plain, in[:])
		b.Sig = is.signBox(b)
		return b
	}
	withSerial := func(serial uint64, id string) []byte {
		return append(binary.BigEndian.AppendUint64(nil, serial), id...)
	}
	b, err := is.Mint(rand.Reader, caps, bp, nil)
	if err != nil {
		t.Fatal(err)
	}
	drawn, err := b.OpenItem(keys, bp, is.Key(b))
	if err != nil {
		t.Fatal(err)
	}
	id := drawn.Item.ID
	for name, payload := range map[string][]byte{
		"no serial":     []byte("x"),
		"serial zero":   withSerial(0, id),
		"above the cap": withSerial(4, id),
		"another item":  withSerial(1, map[string]string{"rare": "plain", "plain": "rare"}[id]),
	} {
		_, err := resealed(b, payload).OpenItem(keys, bp, is.Key(b))
		if !errors.Is(err, ErrDraw) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// An item with no cap in a capped blueprint needs a serial too, and a blueprint
	// with no caps has none.
	plainBox := func() Box {
		for {
			pb, err := is.Mint(rand.Reader, caps, bp, nil)
			if err != nil {
				t.Fatal(err)
			}
			if d, err := pb.OpenItem(keys, bp, is.Key(pb)); err == nil && d.Item.ID == "plain" {
				return pb
			}
		}
	}()
	_, err = resealed(plainBox, withSerial(0, "plain")).OpenItem(keys, bp, is.Key(plainBox))
	want(t, err, ErrDraw)
	if !validSerial(bp, Item{ID: "plain"}, 1<<40) {
		t.Fatal("an item with no cap has no limit on its serial")
	}
	if validSerial(gold(t), gold(t).Items[0], 1) {
		t.Fatal("no caps, no serial")
	}

	// Only an item with a cap can be sold out, and something must be left.
	forge := func(soldOut []uint16) Ticket {
		req, _ := NewDrawRequest(rand.Reader)
		tk, err := is.Ticket(rand.Reader, caps, bp, req.Commit, nil)
		if err != nil {
			t.Fatal(err)
		}
		tk.SoldOut = soldOut
		tk.Sig = is.signTicket(tk)
		return tk
	}
	for name, soldOut := range map[string][]uint16{
		"item with no cap": {0},
		"out of range":     {9},
		"repeated":         {1, 1},
		"nothing left":     {0, 1},
	} {
		tk := forge(soldOut)
		err := tk.Verify(keys, bp, tk.InputCommit)
		if !errors.Is(err, ErrDrawField) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// The list has one byte form.
	_, err = DecodeTicket(forge([]uint16{1, 1}).Encode())
	want(t, err, ErrDrawField)
}

// The odds stay exact once something is sold out: the rest keep their weights over
// a smaller total. 13.82 is the 99.9 % point of chi-square with 2 degrees of
// freedom. The seeds are fixed, so this test cannot flake.
func TestOddsAfterSoldOutAreExact(t *testing.T) {
	bp, err := NewBlueprint("acme/odds", nil, []Item{{"a", 700, 0}, {"b", 250, 0}, {"gone", 45, 7}, {"c", 50, 0}})
	if err != nil {
		t.Fatal(err)
	}
	var gone uint16
	for i, it := range bp.Items {
		if it.ID == "gone" {
			gone = uint16(i)
		}
	}
	soldOut := []uint16{gone}
	rest := Blueprint{Items: bp.available(soldOut)}
	const n = 200_000
	counts := map[string]int{}
	key := seed("odds key")
	for i := range n {
		counts[bp.pick(key, entropyOf(fmt.Sprint("in", i)), soldOut).ID]++
	}
	if counts["gone"] != 0 {
		t.Fatal("a sold out item came up")
	}
	if chi := chiSquare(rest, counts, n); chi > 13.82 {
		t.Fatalf("chi-square %.2f, counts %v", chi, counts)
	}
}
