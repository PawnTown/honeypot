package honeypot

import (
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"strings"
	"unicode/utf8"
)

// TagBlueprint starts every blueprint (spec "Naming").
const TagBlueprint = "HPBLP001"

// ErrBlueprint is a blueprint that breaks the rules: no items, an id that is
// empty, too long, not text, repeated or out of order, or a weight of zero.
var ErrBlueprint = errors.New("honeypot: malformed blueprint")

// Item is one thing a box can hold. Its chance is exactly Weight / Total, with
// no floating point anywhere. Cap is optional: at most this many will ever exist,
// and 0 means no limit (spec "Caps").
type Item struct {
	ID     string
	Weight uint32
	Cap    uint32
}

// Blueprint is the public list of what a box can hold and how likely each item
// is (spec "Blueprints"). Items are sorted by ID, so a blueprint has one byte form
// and one id.
type Blueprint struct {
	Series string
	Meta   []byte
	Items  []Item
}

// NewBlueprint sorts the items and checks the rules.
func NewBlueprint(series string, meta []byte, items []Item) (Blueprint, error) {
	sorted := slices.SortedFunc(slices.Values(items), func(a, b Item) int { return strings.Compare(a.ID, b.ID) })
	bp := Blueprint{Series: series, Meta: meta, Items: sorted}
	if err := bp.check(); err != nil {
		return Blueprint{}, err
	}
	return bp, nil
}

func (bp Blueprint) check() error {
	if len(bp.Series) > math.MaxUint8 || len(bp.Meta) > math.MaxUint16 {
		return ErrTooLong
	}
	if len(bp.Items) == 0 || len(bp.Items) > math.MaxUint16 {
		return ErrBlueprint
	}
	last := ""
	for _, it := range bp.Items {
		if it.ID <= last || len(it.ID) > math.MaxUint8 || !utf8.ValidString(it.ID) || it.Weight == 0 {
			return ErrBlueprint
		}
		last = it.ID
	}
	return nil
}

// Encode is the blueprint as it is published.
func (bp Blueprint) Encode() []byte {
	out := append([]byte(TagBlueprint), byte(len(bp.Series)))
	out = append(out, bp.Series...)
	out = appendU16(out, uint16(len(bp.Meta)))
	out = append(out, bp.Meta...)
	out = appendU16(out, uint16(len(bp.Items)))
	for _, it := range bp.Items {
		out = append(append(out, byte(len(it.ID))), it.ID...)
		out = appendU32(out, it.Weight)
		out = appendU32(out, it.Cap)
	}
	return out
}

// DecodeBlueprint decodes one blueprint and checks the rules.
func DecodeBlueprint(raw []byte) (Blueprint, error) {
	r := &reader{b: raw}
	r.tag(TagBlueprint)
	bp := Blueprint{Series: string(r.take(int(r.u8())))}
	bp.Meta = r.take(int(r.u16()))
	n := int(r.u16())
	for range n {
		id := string(r.take(int(r.u8())))
		bp.Items = append(bp.Items, Item{ID: id, Weight: r.u32(), Cap: r.u32()})
	}
	if r.err == nil && len(r.b) != 0 {
		r.err = ErrTrailing
	}
	if r.err != nil {
		return Blueprint{}, r.err
	}
	if err := bp.check(); err != nil {
		return Blueprint{}, err
	}
	return bp, nil
}

// ID identifies a blueprint: the hash of its bytes. Other odds are another id.
func (bp Blueprint) ID() [32]byte { return sha256.Sum256(bp.Encode()) }

// Total is the sum of the weights.
func (bp Blueprint) Total() uint64 { return totalWeight(bp.Items) }

// totalWeight cannot overflow: at most 65535 items of at most 2^32 - 1 each.
func totalWeight(items []Item) uint64 {
	var total uint64
	for _, it := range items {
		total += uint64(it.Weight)
	}
	return total
}

// capped says whether any item has a cap, which is what makes a draw need state.
func (bp Blueprint) capped() bool {
	return slices.ContainsFunc(bp.Items, func(it Item) bool { return it.Cap > 0 })
}

// available is what a draw can give once the sold out items are left out.
func (bp Blueprint) available(soldOut []uint16) []Item {
	var items []Item
	for i, it := range bp.Items {
		if !slices.Contains(soldOut, uint16(i)) {
			items = append(items, it)
		}
	}
	return items
}

// size is the plaintext size of every box of this blueprint: enough for a serial
// and the longest id, so the size of a box says nothing about which item it holds.
func (bp Blueprint) size() int {
	longest := 0
	for _, it := range bp.Items {
		longest = max(longest, len(it.ID))
	}
	return longest + 2 + 8
}

// at maps a number below the total weight to its item: each item covers exactly
// Weight numbers.
func at(items []Item, r uint64) Item {
	i := 0
	for r >= uint64(items[i].Weight) {
		r -= uint64(items[i].Weight)
		i++
	}
	return items[i]
}

// pick is the draw: the item an open key and an input give, out of what was not
// sold out when the issuer signed the ticket.
func (bp Blueprint) pick(openKey []byte, input [32]byte, soldOut []uint16) Item {
	items := bp.available(soldOut)
	return at(items, roll(openKey, bp.ID(), input, totalWeight(items)))
}
