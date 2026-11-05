package honeypot

import (
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
)

// Deterministic keys and entropy, shared by the tests and the vectors.
func seed(tag string) []byte { s := sha256.Sum256([]byte(tag)); return s[:] }

func entropyOf(tag string) (e [32]byte) { copy(e[:], seed(tag)); return e }

func mustIssuer(t testing.TB, keyID uint8, tag string) *Issuer {
	t.Helper()
	is, err := NewIssuer(keyID, seed(tag))
	if err != nil {
		t.Fatal(err)
	}
	return is
}

const (
	mainTag  = "honeypot test main"
	otherTag = "honeypot test other"
)

var chest = Spec{Series: "acme/season-1/gold", Meta: []byte(`{"name":"Gold chest"}`), Size: 64}

// signTicket signs a ticket the way a dishonest issuer could.
func (is *Issuer) signTicket(t Ticket) []byte {
	sig, _ := is.sign.SignDeterministic(t.signed(), nil)
	return sig
}

// assigned is a chest that belongs to a user.
func assigned(user string) Spec {
	s := chest
	s.Props = map[string]string{PropUser: user}
	return s
}

// sealAt seals with fixed entropy.
func sealAt(t testing.TB, is *Issuer, tag string, spec Spec, payload []byte) Box {
	t.Helper()
	plain, err := pad(payload, spec.Size)
	if err != nil {
		t.Fatal(err)
	}
	return is.seal(entropyOf(tag), spec, plain)
}

// memLedger is the smallest Ledger; a real one is the two statements in the spec.
type memLedger struct {
	mu   sync.Mutex
	rows map[[32]byte]*ledgerRow
	err  error
}

type ledgerRow struct {
	rev     uint32
	owner   string
	claimed bool
}

func newLedger() *memLedger { return &memLedger{rows: map[[32]byte]*ledgerRow{}} }

func (l *memLedger) row(id [32]byte, rev uint32) *ledgerRow {
	r, ok := l.rows[id]
	if !ok {
		r = &ledgerRow{rev: rev}
		l.rows[id] = r
	}
	return r
}

func (l *memLedger) Claim(id [32]byte, rev uint32, owner string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return "", l.err
	}
	r := l.row(id, rev)
	if r.rev > rev {
		return "", ErrStale
	}
	if !r.claimed {
		r.owner, r.claimed = owner, true
	}
	return r.owner, nil
}

func (l *memLedger) Advance(id [32]byte, rev uint32) (uint32, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return 0, l.err
	}
	r := l.row(id, rev)
	r.rev = max(r.rev, rev) + 1
	return r.rev, nil
}

// gold is a blueprint with a rare item, and a longer id for the rare one.
func gold(t testing.TB) Blueprint {
	t.Helper()
	bp, err := NewBlueprint(chest.Series, chest.Meta, []Item{{"wooden sword", 900, 0}, {"silver shield", 99, 0}, {"legendary sword of the first dawn", 1, 0}})
	if err != nil {
		t.Fatal(err)
	}
	return bp
}

// failReader is an RNG that has run dry.
type failReader struct{}

var errRNG = errors.New("rng failed")

func (failReader) Read([]byte) (int, error) { return 0, errRNG }

// memCaps is the smallest Caps; a real one is the statements in the spec.
type memCaps struct {
	mu    sync.Mutex
	taken map[string]uint64
	caps  map[string]uint32
	draws map[string]uint64
	full  map[string]bool
	err   error
	// liar says an item is gone when asked to Take, but never lists it sold out.
	liar bool
}

func newCaps() *memCaps {
	return &memCaps{taken: map[string]uint64{}, caps: map[string]uint32{}, draws: map[string]uint64{}, full: map[string]bool{}}
}

func (c *memCaps) SoldOut([32]byte) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	var out []string
	for id := range c.full {
		out = append(out, id)
	}
	return out, nil
}

func (c *memCaps) Take(_ [32]byte, item string, cap uint32, draw [32]byte) (uint64, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, false, c.err
	}
	if c.liar {
		return 0, false, nil
	}
	key := item + string(draw[:])
	if serial, ok := c.draws[key]; ok {
		return serial, true, nil
	}
	if cap > 0 && c.taken[item] >= uint64(cap) {
		return 0, false, nil
	}
	c.taken[item]++
	if cap > 0 && c.taken[item] == uint64(cap) {
		c.full[item] = true
	}
	c.draws[key] = c.taken[item]
	return c.taken[item], true, nil
}
