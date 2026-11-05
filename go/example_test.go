package honeypot_test

import (
	"crypto/rand"
	"fmt"

	honeypot "github.com/PawnTown/honeypot/go"
)

// memLedger stands in for a table with one row per box.
type memLedger map[[32]byte]*row

type row struct {
	rev   uint32
	owner string
}

func (l memLedger) get(id [32]byte, rev uint32) *row {
	if l[id] == nil {
		l[id] = &row{rev: rev}
	}
	return l[id]
}

func (l memLedger) Claim(id [32]byte, rev uint32, owner string) (string, error) {
	r := l.get(id, rev)
	if r.rev > rev {
		return "", honeypot.ErrStale
	}
	if r.owner == "" {
		r.owner = owner
	}
	return r.owner, nil
}

func (l memLedger) Advance(id [32]byte, rev uint32) (uint32, error) {
	r := l.get(id, rev)
	r.rev = max(r.rev, rev) + 1
	return r.rev, nil
}

func Example() {
	// The issuer: one main key, nothing else to keep.
	main := make([]byte, honeypot.KeySize)
	rand.Read(main)
	issuer, _ := honeypot.NewIssuer(1, main)
	ledger := memLedger{}

	// Sealing: the contents are fixed from here on.
	spec := honeypot.Spec{
		Series: "acme/season-1/gold",
		Props:  map[string]string{honeypot.PropUser: "alice"},
		Size:   256,
	}
	box, _ := issuer.Seal(rand.Reader, spec, []byte("legendary sword"))
	wire := box.Encode()

	// Anyone: the box is genuine and says whose it is, and nobody can tell what
	// is inside.
	keys := map[uint8][]byte{1: issuer.Public()}
	held, _ := honeypot.DecodeBox(wire)
	fmt.Println("genuine:", held.Verify(keys) == nil)
	fmt.Println("owner:", held.Props[honeypot.PropUser])

	// Only the main key can rewrite a property.
	moved, _ := issuer.Rewrite(ledger, held, map[string]string{honeypot.PropUser: "bob"})
	fmt.Println("owner:", moved.Props[honeypot.PropUser], "at revision", moved.Revision)

	// The previous owner's copy still verifies, but it no longer opens anything.
	_, err := issuer.Release(ledger, held, "alice")
	fmt.Println("alice:", err)

	// The issuer derives the key from the main key and the box.
	openKey, _ := issuer.Release(ledger, moved, "bob")
	payload, _ := moved.Open(keys, openKey)
	fmt.Printf("contents: %s\n", payload)

	// Output:
	// genuine: true
	// owner: alice
	// owner: bob at revision 1
	// alice: honeypot: a newer revision of this box exists
	// contents: legendary sword
}
