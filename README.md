# Honeypot

**The Honeypot protocol**: post-quantum safe lootboxes whose contents are fixed at
creation and readable only with a key.

A **blueprint** publishes which items a box can hold and how likely each one is, as
exact whole-number odds, with an optional cap per item. An issuer draws an item and
seals it into a box. Anyone can verify that the box is genuine against the issuer's
public key, and read its public properties, such as who it belongs to. Only the
issuer can change those. Nobody can read the contents or test a guess of what is
inside. One key opens the box, and that key is not stored anywhere: the issuer derives
it from its main key and the box whenever it is needed. A player who takes part in the
draw can prove afterwards that the issuer did not choose the item.

| Step | Who | Needs |
|---|---|---|
| publish a blueprint | issuer | nothing secret |
| draw a box | issuer, and the player if present | main key, the blueprint, a counter if it has caps |
| seal a box by hand | issuer | main key |
| verify a box, read its properties | anyone | issuer public key |
| rewrite properties | issuer | main key, a ledger |
| derive the open key | issuer | main key, the box |
| check a key against a box | anyone | the box, the open key |
| open a box | anyone | issuer public key, the box, the open key |
| claim a box, once | whoever grants the contents | a ledger, one row per box rewritten or opened |

A key opens exactly one box. It cannot be made to work only once, since nobody
can stop a second decryption, so the single claim is enforced by the ledger. The
same goes for properties: an old signed copy of a box stays valid forever, so
whether a property is still the latest takes the ledger too. What a box holds, how
it looks and what opening it grants is up to each application, in its **series
profile**.

Post-quantum: boxes are signed with ML-DSA-65 (FIPS 204), and everything else is
symmetric (HMAC-SHA-256, AES-256-GCM). A box holds no public-key encryption, so
recording boxes today does not help anyone read them later. A box is about 3.4 KB.

Status: **draft, not audited**. The specification is still moving. Go implements
all of it; the vectors pin the bytes for other languages. Not designed yet: proof of
a whole batch to the public (see "Planned").

## Install

| Language | Package |
|---|---|
| Go 1.27 or later | `go get github.com/PawnTown/honeypot/go@latest` |

No dependencies: ML-DSA comes from `crypto/mldsa` in the standard library.

```go
issuer, _ := honeypot.NewIssuer(1, mainKey)

// The odds: 90 %, 9.9 %, 0.1 %, exactly. A cap is optional, here 10 legendary swords.
blueprint, _ := honeypot.NewBlueprint("acme/season-1/gold", nil, []honeypot.Item{
	{ID: "wooden sword", Weight: 900},
	{ID: "silver shield", Weight: 99},
	{ID: "legendary sword", Weight: 1, Cap: 10},
})
props := map[string]string{honeypot.PropUser: "alice"}

// A draw in one call, with no player present. The issuer is trusted here.
// caps counts capped items. It can be nil for a blueprint with no caps.
box, _ := issuer.Mint(rand.Reader, caps, blueprint, props)

// A draw the issuer cannot steer: each side commits before seeing the other's part.
keys := map[uint8][]byte{1: issuer.Public()}
request, _ := honeypot.NewDrawRequest(rand.Reader)                              // player
ticket, _ := issuer.Ticket(rand.Reader, caps, blueprint, request.Commit, props) // issuer
err := ticket.Verify(keys, blueprint, request.Commit)                           // player
odds := ticket.Available(blueprint)                                             // player
box, _ = issuer.Redeem(caps, ticket, blueprint, request.Input)                  // issuer
err = box.VerifyTicket(keys, ticket)                                            // player

// Anyone: genuine, belongs to alice, contents unknown.
err = box.Verify(keys)
owner := box.Props[honeypot.PropUser]

// Only the main key can rewrite. Same id, same contents, same open key.
box, err = issuer.Rewrite(ledger, box, map[string]string{honeypot.PropUser: "bob"})

// Later: the key is derived, one claim per box, old revisions refused.
openKey, err := issuer.Release(ledger, box, "bob")

// The item and its serial, recomputed from the key and the input under the odds.
drawn, err := box.OpenItem(keys, blueprint, openKey)
```

## Layout

| Path | What |
|---|---|
| [`spec/HONEYPOT.md`](spec/HONEYPOT.md) | the protocol |
| [`vectors/`](vectors) | conformance test vectors every implementation must pass |
| [`go/`](go) | Go implementation (`github.com/PawnTown/honeypot/go`), 100 % test coverage |

## Go

```bash
cd go
go test -cover ./...
go test . -update     # regenerate the vectors
```

## Planned

- a series manifest: proof of a whole batch to everyone
- `js/` and `dart/`
- `rust/`

## License

MIT, see [LICENSE](LICENSE).
