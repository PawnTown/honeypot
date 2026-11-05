# The Honeypot protocol (draft)

Status: draft, 2026-11-04. Not audited. The core is implemented in `go/`, pinned
by `vectors/`. Scope: any system that hands out sealed contents, such as game
loot, collectibles, coupons or mystery rewards. What a box holds and what
opening it grants is up to the application.

## Goal

A box is sealed once and its contents never change. Everyone can see that the
box is genuine and read its public properties, such as who it belongs to. Nobody
can tell or test what is inside, and one key opens it.

The issuer keeps a single secret, the **main key**. Open keys are not stored
anywhere: the issuer derives one from the main key and the box whenever it is
needed, and it comes out the same every time.

A **blueprint** publishes what a box can hold and how likely each item is, with an
optional cap on how many of an item will ever exist. A box drawn from it gets an
item with exactly those odds, and a player who takes part in the draw can prove
afterwards that the issuer did not choose the item.

The protocol is post-quantum safe. See "Post-quantum".

```
issuer                                         player, or anyone
  main key
     |
     |  seal(payload, properties)
     v
    box  ----------------------------------->  verify(box, issuer public key)
                                                  genuine, userId readable,
                                                  contents unknown
  rewrite(box, properties)
    box, revision + 1  --------------------->  same id, same contents, new owner
                                                  ... pays, plays, waits ...
         <----------- box, "open it" --------
  claim(box id, revision, owner)   one row, once
  key = derive(main key, box)
         ------------- open key ------------>  verify(box, open key)
                                               open(box, open key) = payload
```

## What a box can prove

| | Box alone | Box and open key |
|---|---|---|
| the issuer sealed it, and it is unchanged | yes | yes |
| the contents were fixed when it was sealed | yes | yes |
| its properties, and that the issuer stated them | yes | yes |
| what the contents are | no | yes |
| whether a guess of the contents is right | no | yes |
| whether two boxes hold the same thing | no | yes |
| this key belongs to this box | | yes |
| this key opens no other box | | yes |
| these properties are still the latest | no | no: the ledger does, see "Old revisions" |
| the box was opened only once | no | no: the ledger does, see "One time" |
| when it was sealed | no | no: signatures say what, never when |
| the item follows from the published odds | no | yes, for a drawn box |
| the issuer did not choose the item | no | yes, for the player who took part in the draw |

The last row matters. A sealed box stops the issuer changing what is inside. Only a
draw with the player taking part stops the issuer choosing it to begin with. See
"Drawing".

## Keys

One function derives everything:

```
KDF(key, tag, data...) = HMAC-SHA-256(key, tag | data...)
```

The **main key** is 32 bytes from a CSPRNG. It is not a passphrase: `KDF` adds no
stretching. It splits into two independent keys:

```
sign_seed = KDF(main, "HPSIGN01")    ML-DSA-65 seed (FIPS 204), signs boxes
open_root = KDF(main, "HPROOT01")    derives open keys
```

The ML-DSA-65 public key, 1952 bytes, is what verifiers pin, under a one-byte
`key_id`. Apps pin the keys they accept (rotation: ship the next key before using
it).

| Who | Holds | Can |
|---|---|---|
| issuer | main key | seal boxes, rewrite properties, derive any open key |
| player, game, anyone | public key | verify a box, read its properties, check a key, open with a key |

Rotate the main key per season or per series. Whoever has a main key can read
every box sealed under it, seal new ones and rewrite any property, so its reach
should stay small.

## Sealing a box

```
input:  key_id, series, meta, properties, size, payload,
        entropy [32] from a CSPRNG

plain      = u16(len(payload)) | payload | zeros, exactly `size` bytes
prefix     = "HPBOX001" | key_id u8 | series (u8 length + bytes)
             | meta (u16 length + bytes) | 0x00
nonce      = KDF(open_root, "HPNONC01", entropy, prefix, plain), first 16 bytes
header     = prefix | nonce
key_input  = SHA-256(header)

open_key   = KDF(open_root, "HPKEY001", key_input)
enc_key    = KDF(open_key, "HPENC001")
key_commit = KDF(open_key, "HPCOMT01")
ct         = AES-256-GCM(enc_key, nonce = 12 zero bytes, aad = key_input, plain)

sealed     = header | key_commit | ct (u16 length + bytes)
box_id     = SHA-256(sealed)

signed     = sealed | revision u32 | properties      revision starts at 0
sig        = ML-DSA-65(sign_seed, signed)
box        = signed | sig
```

The `0x00` says the box was sealed by hand. A drawn box differs in three places,
see "Drawing". Integers are big-endian. A box is 3393 bytes plus series, meta and
size, a drawn box 98 more plus 2 per sold out item, and each property adds 3 bytes
plus its name and value.

`sig` is ML-DSA.Sign of FIPS 204 with an empty context, in its deterministic
variant, so one box at one revision has one signature and the vectors reproduce.
A hedged signature verifies the same way; an issuer on hardware exposed to fault
attacks should prefer it.

| Field | Public meaning |
|---|---|
| `key_id` | which main key sealed it |
| `series` | namespace and kind of box, `acme/season-1/gold`, at most 255 bytes |
| `meta` | anything else public that must never change: name, tier. Opaque, at most 65535 bytes |
| `nonce` | makes the box unique, looks random |
| `key_commit` | pins the one open key |
| `ct` | the contents |
| `revision`, `properties` | see "Properties" |

Why each part is the way it is:

- **The key comes from the header, not the whole box.** The ciphertext needs the
  key, so the key cannot depend on the ciphertext. The header holds every fixed
  field that exists before encryption, so changing any of them gives another key.
- **`box_id` covers the ciphertext.** The id names the contents as well as the
  box, so a holder who keeps 32 bytes can tell that the contents never changed,
  through any number of rewrites.
- **`size` is fixed per series.** A ciphertext is as long as its plaintext. If a
  legendary item took more bytes than a common one, the size of the box would
  tell. Every box in a series uses the same `size`, large enough for its largest
  payload. A payload that does not fit is an error. `size` is at most 65519.
- **The nonce depends on the payload.** One open key must never encrypt two
  plaintexts, because AES-GCM with one key and one nonce fails badly. With the
  plaintext in the nonce, an RNG that repeats itself can at worst produce the
  same box twice. It also makes sealing deterministic for the test vectors.
- **The AEAD nonce can be zero** because an open key encrypts exactly one thing.
- **`key_commit` is required.** AES-GCM alone does not commit to its key: someone
  who picks the keys can make one ciphertext that decrypts under two of them, to
  two different payloads. The signed commitment rules that out, which is what
  makes the contents fixed. `KDF` with a 32-byte key cannot collide without a
  SHA-256 collision, and open keys must be exactly 32 bytes.

A box has one byte form: the lengths have one encoding, properties have one
order, and decoding rejects trailing bytes and any other tag.

## Blueprints

A blueprint is the public list of what a box can hold and how likely each item is.

```
blueprint    = "HPBLP001" | series (u8 length + bytes) | meta (u16 length + bytes)
               | count u16 | item...
item         = id (u8 length + UTF-8) | weight u32 | cap u32     cap 0: no limit
blueprint_id = SHA-256(blueprint)
```

| Item | Weight | Chance | Cap |
|---|---|---|---|
| `legendary sword` | 1 | 1 / 1000 = 0.1 % | 10 |
| `silver shield` | 99 | 99 / 1000 = 9.9 % | none |
| `wooden sword` | 900 | 900 / 1000 = 90 % | none |

- **Odds are whole numbers.** The chance of an item is exactly `weight / total`.
  There is no floating point, so nothing rounds and every language gets the same
  result.
- **Items are sorted by the bytes of their id,** with no duplicates and no empty
  ids, 1 to 65535 of them. Decoding rejects anything else, so a blueprint has one
  byte form and one id.
- **A weight is at least 1.** An item that can never come up cannot be listed, so a
  blueprint cannot advertise a prize that does not exist.
- **The id is the hash.** A blueprint has no signature of its own: the signed ticket
  and box name its `blueprint_id`, and any bytes that hash to it are the real thing.
  Other odds are another id. Publish the ids in use, so players can tell that
  everyone gets the same odds.

A box drawn from a blueprint takes its `series` and `meta`. Its payload is
`serial u64 | item id`, padded to `10 + longest id`, so all its boxes are the same
size. The serial is 0 unless the blueprint has caps. Item ids are public, so anything
secret per box, such as a coupon code, stays with the
application and is handed out when the claim goes through. Boxes sealed by hand are
still possible, but they do not prove any odds.

## Drawing

### The pick

The item follows from the open key and an `input`, with nothing else involved:

```
items  = the blueprint's items, without those the draw lists as sold out
total  = sum of their weights
reject = 2^64 mod total
for j = 0, 1, ...:
  x = first 8 bytes, big-endian, of
      KDF(open_key, "HPROLL01", blueprint_id, input, u32(j))
  if x >= reject: r = x mod total, stop
item = the item at r: walk items in order, subtract each weight
       from r until r is below the next weight
```

`x mod total` alone would be biased, because 2^64 does not divide evenly by `total`.
Dropping the lowest `2^64 mod total` values leaves a range that does, so `r` is
exactly uniform. No blueprint rejects more than 1 draw in 65536.

### Who chooses: nobody

If only the issuer supplies randomness, nobody can tell whether it minted until it
liked the result. So a player who is present adds their own, and each side commits
before it sees the other's part:

```
player                                        issuer
input  = 32 bytes from a CSPRNG
commit = KDF(input, "HPINPT01")
        ------- commit, blueprint id ------->
                                              prefix: ... | 0x01 | blueprint_id | commit | sold_out
                                              nonce  = KDF(open_root, "HPNONC01", entropy, prefix)
                                              open_key, key_commit from them, as in sealing
        <------------- ticket ---------------
ticket checks out
        --------------- input -------------->
                                              commit and ticket check out
                                              item = pick(open_key, input)
                                              box, with input in the signed part
        <-------- box, still closed ---------
box is the one the ticket promised
    ... the usual claim and release ...
item = pick(open_key, input), and it must equal the payload
```

```
ticket = "HPTKT001" | header | key_commit | properties | sig     ML-DSA-65
sealed = header | key_commit | input [32] | ct (u16 length + bytes)
```

`input` goes outside the header, so the open key is fixed before it is known. The
draw is fair if either side is honest:

- **An honest player:** the input is random and hidden when the issuer signs
  `key_commit`, and `key_commit` admits one key. The issuer cannot aim for an item,
  whatever key it picks.
- **An honest issuer:** the player's input is fixed by `commit` before the ticket
  exists, and the open key stays secret until the claim. The player cannot aim for
  an item either, or see it before the claim.

`commit` admits one input, so a ticket gives one box, and asking again returns the
very same box. With no caps, neither side keeps any state. Give out one ticket per
purchase.

The input is public from then on. It reveals nothing without the open key. Testing a
guess of the item still needs the 256-bit key.

### Without a player

`Mint` draws in one call, for boxes with nobody there to take part, such as rewards
from a server. The issuer plays both sides with a fresh input.

| | `Mint` | Ticket and `Redeem` |
|---|---|---|
| odds exact | yes | yes |
| nobody without the main key can predict the item | yes | yes |
| after opening, anyone can recompute the item from the key and the input | yes | yes |
| the issuer cannot choose the item | **no**: it could mint until it likes one | yes |
| works with no player present | yes | no |

Outsiders cannot tell the two apart, because only the player knows the input was
theirs. The proof is for the player in the draw. An issuer and a fake player of its
own can still choose an item, and the public cannot see that.

### What a draw cannot do

- **The issuer can refuse.** It sees the result once it has the input, and could
  decline to fill a box with a rare item. No two-party protocol can prevent that, but
  the refusal is visible: the player holds a signed ticket that was not honoured. The
  rule for clients: after a failure, retry with the same ticket and the same input,
  and never accept a replacement ticket for one that failed. A purchase should be
  refunded and counted if a ticket is not honoured.
- **An input must be fresh.** Once an issuer knows an input, it can pick a nonce that
  suits it. A client makes a new input for every draw.
- **Draws are independent.** A chance of 0.1 % does not mean exactly 1 in 1000 boxes:
  there can be more or fewer. An upper limit is what a cap is for.

## Caps

A cap is optional and set per item: at most this many will ever exist. Most items
need none, and a blueprint with no caps needs no state at all. Caps are part of the
blueprint, so they are public and in its id. To limit a whole run, cap every item.

### How a cap works

```
sold_out = positions of the items at their cap, read when the ticket is made
           u16 count | u16 position..., ascending, signed in the ticket and box
item     = pick(open_key, input), over the items not in sold_out
serial   = Take(blueprint_id, item, cap, SHA-256(header))
payload  = serial u64 | item id
```

- **What is sold out is fixed before the result can be known.** It is signed in the
  ticket before the issuer sees the input, so the player reads the exact odds of this
  draw first (`Ticket.Available`) and can walk away. Whatever is left keeps its weight
  over a smaller total, which is still exact. Only an item with a cap can be listed,
  and something must be left.
- **The issuer never swaps an item.** If a draw lands on an item that sold out after
  the ticket was signed, there is no second try: `Redeem` returns `ErrSoldOut` and the
  ticket is refunded. The item in a box is always exactly what the key and input give,
  caps or no caps. The next ticket must list the item as sold out. A client should
  check that, since otherwise the issuer just refused a win. `Mint` starts a new draw
  by itself.
- **The serial is the proof of the cap.** Every capped item is numbered from 1 to its
  cap, hidden in the payload until opening, and `OpenItem` checks the range. Two boxes
  with one serial of one item, or a serial above the cap, are signed proof of fraud,
  once their holders compare them. This is what `legendary sword #7 of 10` means.
- **Every draw takes a serial, whatever the item.** A blueprint with caps calls `Take`
  once per draw, so a slow response does not reveal a capped item. This costs one row
  per draw, and only for such a blueprint. Items with no cap are numbered too.

```sql
CREATE TABLE honeypot_caps (
  blueprint_id bytea  NOT NULL,
  item         text   NOT NULL,
  cap          bigint NOT NULL,
  taken        bigint NOT NULL,
  PRIMARY KEY (blueprint_id, item)
);
CREATE TABLE honeypot_units (
  blueprint_id bytea  NOT NULL,
  item         text   NOT NULL,
  serial       bigint NOT NULL,
  draw         bytea  NOT NULL,
  PRIMARY KEY (blueprint_id, item, serial),
  UNIQUE (blueprint_id, item, draw)
);

-- SoldOut(blueprint_id)
SELECT item FROM honeypot_caps
WHERE blueprint_id = $1 AND cap > 0 AND taken >= cap;

-- Take(blueprint_id, item, cap, draw): the serial. No row back: sold out.
-- On a unique violation, a retry of this draw won a race: run it again.
WITH prior AS (
  SELECT serial FROM honeypot_units
  WHERE blueprint_id = $1 AND item = $2 AND draw = $4
), bump AS (
  INSERT INTO honeypot_caps (blueprint_id, item, cap, taken)
  SELECT $1, $2, $3, 1 WHERE NOT EXISTS (SELECT 1 FROM prior)
  ON CONFLICT (blueprint_id, item) DO UPDATE
    SET taken = honeypot_caps.taken + 1
    WHERE honeypot_caps.cap = 0 OR honeypot_caps.taken < honeypot_caps.cap
  RETURNING taken
), unit AS (
  INSERT INTO honeypot_units (blueprint_id, item, serial, draw)
  SELECT $1, $2, taken, $4 FROM bump
  RETURNING serial
)
SELECT serial FROM prior UNION ALL SELECT serial FROM unit;
```

### What a cap cannot do

- **"Sold out" is the issuer's word.** It can list an item as sold out early, or draw
  capped items for itself until they run out, and nothing proves otherwise. The list
  is signed and comes before the result, so this cannot target a winning draw, and it
  shows: tickets given out at about the same time should agree.
- **Never publish live counts.** If "4 left" turns into "3 left" just after a draw,
  that player knows what is in their box without a key. Publish only that an item has
  sold out. Even that hints to whoever drew the last one, so publish it with a delay.
- **A unit in a box nobody opens stays taken.** A cap limits how many exist, not how
  many are in use.
- **A cap is an upper limit.** The series can end before it is reached.

## Properties

Properties are public facts about a box: who it belongs to, its level, whether it
was traded. Anyone can read them from the box, with no key and no server, and
verify them with the public key. Only the main key can change them.

```
properties = count u8 | entry...
entry      = name (u8 length + UTF-8) | value (u16 length + UTF-8)
```

Entries are sorted by the bytes of their name, with no duplicates and no empty
names, at most 255 of them. Values are text, so any tool can show them. Decoding
rejects anything else, so properties have one byte form.

The protocol knows one name, **`userId`**: a box that has it goes to that user
only (see "Opening"). A box without it goes to whoever claims it first. All other
names are up to the series profile.

| | `series`, `meta` | properties |
|---|---|---|
| readable by anyone, no key needed | yes | yes |
| signed by the issuer | yes | yes |
| can change | never: another value is another box with another key | with the main key: next revision, new signature |
| format | opaque | named text |

Use `meta` for what must never change, even by the issuer, and properties for what
should be able to.

Properties are public, for as long as anyone keeps a copy. Use an opaque `userId`,
not an e-mail address, and put nothing in them that says what the box holds.

### Rewriting

```
rewrite(box, properties):
  verify the box against the issuer's own public key
  revision = ledger.advance(box_id, box.revision)
  sig      = ML-DSA-65(sign_seed, sealed | revision u32 | properties)
```

A rewrite replaces all properties and signs again. `sealed` does not change, so
the box keeps its `box_id`, its open key and its contents. Rewriting cannot change
what is inside: other contents would be another `box_id`.

A rewrite does not take back an open key that was already released.

### Old revisions

**A signature cannot expire.** After a rewrite, the old revision still verifies
forever, and anyone may have kept a copy. `Verify` proves "the issuer stated this
at revision N". It cannot prove that N is the latest, and no check on the box
alone can. If it matters, the check needs newer information:

| Who is checking | How |
|---|---|
| the issuer releasing a key | the ledger refuses a revision below the one on record, built into `Release` |
| anyone holding two copies | the higher revision of the same `box_id` wins (`Supersedes`) |
| a service acting on a property, such as a trade | asks the issuer or the ledger for the current revision of `box_id` |
| an offline device | a profile can add an `expires` property and re-sign regularly, which limits the window but does not close it |

Treat a property read from a box alone as "true at some point". Two signed copies
of one `box_id` at one revision with different properties are portable proof that
the issuer cheated.

## Verifying

Two checks, and neither says what is inside.

**Against the issuer's public key:** `ML-DSA-65.verify(public[key_id], signed, sig)`
with an empty context. It covers everything in the box, including the revision and
the properties.

**Against an open key:** `key_commit == KDF(open_key, "HPCOMT01")`, in constant
time. Together they chain: the public key vouches for the box, and the box
vouches for the key. An open key needs no signature of its own.

### Why the contents cannot be checked

Box contents come from small sets. If a box published `SHA-256(payload)`, anyone
could hash `"sword"`, `"shield"` and every other item until one matched: the
contents would be sealed in name only.

So no public field can be computed from the payload without a secret. Testing a
guess needs `open_root` (nonce), or the 256-bit open key (`key_commit`, `ct`),
and neither can be searched for. Sealing the same payload twice gives two boxes
that have nothing in common.

## Opening

Opening is `AES-256-GCM.open` with the keys above, after verifying the box and
the open key. The payload is then read back from `plain`. Length past the end, or
a nonzero byte in the padding, is an error, so a plaintext has one byte form.

The issuer derives the open key when asked. The rules:

1. **The box first.** The player gets and verifies the box before paying or
   committing to anything. A box that arrives only after the purchase proves
   nothing about what was bought.
2. **The claim before the key.** The issuer verifies the signature, checks that
   `userId`, if the box has one, is the one asking, checks the application's rules,
   records the claim, and only then derives the key.
3. **A retry is safe.** The same owner asking again gets the same key, since it
   is derived and not used up. A lost response costs nothing.

### One time

A key opens one box, and that much is mathematics: `open_key` depends on the
header, and only one key passes the box's `key_commit`.

A key cannot be made to work only once. Nothing stops someone who has a box and
its key from decrypting again, or from passing the key on, and no stateless
check can tell a first use from a replay. So "one time" is a rule about the claim
and needs one piece of state, one row per box that was rewritten or opened:

```sql
CREATE TABLE honeypot_boxes (
  box_id   bytea  PRIMARY KEY,
  revision bigint NOT NULL,
  owner    text
);

-- Advance(box_id, revision): the next revision.
INSERT INTO honeypot_boxes (box_id, revision) VALUES ($1, $2 + 1)
ON CONFLICT (box_id) DO UPDATE
  SET revision = GREATEST(honeypot_boxes.revision, $2) + 1
RETURNING revision;

-- Claim(box_id, revision, owner): the owner on record.
-- No row back: a newer revision exists, the box is stale.
INSERT INTO honeypot_boxes (box_id, revision, owner) VALUES ($1, $2, $3)
ON CONFLICT (box_id) DO UPDATE
  SET owner = COALESCE(honeypot_boxes.owner, $3)
  WHERE honeypot_boxes.revision <= $2
RETURNING owner;
```

Keys stay unstored, and a box that was neither rewritten nor opened costs nothing.
This is the `Ledger` of the library, and `Release` is the rule in code. A claim is
final: rewriting a box later does not open it a second time. Losing the ledger
makes old revisions and spent boxes valid again, so back it up like the data it is.

A leaked key shows the contents but does not grant them, because the grant goes
through the ledger. A service that grants items needs only the public key and the
ledger: verify, open, claim. It never holds a secret.

Identify a box by `box_id`, never by its bytes or its signature. Both change with
every rewrite, and a dishonest signer can make a second valid signature for one
box, which must not count as a second box.

## Post-quantum

A large quantum computer breaks elliptic curves and RSA (Shor), and speeds up key
search (Grover) and, on paper, hash collisions. Honeypot uses no scheme Shor
breaks:

| Used for | Primitive | Against a quantum computer |
|---|---|---|
| signatures | ML-DSA-65 (FIPS 204) | built for it, NIST category 3 |
| key derivation, draw | HMAC-SHA-256 with 256-bit keys | Grover leaves about 2^128 work |
| contents | AES-256-GCM | Grover leaves about 2^128 work, category 5 |
| `box_id`, `key_commit` binding | SHA-256 | collisions rate category 2 |

**Contents cannot be harvested.** A box uses no public-key encryption, only keys
from `open_root`. Someone who records a box today learns nothing about its
contents when quantum computers arrive, even with the issuer's public key.

**Collisions only matter to a cheating issuer.** Nobody else can sign a box, so
only the issuer gains from two keys or two ciphertexts that hash alike. The known
quantum collision attack needs about 2^85 queries and as much quantum memory, no
cheaper in practice than the classical 2^128.

**The rest of the path matters too.** The protocol cannot protect what it does not
touch:

- Deliver open keys over TLS with a post-quantum key exchange (X25519MLKEM768, the
  default in Go since 1.24). Otherwise someone recording the traffic can recover
  released keys later.
- Pinned public keys must reach verifiers in a way that cannot be forged: ship
  them in the app, and sign the app or the key list with a post-quantum scheme
  once your platform offers one.
- A KMS holding the main key should be reached over the same kind of channel.

## Series profile

Everything that is policy rather than protocol belongs to the application. A
series publishes its choices, and `series` names them:

| Choice | Example |
|---|---|
| what is in a box | a blueprint, and what its item ids mean |
| who takes part in a draw | the player with a ticket, or the server with `Mint` |
| payload format and `size`, for boxes sealed by hand | item id, JSON, a hash pointing at larger content; 256 |
| `meta` format | `{"name":"Gold chest"}` |
| property names | `userId`, `level`, `expires` |
| caps, and how sold out items are announced | `legendary sword`: 10, on the odds page after an hour |
| who owns a box | `userId` from sealing on, set later by a rewrite, or whoever claims first |
| whether a box can be traded, before and after opening | a rewrite of `userId`, or none at all |
| what opening grants, and whether it can be undone | the ledger row is final, refunds are the application's |
| when a box expires | checked before the claim |

Nothing private goes in `meta`, `series` or properties: they are public and signed,
and they must not say what is in the box. A public tier is fine if the tier is
meant to be public.

## Audit

The split in "Keys" allows an audit after a series closes. Publishing the
`open_root` of a retired `key_id` lets anyone derive every open key and read every
box, while `sign_seed` stays secret, so nobody can forge a box. Each derived key
is checked against its `key_commit`, so a false root is caught at once. Only do
this when no unopened box under that key still matters.

## Attacks

| Attack | Stopped by |
|---|---|
| Read a box without the key | AES-256-GCM under a key only the main key can derive |
| Record boxes now, read them with a quantum computer later | no public-key encryption in a box, AES-256 and HMAC keys hold |
| Forge a box with a quantum computer | ML-DSA-65 |
| Test a guess of the contents | nothing public is a function of the payload without a secret |
| Tell the rare item by the size of the box | one `size` per series |
| Compare boxes to find equal contents | every box has its own nonce, key and ciphertext |
| Issuer swaps the contents after the sale | the ciphertext and `key_commit` are signed, and `box_id` covers them |
| Issuer swaps the contents in a rewrite | other contents are another `box_id`, which the holder sees |
| Issuer sends a different key that decrypts to something cheaper | `key_commit` admits one key |
| Use one box's key on another | each box has its own key, and `key_commit` rejects the other |
| Move a ciphertext into another box | the signature, and `key_input` as associated data |
| Forge a box | ML-DSA-65, and the pinned public key |
| Set your own `userId`, or change any property | the signature covers them, and only the main key signs |
| Claim a box assigned to someone else | `Release` compares `userId` |
| Keep a copy, give the box away, then open it with the copy | the ledger refuses the old revision |
| Show an old copy to a service as proof of ownership | **only stopped if the service checks freshness**: see "Old revisions" |
| Issuer signs two different states at one revision | `Advance` hands each revision out once; if both exist anyway, they are proof of fraud |
| Issuer seals two contents under one header | they have different `box_id`s, and the two boxes are proof of fraud |
| Claim twice with a second signature | `box_id` leaves out the signature |
| Two players claim at once | `Claim` is atomic: one row, one winner |
| Open the box, then refuse to pay | payment comes before the claim |
| Feed a key server fake boxes | signature first: a fake never reaches the ledger or the derivation |
| Ask for keys of boxes you do not own | the claim checks the owner; never expose `Key` directly |
| Steal a key in transit | it shows the contents but grants nothing: the ledger holds the owner. Use post-quantum TLS |
| RNG repeats itself | the nonce depends on the plaintext, so one key never encrypts two |
| Main key stolen | **not stopped**: every box under it is readable and forgeable, every property rewritable. Keep it in a KMS, rotate it per series |
| Issuer picks the item, or mints until it likes one | the ticket: the key is signed before the input is known. **Not stopped with `Mint`** |
| Player aims for an item | `commit` fixes the input before the ticket exists, and the open key stays secret |
| Player asks for two boxes on one ticket | `commit` admits one input, and asking again gives the same box |
| Issuer sends a box other than the promised one | `VerifyTicket`: another header or `key_commit` is rejected |
| Issuer delivers another item than the draw gave | `OpenItem` recomputes it: a mismatch is signed proof of fraud |
| Issuer rounds odds in its favour, modulo bias, float error | whole-number weights and rejection: exact |
| Issuer makes more of a capped item than the cap | a serial above the cap, or two boxes with one serial: signed proof of fraud when compared |
| Issuer swaps a winning draw for another item, saying it sold out | no second try: the item must be what the key and input give, or the ticket is refused and refunded |
| Issuer calls an item sold out after seeing the result | the list is signed in the ticket, before the input |
| Issuer lists an item with no cap as sold out, or everything | `Ticket.Verify` rejects it |
| Issuer lists a capped item as sold out too early, or keeps units for itself | **not stopped, only visible**: tickets should agree with each other |
| Tell a capped item by a slow response | every draw of such a blueprint calls `Take` once. Some difference may remain, so deliver boxes with a queue if it matters |
| Watch a live count to learn what is in a box | **up to the application**: never publish live counts |
| Exhaust a cap by asking twice with one ticket | `Take` is keyed by the draw: a retry keeps its serial |
| Issuer shows one blueprint and draws from another | the signed box names the `blueprint_id`, and `OpenItem` checks it |
| Issuer gives some players worse odds | each box names its blueprint: publish the ids in use. **Otherwise not stopped** |
| Issuer lists a prize that cannot come up | a weight is at least 1, though a tiny weight is allowed: read the odds |
| Issuer refuses to fill a box with a rare item | **not stopped, only visible**: a signed ticket left unhonoured |
| Issuer and a fake player of its own choose an item | **not stopped**: the public cannot tell |
| Time the draw to guess the item | **not claimed**: the walk over the items is not constant time. It takes nanoseconds next to a signature, but limit how often one ticket can be redeemed |

## Considered and dropped

- **Ed25519, or any elliptic curve signature.** 64 bytes against 3309, but Shor
  breaks them: anyone could forge boxes and rewrite properties from the public key.
- **Ed25519 alongside ML-DSA (hybrid).** Forging would need both broken, for 64
  more bytes. Worth revisiting. Dropped for now because a signature break only
  allows forgery, the contents stay hidden and rotation repairs it, and a second
  scheme is one more thing every implementation must agree on.
- **ML-DSA-44.** 2420-byte signatures and 1312-byte keys, category 2, and what the
  Go documentation suggests for most applications. ML-DSA-65 costs 889 bytes more
  per box. It was chosen for the margin against progress on lattices, since there
  is no hybrid to fall back on.
- **SLH-DSA (FIPS 205).** Rests on hashes alone and has 32-byte keys, but signatures
  start at 7856 bytes and it is slow to sign, which hurts when minting in bulk.
- **LMS and XMSS.** Stateful: signing twice with one state breaks them, and a
  restored backup is enough to do that.
- **Floating point odds, or `x mod total` alone.** Both are off by a little, and
  floats differ between platforms, so nobody could recompute a draw exactly.
- **Falling back to another item when a draw lands on a sold out one.** The natural
  choice, but then the issuer could turn any win into a loss by saying "sold out",
  after seeing the result. A refusal costs it the sale and shows.
- **Reserving units when a ticket is made.** It would avoid refusals, but with 10 units
  left and 1000 tickets open, most tickets would lose their chance at the item, and
  abandoned tickets would hold units forever.
- **The item only in the key, with no ciphertext.** The item follows from the key and
  the input, so a drawn box does not strictly need a payload. It keeps one so that a
  key decrypts a box the same way everywhere, and `OpenItem` checks that they agree.
- **A separate secret for the draw.** It would add a second commitment to every box.
  The open key is already secret until the claim and committed in advance.
- **VRF for the draw.** It would prove a roll without a player, but the input could
  still be ground. There is also no standard post-quantum VRF.
- **Putting properties in `meta`.** `meta` is in the header and so in the key: a
  change would give another key and break the box.
- **A separate signed record for properties.** The box would need a second signature
  of 3309 bytes, and properties would no longer be on the box.
- **A random key per box, in a table.** Simple, but every box needs a secret row
  from sealing until opening, and it can be lost or leaked row by row.
- **`SHA-256(payload)` as the commitment.** Checkable, see above. Adding a salt
  means keeping or sending the salt; `key_commit` and the signed ciphertext
  already bind the contents.
- **VRF, BLS or X25519 for the open key.** Shor breaks all of them. They would also
  let the key verify without the box, which the signed `key_commit` already gives.
- **ChaCha20-Poly1305.** As strong, but neither Go's standard library nor WebCrypto
  has it.

## Planned

- **Series manifest:** a signed Merkle root over all boxes of a series, fixed before
  the first sale, with public randomness mixed in afterwards (a beacon). It would
  prove a batch to everyone, not only to one player, including that a cap was really
  reached, and cover draws with no player present. It can also take the signature off
  each box, leaving a Merkle path of hashes, about 640 bytes for a million boxes.
- **A key server without signing power:** a service holding only `open_root` can
  release keys but cannot seal boxes or rewrite properties. The derivation already
  allows it.

## Naming

`HPBOX001` starts every box and `HPTKT001` every ticket, and each is what the
signature covers first, so a signature for one never verifies as the other.
`HPBLP001` starts every blueprint. The derivation tags (`HPSIGN01`, `HPROOT01`,
`HPNONC01`, `HPKEY001`, `HPENC001`, `HPCOMT01`, `HPINPT01`, `HPROLL01`) keep each key
apart.
All are versioned: a change to a layout gets a new tag, so old and new boxes can
never be confused.
