// The attack gallery: the tricks from the spec's attack table, one card each.
export default {
  title: "Attack gallery",
  lead: "What a cheater could try, on either side, and what happens. Red: caught, with proof or a refusal. Green: no gain. Dashed: not stopped, and what limits it.",
  body: ({ attack, sequence }) => {
    const P = { id: "p", label: "Player", tone: "white" };
    const I = { id: "i", label: "Issuer", tone: "server" };
    const groups = [
      {
        title: "Peeking before opening",
        items: [
          attack({ id: "guess", name: "Test a guess", tone: "none", tries: "Hash every item in the blueprint and look for a match in the box.", caught: "Nothing public is a function of the item without a secret. There is no hash of it, and the contents are encrypted under a 256-bit key.", outcome: "Nothing to test against." }),
          attack({ id: "size", name: "Read the size", tone: "none", tries: "A rare item has a longer name, so look for the bigger box.", caught: "Every box of a blueprint is padded to fit its longest id.", outcome: "All boxes are the same size." }),
          attack({ id: "harvest", name: "Record now, decrypt later", tone: "none", tries: "Store boxes today and read them with a quantum computer.", caught: "No public-key encryption is used in a box. The keys come from HMAC, and the contents are AES-256.", outcome: "Grover leaves about 2^128 work per key." }),
          attack({ id: "counts", name: "Watch a live count", tone: "limit", tries: "See \"4 left\" turn into \"3 left\" right after a draw, and know the box holds the capped item.", caught: "The protocol keeps counts private, but an application can leak them by showing them.", outcome: "Up to the application: publish only that an item sold out." }),
        ],
      },
      {
        title: "Cheating on the contents",
        items: [
          attack({
            id: "swap-after",
            name: "Swap the contents after the sale",
            tone: "lose",
            tries: "The issuer replaces the sealed contents with something cheaper.",
            caught: "The ciphertext is signed, and <code>box_id</code> covers it. Other contents are another box, which the holder sees.",
            outcome: "The two signed boxes are portable proof of fraud.",
          }),
          attack({ id: "other-key", name: "Send a key that decrypts to something else", tone: "lose", tries: "Build a ciphertext that opens to two different items under two keys, and send the cheap one.", caught: "AES-GCM alone would allow it. The signed <code>key_commit</code> admits one key.", outcome: "The wrong key fails <code>VerifyKey</code>." }),
          attack({ id: "reuse-key", name: "Use one box's key on another", tone: "void", tries: "Claim one box, and use its key on every other.", caught: "Each box has its own key, and <code>key_commit</code> rejects the other.", outcome: "Refused." }),
          attack({ id: "forge", name: "Forge a box", tone: "void", tries: "Make a box with a legendary inside, or forge one with a quantum computer.", caught: "ML-DSA-65 and the pinned public key.", outcome: "Bad signature. A fake never reaches the ledger or the key derivation." }),
        ],
      },
      {
        title: "Cheating on the draw",
        items: [
          attack({
            id: "aim",
            name: "Issuer aims for an item",
            tone: "lose",
            tries: "See the player's input first, then pick a key that lands on a cheap item.",
            caught: "The key is committed in the signed ticket before the input is known. A box with another key does not match the ticket.",
            outcome: "<code>VerifyTicket</code> rejects the box.",
            fig: sequence([P, I], [
              { arrows: [{ from: "i", to: "p", label: "ticket: key commitment A", tone: "plain" }] },
              { arrows: [{ from: "p", to: "i", label: "the input", tone: "plain" }] },
              { arrows: [{ from: "i", to: "p", label: "box with key commitment B", tone: "bad" }] },
              { note: { at: "p", text: "not the promised box", tone: "bad" } },
            ], { title: "The issuer is fixed before it sees the input.", width: 640 }),
          }),
          attack({ id: "swap-item", name: "Deliver another item than the draw gave", tone: "lose", tries: "Seal a cheap item whatever the roll says.", caught: "<code>OpenItem</code> recomputes the item from the key and the input.", outcome: "A mismatch is signed proof of fraud." }),
          attack({ id: "bias", name: "Round the odds in your favour", tone: "none", tries: "Modulo bias, or floating point that rounds the right way.", caught: "Whole-number weights and rejection give an exact chance, and anyone can recompute it.", outcome: "Exact." }),
          attack({ id: "player-aim", name: "Player aims for an item", tone: "none", tries: "Choose an input that gives the legendary.", caught: "The commitment fixes the input before the ticket exists, and the open key stays secret until the claim.", outcome: "The player cannot compute anything." }),
          attack({ id: "two-boxes", name: "Two boxes on one ticket", tone: "none", tries: "Redeem one ticket twice.", caught: "The commitment admits one input, and asking again gives the very same box, the same row in the ledger.", outcome: "One box." }),
          attack({ id: "refuse", name: "Refuse a rare item", tone: "limit", tries: "See the result once the input arrives, and decline to fill the box.", caught: "No two-party protocol can stop this, but the player holds a signed ticket that was not honoured.", outcome: "Visible, not prevented. Clients retry the same ticket, and refund and count failures." }),
          attack({ id: "mint-until", name: "Mint until it likes one", tone: "limit", tries: "With <code>Mint</code>, the issuer draws for itself, as often as it wants.", caught: "Nothing does. That is the difference between <code>Mint</code> and a ticket.", outcome: "Use tickets when a player is online." }),
          attack({ id: "sockpuppet", name: "Issuer and a fake player", tone: "limit", tries: "The issuer plays both sides of a ticket, and gives itself the rare items.", caught: "Only a player knows an input was theirs, so the public cannot tell.", outcome: "Not stopped. The planned manifest would prove a batch to everyone." }),
        ],
      },
      {
        title: "Cheating on ownership and claims",
        items: [
          attack({ id: "set-owner", name: "Set your own userId", tone: "void", tries: "Edit the property on your copy of the box.", caught: "The signature covers the properties, and only the main key signs.", outcome: "Bad signature." }),
          attack({ id: "other-owner", name: "Claim a box assigned to someone else", tone: "void", tries: "Send someone else's box with your name.", caught: "<code>Release</code> compares <code>userId</code>.", outcome: "Refused, with no row taken." }),
          attack({ id: "keep-copy", name: "Give it away, then use the old copy", tone: "void", tries: "Keep the signed box from before a transfer, and open it with that.", caught: "The ledger refuses a revision below the one on record.", outcome: "Refused by <code>Release</code>." }),
          attack({ id: "old-proof", name: "Show an old copy as proof of ownership", tone: "limit", tries: "Show a service the old copy, which still verifies.", caught: "A signature cannot expire. The service must check the current revision.", outcome: "Only stopped if the service checks freshness." }),
          attack({ id: "claim-twice", name: "Claim twice", tone: "void", tries: "Race a second claim, or claim with a second signature on the same box.", caught: "<code>Claim</code> is atomic, and <code>box_id</code> leaves out the signature.", outcome: "One row, one winner." }),
          attack({ id: "steal-key", name: "Steal a key in transit", tone: "none", tries: "Intercept the key on its way to the owner.", caught: "It shows the contents but grants nothing, because the ledger holds the owner.", outcome: "No item. Use post-quantum TLS anyway." }),
        ],
      },
      {
        title: "Cheating on caps",
        items: [
          attack({ id: "over-cap", name: "Make more than the cap", tone: "lose", tries: "The issuer mints an 11th of 10.", caught: "A serial above the cap fails <code>OpenItem</code>, and two boxes with one serial are signed.", outcome: "Proof of fraud, once holders compare." }),
          attack({ id: "fake-sold-out", name: "Say \"sold out\" after seeing a win", tone: "lose", tries: "Swap a winning draw for another item.", caught: "The sold out list is signed in the ticket, before the input. There is no second try: the item must be what the key and input give.", outcome: "The ticket is refused and refunded, and the next ticket must agree." }),
          attack({ id: "early-sold-out", name: "List a capped item as sold out early", tone: "limit", tries: "Keep units for yourself, or pretend they are gone.", caught: "It cannot target a win, but nothing proves the list true.", outcome: "Visible only: tickets given out at about the same time should agree." }),
        ],
      },
      {
        title: "The one that ends everything",
        items: [
          attack({ id: "main-key", name: "Main key stolen", tone: "limit", tries: "Get the main key.", caught: "Nothing does. Every box under it is readable and forgeable, and every property rewritable.", outcome: "Keep it in a KMS, and rotate it per series so its reach stays small." }),
        ],
      },
    ];
    return groups.map((g) => `<h2>${g.title}</h2>${g.items.join("")}`).join("");
  },
};
