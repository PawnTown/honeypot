export default {
  title: "Go library",
  nav: "Go library",
  lead: "The reference implementation. No dependencies, 100 % test coverage, and every byte pinned by the conformance vectors.",
  body: ({ REPO, esc, callout }) => `
<h2>Install</h2>
<pre><code>go get github.com/PawnTown/honeypot/go@latest</code></pre>
<p>It needs Go 1.27 or later, for <code>crypto/mldsa</code> in the standard library.</p>

<h2>Use it</h2>
<pre><code>${esc(`issuer, _ := honeypot.NewIssuer(1, mainKey)

// The odds: 90 %, 9.9 %, 0.1 %, exactly. A cap is optional.
blueprint, _ := honeypot.NewBlueprint("acme/season-1/gold", nil, []honeypot.Item{
	{ID: "wooden sword", Weight: 900},
	{ID: "silver shield", Weight: 99},
	{ID: "legendary sword", Weight: 1, Cap: 10},
})
props := map[string]string{honeypot.PropUser: "alice"}

// A draw the issuer cannot steer. caps can be nil if the blueprint has no caps.
keys := map[uint8][]byte{1: issuer.Public()}
request, _ := honeypot.NewDrawRequest(rand.Reader)                        // player
ticket, _ := issuer.Ticket(rand.Reader, caps, blueprint, request.Commit, props) // issuer
err := ticket.Verify(keys, blueprint, request.Commit)                     // player
box, _ := issuer.Redeem(caps, ticket, blueprint, request.Input)           // issuer
err = box.VerifyTicket(keys, ticket)                                      // player

// Or in one call, with no player present. The issuer is trusted here.
box, _ = issuer.Mint(rand.Reader, caps, blueprint, props)

// Anyone: genuine, belongs to alice, contents unknown.
err = box.Verify(keys)
owner := box.Props[honeypot.PropUser]

// Only the main key can rewrite. Same id, same contents, same open key.
box, err = issuer.Rewrite(ledger, box, map[string]string{honeypot.PropUser: "bob"})

// Later: the key is derived, one claim per box, old revisions refused.
openKey, err := issuer.Release(ledger, box, "bob")

// The item and its serial, recomputed from the key and the input.
drawn, err := box.OpenItem(keys, blueprint, openKey)`)}</code></pre>

<h2>What your server stores</h2>
<table>
<tr><th>When</th><th>What</th></tr>
<tr><td>Always</td><td>The main key, in a KMS. Open keys are never stored.</td></tr>
<tr><td>A box is rewritten or opened</td><td>One row in the ledger.</td></tr>
<tr><td>A blueprint has caps</td><td>One row per draw, and a counter per item.</td></tr>
<tr><td>A box exists, unopened, never rewritten, no caps</td><td>Nothing.</td></tr>
</table>
<p>The ledger and the counter are two small interfaces, <code>Ledger</code> and <code>Caps</code>, and the statements for Postgres are in the <a href="${REPO}/blob/main/spec/HONEYPOT.md">specification</a>.</p>

<h2>Other languages</h2>
<p>Every implementation must reproduce <a href="${REPO}/tree/main/vectors"><code>vectors/core.json</code></a> exactly. The JavaScript behind the <a href="demo.html">demo</a> is tested against it on every push, but it is written for the demo and is not a published library.</p>
${callout("warn", "Draft", `<p>The byte formats can still change until the first release. A changed layout gets a new tag, so old and new boxes can never be confused.</p>`)}
`,
};
