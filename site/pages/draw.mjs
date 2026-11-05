export default {
  title: "Blueprints and the draw",
  nav: "The draw",
  lead: "A blueprint publishes what a box can hold and how likely each item is. The draw makes those odds exact, and with a player taking part, the issuer cannot steer it.",
  body: ({ sequence, callout, href, vectors, esc }) => {
    const gold = vectors.core.blueprints.gold;
    const rows = [...gold.items]
      .sort((a, b) => b.Weight - a.Weight)
      .map((it) => `<tr><td>${esc(it.ID)}</td><td>${it.Weight}</td><td>${it.Weight} / ${gold.total} = ${((100 * it.Weight) / gold.total).toLocaleString("en-US", { maximumFractionDigits: 2 })} %</td></tr>`)
      .join("");
    return `
<h2>A blueprint</h2>
<p>This one is from the test vectors, and its id is <code>${gold.id.slice(0, 16)}…</code>.</p>
<table>
<tr><th>Item</th><th>Weight</th><th>Chance</th></tr>
${rows}
</table>
<ul>
<li><strong>Odds are whole numbers.</strong> A chance is exactly <code>weight / total</code>. There is no floating point, so nothing rounds and every language gets the same result.</li>
<li><strong>A weight is at least 1.</strong> A prize that can never come up cannot be listed.</li>
<li><strong>The id is the hash of the bytes.</strong> Other odds are another id, and every signed box names the one it came from. Publish the ids in use, so players can tell everyone gets the same odds.</li>
</ul>

<h2>The pick</h2>
<p>The item follows from the open key and an input, with nothing else involved.</p>
<pre><code>total  = sum of the weights of the items not sold out
reject = 2^64 mod total
for j = 0, 1, ...:
  x = first 8 bytes of KDF(open_key, "HPROLL01", blueprint_id, input, j)
  if x >= reject: r = x mod total, stop
item = walk the items in order, subtracting weights from r</code></pre>
<p><code>x mod total</code> alone would be biased, because 2^64 does not divide evenly by the total. Dropping the lowest values leaves a range that does, so <code>r</code> is exactly uniform. The item cannot disagree with the key and input: <code>OpenItem</code> recomputes it, and a mismatch is signed proof of fraud.</p>

<h2>Who chooses: nobody</h2>
<p>If only the issuer supplies randomness, nobody can tell whether it minted until it liked the result. So a player who is present adds their own, and each side commits first.</p>
${sequence(
  [
    { id: "p", label: "Player", tone: "white" },
    { id: "i", label: "Issuer", tone: "server" },
  ],
  [
    { note: { at: "p", text: "secret input, keeps it" } },
    { arrows: [{ from: "p", to: "i", label: "commitment to the input", tone: "plain" }] },
    { note: { at: "i", text: "fixes the key, signs" } },
    { arrows: [{ from: "i", to: "p", label: "ticket: key commitment, sold out list", tone: "plain" }] },
    { note: { at: "p", text: "checks the ticket and the odds" } },
    { arrows: [{ from: "p", to: "i", label: "the input", tone: "ok" }] },
    { note: { at: "i", text: "item = pick(key, input)" } },
    { arrows: [{ from: "i", to: "p", label: "the box, still closed", tone: "ok" }] },
    { note: { at: "p", text: "the box the ticket promised?" } },
  ],
  { title: "Each side is fixed before it can see the other's part." },
)}
<p>The draw is fair if either side is honest:</p>
<ul>
<li><strong>An honest player:</strong> the input is random and hidden when the issuer signs the key commitment, and that commitment admits one key. The issuer cannot aim for an item, whatever key it picks.</li>
<li><strong>An honest issuer:</strong> the input is fixed before the ticket exists, and the open key stays secret until the claim. The player cannot aim for an item, or see it before the claim.</li>
</ul>
<p>The commitment admits one input, so a ticket gives one box, and asking again returns the very same box. With no caps, neither side stores anything.</p>

<h2>Without a player</h2>
<p><code>Mint</code> draws in one call, for rewards from a server with nobody there to take part.</p>
<table>
<tr><th></th><th>Mint</th><th>Ticket and Redeem</th></tr>
<tr><td>Odds exact</td><td>yes</td><td>yes</td></tr>
<tr><td>Nobody without the main key can predict the item</td><td>yes</td><td>yes</td></tr>
<tr><td>Anyone can recompute the item after opening</td><td>yes</td><td>yes</td></tr>
<tr><td>The issuer cannot choose the item</td><td><strong>no</strong>, it could mint until it likes one</td><td>yes</td></tr>
<tr><td>Works with no player present</td><td>yes</td><td>no</td></tr>
</table>

<h2>What a draw cannot do</h2>
${callout("warn", "The issuer can refuse", `<p>It sees the result once it has the input, and could decline to fill a box with a rare item. No two-party protocol can prevent that, but the refusal shows: the player holds a signed ticket that was not honoured. Clients should retry with the same ticket and input, never accept a replacement for a failed ticket, and refund and count any ticket not honoured.</p>`)}
<ul>
<li><strong>An input must be fresh.</strong> Once an issuer knows an input, it can pick a nonce that suits it. Clients make a new one for every draw.</li>
<li><strong>The proof is personal.</strong> Only the player knows the input was theirs. Outsiders cannot tell a ticket from a <code>Mint</code>, so an issuer and a fake player of its own can still choose an item unnoticed.</li>
<li><strong>Draws are independent.</strong> A chance of 0.1 % does not mean exactly 1 in 1000 boxes. An upper limit is what a <a href="${href("caps")}">cap</a> is for.</li>
</ul>
`;
  },
};
