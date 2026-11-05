export default {
  title: "Caps",
  lead: "Optional, per item: at most this many will ever exist. Most items need none, and a blueprint with no caps needs no state at all.",
  body: ({ callout, esc, sequence }) => `
<h2>How a cap works</h2>
<pre><code>{ID: "wooden sword", Weight: 900}                 // no limit
{ID: "legendary sword", Weight: 1, Cap: 10}       // at most 10 ever</code></pre>
<p>Caps are part of the blueprint, so they are public and covered by its id. To limit a whole run, cap every item.</p>
<ul>
<li><strong>What is sold out is fixed before the result can be known.</strong> It is signed in the ticket before the issuer sees the input, so the player reads the exact odds of this draw first (<code>Ticket.Available</code>) and can walk away. What is left keeps its weight over a smaller total, which is still exact.</li>
<li><strong>The serial is the proof of the cap.</strong> Every capped item is numbered from 1 to its cap, hidden until opening, and <code>OpenItem</code> checks the range. Two boxes with one serial of one item, or a serial above the cap, are signed proof of fraud once their holders compare them. That is what "legendary sword #7 of 10" means.</li>
<li><strong>Every draw takes a serial, whatever the item,</strong> so a slow response does not reveal a capped item. This costs one row per draw, only for a blueprint with caps.</li>
</ul>

<h2>Sold out during a draw</h2>
${sequence(
  [
    { id: "p", label: "Player", tone: "white" },
    { id: "i", label: "Issuer", tone: "server" },
  ],
  [
    { arrows: [{ from: "i", to: "p", label: "ticket: rare item still available", tone: "plain" }] },
    { note: { at: "i", text: "someone takes the last one" } },
    { arrows: [{ from: "p", to: "i", label: "the input", tone: "plain" }] },
    { note: { at: "i", text: "this draw lands on it too", tone: "warn" } },
    { arrows: [{ from: "i", to: "p", label: "ErrSoldOut: ticket refunded", tone: "warn" }] },
    { arrows: [{ from: "i", to: "p", label: "next ticket lists it as sold out", tone: "ok" }] },
  ],
  { title: "There is no second try. The issuer may not give something else instead." },
)}
<p>Falling back to another item looks natural, but then the issuer could turn any win into a loss by saying "sold out" after seeing the result. A refusal costs it the sale, and it shows. <code>Mint</code> has no ticket to honour, so it simply starts a new draw.</p>
${callout("warn", "Clients must check this", `<p>After <code>ErrSoldOut</code>, the next ticket has to list that item as sold out. If it does not, the issuer just refused a win. The library leaves this check to the client.</p>`)}

<h2>What a cap cannot do</h2>
<ul>
<li><strong>"Sold out" is the issuer's word.</strong> It can list an item early, or draw capped items for itself until they run out, and nothing proves otherwise. The list comes before the result, so this cannot target a winning draw, and tickets given out at about the same time should agree.</li>
<li><strong>Never publish live counts.</strong> If "4 left" turns into "3 left" just after a draw, that player knows what is in their box without a key. Publish only that an item has sold out, with a delay.</li>
<li><strong>A unit in a box nobody opens stays taken.</strong> A cap limits how many exist, not how many are in use.</li>
</ul>

<h2>What it stores</h2>
<pre><code>${esc(`-- SoldOut(blueprint_id)
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
SELECT serial FROM prior UNION ALL SELECT serial FROM unit;`)}</code></pre>
<p>The full schema is in the <a href="https://github.com/PawnTown/honeypot/blob/main/spec/HONEYPOT.md">specification</a>.</p>
`,
};
