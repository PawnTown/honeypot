const PER_ROW = 14;

export default {
  title: "Overview",
  nav: "Overview",
  description: "Honeypot: post-quantum safe lootboxes. Contents fixed at creation, hidden until one key opens them, with exact odds anyone can recompute.",
  hero: ({ vectors, href, comb, boxSegs }) => {
    const draw = vectors.core.draws[4];
    const bare = boxSegs(draw.box, 0).segs.reduce((n, seg) => n + seg.len, 0);
    const honeycomb = (perRow, className) => {
      const shown = perRow * Math.ceil((bare + 1) / perRow) - bare;
      const { segs, hex } = boxSegs(draw.box, shown);
      return `<div class="hero-comb ${className}">${comb(hex, segs, {
        perRow,
        title: "A real box, one cell per byte. The dark cells are the sealed contents.",
        more: `Plus ${(3309 - shown).toLocaleString("en-US")} more signature bytes.`,
      })}</div>`;
    };
    return `<section class="hero">
  <div class="hero-in">
    <div>
      <h1>Sealed loot, checkable odds.</h1>
      <p class="lead">Honeypot seals an item into a box the moment the box is made. Anyone can check the box is genuine and who owns it, but nobody can tell what is inside until one key opens it. Then anyone can recompute that the published odds picked that item.</p>
      <div class="hero-cta"><a class="btn primary" href="${href("demo")}">Open a box</a><a class="btn ghost" href="${href("concepts")}">How it works</a></div>
    </div>
    <img class="hero-box" src="assets/logo.webp" alt="A Honeypot cereal box: a grinning ghost holds up a mystery capsule over a bowl of honey crunch, under a burst reading secret toy inside." width="720" height="1084" fetchpriority="high">
  </div>
  ${honeycomb(30, "comb-wide")}
  ${honeycomb(14, "comb-narrow")}
  <svg class="drip" viewBox="0 0 1440 60" preserveAspectRatio="none" aria-hidden="true"><path fill="#fffcf0" d="M0,60 L0,24 C80,24 90,46 150,46 C210,46 200,18 290,18 C360,18 360,52 430,52 C490,52 480,26 560,26 C640,26 650,44 720,44 C800,44 790,14 880,14 C960,14 950,50 1030,50 C1100,50 1100,28 1180,28 C1260,28 1260,42 1330,42 C1390,42 1400,30 1440,30 L1440,60 Z"/></svg>
</section>`;
  },
  body: ({ sequence, href, callout }) => `
<h2>What it is</h2>
<p>Honeypot is a protocol for any system that hands out sealed contents: game loot, collectibles, coupons, mystery rewards. The issuer keeps one secret, the <strong>main key</strong>. From it comes everything else, including the key to any box, whenever it is needed. Nothing per box has to be stored until someone opens it.</p>

${sequence(
  [
    { id: "i", label: "Issuer", tone: "server" },
    { id: "p", label: "Player", tone: "white" },
  ],
  [
    { note: { at: "i", text: "seals the item" } },
    { arrows: [{ from: "i", to: "p", label: "the box", tone: "plain" }] },
    { note: { at: "p", text: "checks it, cannot read it" } },
    { arrows: [{ from: "p", to: "i", label: "claim this box", tone: "muted", dashed: true }] },
    { note: { at: "i", text: "derives the key, records the claim" } },
    { arrows: [{ from: "i", to: "p", label: "the open key", tone: "ok" }] },
    { note: { at: "p", text: "opens it, recomputes the item" } },
  ],
  { title: "The box comes first, the key later. The contents cannot change in between." },
)}

<h2>What it gives you</h2>
<table>
<tr><th>You want</th><th>How Honeypot does it</th></tr>
<tr><td>Contents that cannot change after sale</td><td>The sealed contents and a commitment to the key are signed when the box is made.</td></tr>
<tr><td>No peeking, no guessing</td><td>Nothing public depends on the item without a secret, and every box of a kind is the same size.</td></tr>
<tr><td>No key database</td><td>The open key is derived from the main key and the box, the same every time.</td></tr>
<tr><td>Published odds that are really used</td><td>A blueprint lists items and exact whole-number weights. The item follows from the key and an input, so anyone can recompute it.</td></tr>
<tr><td>An issuer that cannot pick the winner</td><td>The player adds randomness in a ticket exchange, and each side commits before seeing the other's part.</td></tr>
<tr><td>Limited items</td><td>An optional cap per item, with numbered serials that prove it.</td></tr>
<tr><td>Public, tamper-proof facts such as the owner</td><td>Properties anyone can read on the box and only the main key can rewrite.</td></tr>
<tr><td>Safety against quantum computers</td><td>ML-DSA-65 signatures, and everything else is symmetric.</td></tr>
</table>

${callout("warn", "Draft, not audited", `<p>The specification is still moving and nobody independent has reviewed the cryptography. Get a review before real money or real prizes depend on it. Some things it does not stop are listed in <a href="${href("security")}">What it proves</a>.</p>`)}

<h2>Where to go next</h2>
<div class="grid grid-2">
  <a class="card" href="${href("demo")}"><p class="card-title">Try it</p><p>Set the odds, draw a box, flip its bytes, open it and try to cheat, with the real protocol running in your browser.</p></a>
  <a class="card" href="${href("concepts")}"><p class="card-title">How it works</p><p>Keys, sealing, the two checks, and what "one time" really means.</p></a>
  <a class="card" href="${href("attacks")}"><p class="card-title">Attack gallery</p><p>What a cheater could try, on either side, and what happens.</p></a>
  <a class="card" href="${href("libraries")}"><p class="card-title">Go library</p><p>Install it, and see what your server has to store.</p></a>
</div>
`,
};
