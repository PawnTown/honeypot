export default {
  title: "Byte layouts",
  nav: "Byte layouts",
  lead: "Every byte, drawn from vectors/core.json: the exact bytes every implementation must produce. Point at or tap a byte to read its field.",
  body: ({ hexdump, vectors, boxSegs, ticketSegs, blueprintSegs, callout }) => {
    const v = vectors.core;
    const SHOW = 32;
    const box = boxSegs(v.draws[4].box, SHOW);
    const ticket = ticketSegs(v.draws[4].ticket, SHOW);
    const hand = boxSegs(v.boxes[3].box, SHOW);
    const moved = boxSegs(v.rewrites[0].box, SHOW);
    const sum = (segs) => segs.reduce((n, s) => n + s.len, 0);
    return `
<p>Integers are big-endian. Signatures are ML-DSA-65, 3309 bytes, and only the first ${SHOW} are drawn here.</p>

<h2>A blueprint</h2>
${hexdump(v.blueprints.even.hex, blueprintSegs(v.blueprints.even.hex), { title: "blueprint: a 1, b 1, c 2" })}
<p>Its id is the SHA-256 of these bytes.</p>

<h2>A ticket</h2>
<p>What the issuer signs before it sees the player's input. It carries the whole header of the box to come, so the open key is already fixed.</p>
${hexdump(ticket.hex, ticket.segs, { title: "ticket" })}

<h2>A drawn box</h2>
<p>The same header, then the commitment to the key, the input, the sealed contents, and the part that can be rewritten.</p>
${hexdump(box.hex, box.segs, { title: "box, drawn from a blueprint" })}
${callout("rule", "What box_id covers", `<p>Everything before the revision: the header, the key commitment, the input and the contents. The revision, the properties and the signature are left out, because they change. That is ${sum(box.segs.slice(0, box.segs.findIndex((s) => s.label === "revision")))} bytes here.</p>`)}

<h2>The same box after a rewrite</h2>
<p>This one comes from the rewrite vector: another box, with a new owner, revision 1 and a new signature. Its sealed part is unchanged from revision 0.</p>
${hexdump(moved.hex, moved.segs, { title: "box, revision 1" })}

<h2>A box sealed by hand</h2>
<p>With no blueprint, the draw flag is 0, and there is no input.</p>
${hexdump(hand.hex, hand.segs, { title: "box, sealed by hand" })}

<h2>Sizes</h2>
<table>
<tr><th>Thing</th><th>Size</th></tr>
<tr><td>Box sealed by hand</td><td>3393 bytes, plus series, meta and size</td></tr>
<tr><td>Drawn box</td><td>98 more, plus 2 per sold out item</td></tr>
<tr><td>Each property</td><td>3 bytes, plus its name and value</td></tr>
<tr><td>Issuer public key</td><td>1952 bytes</td></tr>
<tr><td>Open key, main key</td><td>32 bytes</td></tr>
</table>
`;
  },
};
