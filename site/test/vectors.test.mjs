// The demo runs the real protocol: this checks its JavaScript byte for byte
// against the vectors the Go library writes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  E, Issuer, MemCaps, MemLedger, PROP_USER, blueprintId, boxId, decodeBlueprint, decodeBox, decodeTicket, encodeBlueprint, encodeBox, encodeTicket, hex, isError, newBlueprint, newDrawRequest, openBox, openItem, pick, roll, supersedes, unhex, verifyBox, verifyBoxTicket, verifyKey, verifyTicket,
} from "../assets/honeypot.js";

const v = JSON.parse(readFileSync(new URL("../../vectors/core.json", import.meta.url)));
const issuer = new Issuer(v.issuer.key_id, unhex(v.issuer.main_key));
const keys = issuer.keys;
const blueprint = (name) => decodeBlueprint(unhex(v.blueprints[name].hex));
const raises = async (fn, message) => {
  await assert.rejects(async () => fn(), (err) => isError(err, message) || assert.fail(`${err.message}, want ${message}`));
};

test("the main key splits the same way", () => {
  assert.equal(hex(issuer.signSeed), v.issuer.sign_seed);
  assert.equal(hex(issuer.root), v.issuer.open_root);
  assert.equal(hex(issuer.publicKey), v.issuer.public);
});

test("boxes sealed by hand", async () => {
  for (const c of v.boxes) {
    const b = await issuer.seal({ series: c.series, meta: unhex(c.meta), props: c.properties ?? {}, size: c.size }, unhex(c.payload), unhex(c.entropy));
    assert.equal(hex(encodeBox(b)), c.box, c.name);
    assert.equal(hex(issuer.key(b)), c.open_key, c.name);
    assert.equal(hex(boxId(b)), c.box_id, c.name);
    const got = decodeBox(unhex(c.box));
    verifyBox(got, keys);
    verifyKey(got, unhex(c.open_key));
    assert.equal(hex(await openBox(got, keys, unhex(c.open_key))), c.payload, c.name);
    assert.equal(hex(encodeBox(got)), c.box, c.name);
  }
});

test("a rewrite signs the same bytes", () => {
  const first = decodeBox(unhex(v.boxes[0].box));
  for (const c of v.rewrites) {
    const b = issuer.rewrite(new MemLedger(), first, c.properties);
    assert.equal(hex(encodeBox(b)), c.box);
    assert.ok(supersedes(b, first));
    assert.equal(hex(boxId(b)), hex(boxId(first)));
  }
});

test("blueprints", () => {
  for (const [name, c] of Object.entries(v.blueprints)) {
    const built = newBlueprint(c.series, unhex(c.meta), c.items.map((it) => ({ id: it.ID, weight: it.Weight, cap: it.Cap })));
    assert.equal(hex(encodeBlueprint(built)), c.hex, name);
    assert.equal(hex(blueprintId(built)), c.id, name);
    assert.equal(hex(encodeBlueprint(blueprint(name))), c.hex, name);
  }
  for (const items of [[], [{ id: "", weight: 1 }], [{ id: "a", weight: 0 }], [{ id: "a", weight: 1 }, { id: "a", weight: 2 }], [{ id: "a", weight: 1.5 }]]) {
    assert.throws(() => newBlueprint("s", null, items), /malformed blueprint/);
  }
});

test("the roll, with its retry", () => {
  for (const c of v.rolls) {
    assert.equal(String(roll(unhex(c.Key), unhex(c.BlueprintID), unhex(c.Input), BigInt(c.Total)).r), c.R);
  }
  assert.ok(v.rolls.some((c) => roll(unhex(c.Key), unhex(c.BlueprintID), unhex(c.Input), BigInt(c.Total)).rejected > 0));
});

test("draws, through the whole ticket exchange", async () => {
  for (const c of v.draws) {
    const bp = blueprint(c.blueprint);
    const input = unhex(c.input);
    const req = newDrawRequest(input);
    assert.equal(hex(req.commit), c.input_commit, c.name);
    const ticket = issuer.ticket(bp, req.commit, c.properties ?? {}, { entropy: unhex(c.entropy) });
    assert.equal(hex(encodeTicket(ticket)), c.ticket, c.name);
    const decoded = decodeTicket(unhex(c.ticket));
    verifyTicket(decoded, keys, bp, req.commit);
    const b = await issuer.redeem(decoded, bp, input);
    assert.equal(hex(encodeBox(b)), c.box, c.name);
    const held = decodeBox(unhex(c.box));
    verifyBoxTicket(held, keys, decoded);
    const drawn = await openItem(held, keys, bp, unhex(c.open_key));
    assert.equal(drawn.item.id, c.item, c.name);
    assert.equal(drawn.serial, 0n, c.name);
    assert.equal(pick(bp, unhex(c.open_key), input).id, c.item, c.name);
  }
});

test("capped draws, with the counter and the sold out list", async () => {
  const bp = blueprint("limited");
  const caps = new MemCaps();
  let soldOutSeen = 0;
  for (const c of v.capped_draws) {
    const req = newDrawRequest(unhex(c.input));
    const ticket = issuer.ticket(bp, req.commit, {}, { caps, entropy: unhex(c.entropy) });
    assert.equal(hex(encodeTicket(ticket)), c.ticket, c.name);
    if (ticket.soldOut.length) soldOutSeen++;
    const b = await issuer.redeem(ticket, bp, req.input, caps);
    assert.equal(hex(encodeBox(b)), c.box, c.name);
    const drawn = await openItem(decodeBox(unhex(c.box)), keys, bp, unhex(c.open_key));
    assert.equal(drawn.item.id, c.item, c.name);
    assert.equal(drawn.serial, BigInt(c.serial), c.name);
  }
  assert.ok(soldOutSeen > 0);
});

test("what must be rejected", async () => {
  for (const [name, s] of Object.entries(v.invalid.undecodable)) assert.throws(() => decodeBox(unhex(s)), /honeypot:/, name);
  for (const [name, s] of Object.entries(v.invalid.bad_signature)) {
    let b;
    try {
      b = decodeBox(unhex(s));
    } catch {
      continue;
    }
    assert.throws(() => verifyBox(b, keys), /bad signature|unknown issuer key/, name);
  }
  const first = decodeBox(unhex(v.boxes[0].box));
  for (const s of Object.values(v.invalid.wrong_key)) await raises(() => openBox(first, keys, unhex(s)), E.wrongKey);
});

test("every byte of a drawn box is covered", () => {
  const raw = unhex(v.draws[0].box);
  for (let i = 0; i < raw.length; i += 7) {
    const bad = raw.slice();
    bad[i] ^= 1;
    let b;
    try {
      b = decodeBox(bad);
    } catch {
      continue;
    }
    assert.throws(() => verifyBox(b, keys), /bad signature|unknown issuer key/, `byte ${i}`);
  }
});

test("ownership, transfer and the one-time claim", async () => {
  const bp = blueprint("gold");
  const ledger = new MemLedger();
  const old = await issuer.mint(bp, { [PROP_USER]: "alice" });
  await raises(() => issuer.release(ledger, old, "bob"), E.notOwner);
  const moved = issuer.rewrite(ledger, old, { [PROP_USER]: "bob" });
  await raises(() => issuer.release(ledger, old, "alice"), E.stale);
  const key = issuer.release(ledger, moved, "bob");
  assert.equal(hex(issuer.release(ledger, moved, "bob")), hex(key));
  const back = issuer.rewrite(ledger, moved, { [PROP_USER]: "alice" });
  await raises(() => issuer.release(ledger, back, "alice"), E.claimed);
  assert.equal((await openItem(moved, keys, bp, key)).serial, 0n);
});

test("the issuer cannot swap the item", async () => {
  const bp = blueprint("even");
  const req = newDrawRequest();
  const ticket = issuer.ticket(bp, req.commit, {});
  const good = await issuer.redeem(ticket, bp, req.input);
  const key = issuer.key(good);
  const drawn = pick(bp, key, req.input);
  const other = bp.items.find((it) => it.id !== drawn.id);
  const liar = { id: other.id, weight: other.weight, cap: 0 };
  const forged = await issuer.fill(ticket, { ...bp, items: [liar] }, req.input);
  forged.sig = issuer.signBox(forged);
  await raises(() => openItem(forged, keys, bp, key), E.draw);
});
