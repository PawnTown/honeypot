// The Honeypot protocol in JavaScript, for the demo. Every byte matches the Go
// library: site/test/vectors.test.mjs runs this file against vectors/core.json.
import { hmac, ml_dsa65, sha256 } from "./vendor/noble.js";

const utf8 = new TextEncoder();
const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const lenient = new TextDecoder("utf-8", { ignoreBOM: true });

export const KEY_SIZE = 32;
export const SIG_SIZE = 3309;
export const PROP_USER = "userId";
const TAG_BOX = "HPBOX001";
const TAG_TICKET = "HPTKT001";
const TAG_BLUEPRINT = "HPBLP001";
const MAX_SIZE = 65535 - 16;

// The same messages as the Go library.
export const E = {
  short: "input too short",
  tag: "wrong message tag",
  trailing: "bytes after the message",
  drawField: "malformed draw fields",
  tooLong: "series longer than 255 bytes or meta longer than 65535",
  property: "malformed properties",
  size: "payload does not fit the series size",
  keySize: "key must be 32 bytes",
  unknownKey: "unknown issuer key",
  signature: "bad signature",
  wrongKey: "open key does not belong to this box",
  ciphertext: "ciphertext does not decrypt",
  padding: "malformed plaintext",
  blueprint: "malformed blueprint",
  notDrawn: "box was not drawn from a blueprint",
  wrongBlueprint: "not the blueprint of this box",
  input: "input does not match its commitment",
  ticket: "box does not match the ticket",
  draw: "contents are not what the draw gives",
  noCaps: "this blueprint has caps and needs Caps",
  soldOut: "sold out",
  claimed: "box already claimed by another owner",
  notOwner: "box is assigned to another user",
  stale: "a newer revision of this box exists",
};
const fail = (message) => {
  throw new Error(`honeypot: ${message}`);
};
export { sha256 };
export const isError = (err, message) => err?.message === `honeypot: ${message}`;

// ------------------------------------------------------------------- bytes

export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
export const text = (b) => lenient.decode(b);
export const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const u8 = (n) => Uint8Array.of(n);
const u16 = (n) => Uint8Array.of(n >>> 8, n & 255);
const u32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const u64 = (n) => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
};
const same = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};
const compare = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};
const byName = (a, b) => compare(utf8.encode(a), utf8.encode(b));
const validText = (b) => {
  try {
    strict.decode(b);
    return true;
  } catch {
    return false;
  }
};

class Reader {
  constructor(b) {
    this.b = b;
    this.at = 0;
    this.err = null;
  }
  get left() {
    return this.b.length - this.at;
  }
  take(n) {
    if (this.err) return new Uint8Array(n);
    if (n > this.left) {
      this.err = E.short;
      return new Uint8Array(n);
    }
    this.at += n;
    return this.b.subarray(this.at - n, this.at);
  }
  u8() {
    return this.take(1)[0];
  }
  u16() {
    const b = this.take(2);
    return (b[0] << 8) | b[1];
  }
  u32() {
    const b = this.take(4);
    return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  }
  tag(want) {
    if (text(this.take(want.length)) !== want && !this.err) this.err = E.tag;
  }
  done(result) {
    if (!this.err && this.left !== 0) this.err = E.trailing;
    if (this.err) fail(this.err);
    return result;
  }
}

// One function derives everything: HMAC-SHA-256 over a tag and the data.
const kdf = (key, tag, ...data) => hmac(sha256, key, cat(utf8.encode(tag), ...data));

// --------------------------------------------------------------- properties

const validProp = (name, value) => {
  const n = utf8.encode(name);
  return n.length > 0 && n.length <= 255 && utf8.encode(value).length <= 65535;
};
const checkProps = (props = {}) => {
  const entries = Object.entries(props);
  if (entries.length > 255 || !entries.every(([n, v]) => validProp(n, v))) fail(E.property);
};
const encodeProps = (props = {}) => {
  const names = Object.keys(props).sort(byName);
  const parts = [u8(names.length)];
  for (const name of names) {
    const n = utf8.encode(name);
    const v = utf8.encode(props[name]);
    parts.push(u8(n.length), n, u16(v.length), v);
  }
  return cat(...parts);
};
const readProps = (r) => {
  const props = {};
  let last = new Uint8Array();
  const n = r.u8();
  for (let i = 0; i < n && !r.err; i++) {
    const name = r.take(r.u8());
    const value = r.take(r.u16());
    if (!r.err && (compare(name, last) <= 0 || !validText(name) || !validText(value))) r.err = E.property;
    last = name;
    if (!r.err) props[text(name)] = text(value);
  }
  return props;
};

// --------------------------------------------------------------- blueprints

export function newBlueprint(series, meta, items) {
  const bp = {
    series,
    meta: meta ?? new Uint8Array(),
    items: [...items].sort((a, b) => byName(a.id, b.id)).map((it) => ({ id: it.id, weight: it.weight, cap: it.cap ?? 0 })),
  };
  checkBlueprint(bp);
  return bp;
}

function checkBlueprint(bp) {
  if (utf8.encode(bp.series).length > 255 || bp.meta.length > 65535) fail(E.tooLong);
  if (bp.items.length === 0 || bp.items.length > 65535) fail(E.blueprint);
  let last = new Uint8Array();
  for (const it of bp.items) {
    const id = utf8.encode(it.id);
    const whole = (n, max) => Number.isInteger(n) && n >= 0 && n <= max;
    if (compare(id, last) <= 0 || id.length > 255 || !whole(it.weight, 0xffffffff) || !whole(it.cap, 0xffffffff) || it.weight === 0) fail(E.blueprint);
    last = id;
  }
}

export function encodeBlueprint(bp) {
  const s = utf8.encode(bp.series);
  const parts = [utf8.encode(TAG_BLUEPRINT), u8(s.length), s, u16(bp.meta.length), bp.meta, u16(bp.items.length)];
  for (const it of bp.items) {
    const id = utf8.encode(it.id);
    parts.push(u8(id.length), id, u32(it.weight), u32(it.cap));
  }
  return cat(...parts);
}

export function decodeBlueprint(raw) {
  const r = new Reader(raw);
  r.tag(TAG_BLUEPRINT);
  const series = text(r.take(r.u8()));
  const meta = r.take(r.u16());
  const n = r.u16();
  const items = [];
  for (let i = 0; i < n && !r.err; i++) {
    const idBytes = r.take(r.u8());
    if (!r.err && !validText(idBytes)) r.err = E.blueprint;
    items.push({ id: text(idBytes), weight: r.u32(), cap: r.u32() });
  }
  r.done();
  const bp = { series, meta, items };
  checkBlueprint(bp);
  return bp;
}

export const blueprintId = (bp) => sha256(encodeBlueprint(bp));
export const totalWeight = (items) => items.reduce((t, it) => t + it.weight, 0);
export const capped = (bp) => bp.items.some((it) => it.cap > 0);
export const available = (bp, soldOut = []) => bp.items.filter((_, i) => !soldOut.includes(i));
const plainSize = (bp) => Math.max(...bp.items.map((it) => utf8.encode(it.id).length)) + 2 + 8;

// ---------------------------------------------------------------- the draw

// A number exactly uniform in [0, total), and how many values were rejected.
export function roll(openKey, id, input, total) {
  const t = BigInt(total);
  const reject = (1n << 64n) % t;
  for (let j = 0; ; j++) {
    const block = kdf(openKey, "HPROLL01", id, input, u32(j));
    const x = new DataView(block.buffer, block.byteOffset).getBigUint64(0);
    if (x >= reject) return { r: x % t, rejected: j };
  }
}

export function itemAt(items, r) {
  let left = BigInt(r);
  let i = 0;
  while (left >= BigInt(items[i].weight)) {
    left -= BigInt(items[i].weight);
    i++;
  }
  return items[i];
}

export function pick(bp, openKey, input, soldOut = [], id = blueprintId(bp)) {
  const items = available(bp, soldOut);
  return itemAt(items, roll(openKey, id, input, totalWeight(items)).r);
}

const commitInput = (input) => kdf(input, "HPINPT01");

export function newDrawRequest(input = randomBytes(32)) {
  return { input, commit: commitInput(input) };
}

// ---------------------------------------------------------------- the box

const prefix = (b) => {
  const parts = [utf8.encode(TAG_BOX), u8(b.keyId), u8(b.series.length), b.series, u16(b.meta.length), b.meta];
  if (!b.draw) parts.push(u8(0));
  else parts.push(u8(1), b.draw.blueprintId, b.draw.inputCommit, u16(b.draw.soldOut.length), ...b.draw.soldOut.map(u16));
  return cat(...parts);
};
const header = (b) => cat(prefix(b), b.nonce);
const keyInput = (b) => sha256(header(b));
const sealedPart = (b) => cat(header(b), b.keyCommit, b.draw ? b.draw.input : new Uint8Array(), u16(b.ciphertext.length), b.ciphertext);
const signedPart = (b) => cat(sealedPart(b), u32(b.revision), encodeProps(b.props));

export const boxId = (b) => sha256(sealedPart(b));
export const encodeBox = (b) => cat(signedPart(b), b.sig);

function readHeader(r) {
  r.tag(TAG_BOX);
  const b = { keyId: r.u8(), series: r.take(r.u8()), meta: r.take(r.u16()), draw: null };
  const flag = r.u8();
  if (flag === 1) {
    b.draw = { blueprintId: r.take(32), inputCommit: r.take(32), soldOut: [], input: null };
    const n = r.u16();
    for (let i = 0; i < n && !r.err; i++) {
      const v = r.u16();
      if (!r.err && i > 0 && v <= b.draw.soldOut[i - 1]) r.err = E.drawField;
      b.draw.soldOut.push(v);
    }
  } else if (flag !== 0 && !r.err) {
    r.err = E.drawField;
  }
  b.nonce = r.take(16);
  return b;
}

export function decodeBox(raw) {
  const r = new Reader(raw);
  const b = readHeader(r);
  b.keyCommit = r.take(32);
  if (b.draw) b.draw.input = r.take(32);
  b.ciphertext = r.take(r.u16());
  b.revision = r.u32();
  b.props = readProps(r);
  b.sig = r.take(SIG_SIZE);
  return r.done(b);
}

// Where each field of an encoded box sits, for drawing it.
export function boxFields(b) {
  const fields = [
    ["tag", 8],
    ["key id", 1],
    ["series", 1 + b.series.length],
    ["meta", 2 + b.meta.length],
    ["draw flag", 1],
    ...(b.draw ? [["blueprint id", 32], ["input commitment", 32], ["sold out list", 2 + 2 * b.draw.soldOut.length]] : []),
    ["nonce", 16],
    ["key commitment", 32],
  ];
  if (b.draw) fields.push(["input", 32]);
  fields.push(["contents length", 2], ["sealed contents", b.ciphertext.length], ["revision", 4], ["properties", encodeProps(b.props).length], ["signature", b.sig.length]);
  return fields;
}

const verifySig = (pub, msg, sig) => {
  try {
    return ml_dsa65.verify(sig, msg, pub);
  } catch {
    return false;
  }
};
const verifyFrom = (keys, keyId, msg, sig) => {
  const pub = keys[keyId];
  if (!pub) fail(E.unknownKey);
  if (!verifySig(pub, msg, sig)) fail(E.signature);
};

export const verifyBox = (b, keys) => verifyFrom(keys, b.keyId, signedPart(b), b.sig);

export function verifyKey(b, openKey) {
  if (openKey.length !== KEY_SIZE) fail(E.keySize);
  if (!same(kdf(openKey, "HPCOMT01"), b.keyCommit)) fail(E.wrongKey);
}

export const supersedes = (b, old) => same(boxId(b), boxId(old)) && b.revision > old.revision;

const aesKey = (openKey) => crypto.subtle.importKey("raw", kdf(openKey, "HPENC001"), "AES-GCM", false, ["encrypt", "decrypt"]);
const aes = (b) => ({ name: "AES-GCM", iv: new Uint8Array(12), additionalData: keyInput(b), tagLength: 128 });
const encrypt = async (b, openKey, plain) => new Uint8Array(await crypto.subtle.encrypt(aes(b), await aesKey(openKey), plain));

const pad = (payload, size) => {
  if (size > MAX_SIZE || payload.length + 2 > size) fail(E.size);
  const plain = new Uint8Array(size);
  plain.set(u16(payload.length));
  plain.set(payload, 2);
  return plain;
};
const unpad = (plain) => {
  const r = new Reader(plain);
  const payload = r.take(r.u16());
  if (r.err || plain.subarray(r.at).some((c) => c !== 0)) fail(E.padding);
  return payload;
};

// Verifies the box and the key, and returns the whole plaintext, padding included.
export async function decrypt(b, keys, openKey) {
  verifyBox(b, keys);
  verifyKey(b, openKey);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(aes(b), await aesKey(openKey), b.ciphertext));
  } catch {
    fail(E.ciphertext);
  }
}
export const openBox = async (b, keys, openKey) => unpad(await decrypt(b, keys, openKey));

const checkSoldOut = (bp, soldOut) => {
  if (soldOut.length >= bp.items.length) fail(E.drawField);
  soldOut.forEach((pos, i) => {
    if (pos >= bp.items.length || bp.items[pos].cap === 0 || (i > 0 && pos <= soldOut[i - 1])) fail(E.drawField);
  });
};
const checkBlueprintOf = (b, bp) => {
  if (!b.draw) fail(E.notDrawn);
  checkBlueprint(bp);
  if (!same(b.draw.blueprintId, blueprintId(bp)) || !same(b.series, utf8.encode(bp.series)) || !same(b.meta, bp.meta)) fail(E.wrongBlueprint);
  checkSoldOut(bp, b.draw.soldOut);
};
const validSerial = (bp, it, serial) => {
  if (!capped(bp)) return serial === 0n;
  return it.cap > 0 ? serial >= 1n && serial <= BigInt(it.cap) : serial >= 1n;
};

// Opens a drawn box and checks the draw: the key and the input must give exactly
// the item inside, under the published odds, with a serial within its cap.
export async function openItem(b, keys, bp, openKey) {
  const payload = await openBox(b, keys, openKey);
  checkBlueprintOf(b, bp);
  if (!same(commitInput(b.draw.input), b.draw.inputCommit)) fail(E.input);
  if (payload.length < 8) fail(E.draw);
  const serial = new DataView(payload.buffer, payload.byteOffset).getBigUint64(0);
  const items = available(bp, b.draw.soldOut);
  const { r, rejected } = roll(openKey, b.draw.blueprintId, b.draw.input, totalWeight(items));
  const item = itemAt(items, r);
  if (item.id !== text(payload.subarray(8)) || !validSerial(bp, item, serial)) fail(E.draw);
  return { item, serial, r, total: totalWeight(items), rejected, available: items };
}

// ------------------------------------------------------------------ tickets

const ticketBox = (t) => ({
  keyId: t.keyId,
  series: t.series,
  meta: t.meta,
  nonce: t.nonce,
  keyCommit: t.keyCommit,
  props: t.props,
  ciphertext: new Uint8Array(),
  revision: 0,
  draw: { blueprintId: t.blueprintId, inputCommit: t.inputCommit, soldOut: t.soldOut, input: null },
});
const signedTicket = (t) => cat(utf8.encode(TAG_TICKET), header(ticketBox(t)), t.keyCommit, encodeProps(t.props));

export const encodeTicket = (t) => cat(signedTicket(t), t.sig);

export function decodeTicket(raw) {
  const r = new Reader(raw);
  r.tag(TAG_TICKET);
  const b = readHeader(r);
  if (!r.err && !b.draw) r.err = E.drawField;
  const keyCommit = r.take(32);
  const props = readProps(r);
  const sig = r.take(SIG_SIZE);
  r.done();
  return { keyId: b.keyId, series: b.series, meta: b.meta, blueprintId: b.draw.blueprintId, inputCommit: b.draw.inputCommit, soldOut: b.draw.soldOut, nonce: b.nonce, keyCommit, props, sig };
}

// The player's check before giving up the input.
export function verifyTicket(t, keys, bp, inputCommit) {
  verifyFrom(keys, t.keyId, signedTicket(t), t.sig);
  checkBlueprintOf(ticketBox(t), bp);
  if (!same(t.inputCommit, inputCommit)) fail(E.input);
}

// The player's check on the box that came for a ticket.
export function verifyBoxTicket(b, keys, t) {
  verifyBox(b, keys);
  if (!b.draw) fail(E.notDrawn);
  if (!same(header(b), header(ticketBox(t))) || !same(b.keyCommit, t.keyCommit)) fail(E.ticket);
  if (b.revision === 0 && !same(encodeProps(b.props), encodeProps(t.props))) fail(E.ticket);
  if (!same(commitInput(b.draw.input), b.draw.inputCommit)) fail(E.input);
}

// ------------------------------------------------------------------- issuer

export class Issuer {
  constructor(keyId, main) {
    if (main.length !== KEY_SIZE) fail(E.keySize);
    this.keyId = keyId;
    this.signSeed = kdf(main, "HPSIGN01");
    this.root = kdf(main, "HPROOT01");
    const pair = ml_dsa65.keygen(this.signSeed);
    this.publicKey = pair.publicKey;
    this.secretKey = pair.secretKey;
  }
  get keys() {
    return { [this.keyId]: this.publicKey };
  }
  sign(msg) {
    return ml_dsa65.sign(msg, this.secretKey, { extraEntropy: false });
  }
  signBox(b) {
    return this.sign(signedPart(b));
  }
  signTicket(t) {
    return this.sign(signedTicket(t));
  }
  // The open key of a box: never stored, the same every time.
  key(b) {
    return kdf(this.root, "HPKEY001", keyInput(b));
  }

  // Seals a payload by hand, with no blueprint behind it.
  async seal({ series = "", meta = new Uint8Array(), props = {}, size }, payload, entropy = randomBytes(32)) {
    checkProps(props);
    const plain = pad(payload, size);
    const b = { keyId: this.keyId, series: utf8.encode(series), meta, draw: null, props, revision: 0 };
    b.nonce = kdf(this.root, "HPNONC01", entropy, prefix(b), plain).subarray(0, 16);
    const openKey = this.key(b);
    b.keyCommit = kdf(openKey, "HPCOMT01");
    b.ciphertext = await encrypt(b, openKey, plain);
    b.sig = this.signBox(b);
    return b;
  }

  prepare(bp, inputCommit, props = {}, { caps, entropy = randomBytes(32) } = {}) {
    checkBlueprint(bp);
    checkProps(props);
    const id = blueprintId(bp);
    const soldOut = [];
    if (capped(bp)) {
      if (!caps) fail(E.noCaps);
      const gone = caps.soldOut(id);
      bp.items.forEach((it, i) => {
        if (it.cap > 0 && gone.includes(it.id)) soldOut.push(i);
      });
      if (soldOut.length === bp.items.length) fail(E.soldOut);
    }
    const t = { keyId: this.keyId, series: utf8.encode(bp.series), meta: bp.meta, blueprintId: id, inputCommit, soldOut, props };
    t.nonce = new Uint8Array(16);
    t.keyCommit = new Uint8Array(32);
    t.nonce = kdf(this.root, "HPNONC01", entropy, prefix(ticketBox(t))).subarray(0, 16);
    t.keyCommit = kdf(this.key(ticketBox(t)), "HPCOMT01");
    return t;
  }

  // Answers a player's commitment with a signed promise of one box.
  ticket(bp, inputCommit, props, opts) {
    const t = this.prepare(bp, inputCommit, props, opts);
    t.sig = this.signTicket(t);
    return t;
  }

  async fill(t, bp, input, caps) {
    const b = ticketBox(t);
    b.draw.input = input;
    const openKey = this.key(b);
    const item = pick(bp, openKey, input, t.soldOut);
    let serial = 0n;
    if (capped(bp)) {
      if (!caps) fail(E.noCaps);
      const taken = caps.take(t.blueprintId, item.id, item.cap, keyInput(b));
      if (taken === null) fail(E.soldOut);
      serial = taken;
    }
    const payload = cat(u64(serial), utf8.encode(item.id));
    b.ciphertext = await encrypt(b, openKey, pad(payload, plainSize(bp)));
    b.sig = this.signBox(b);
    return b;
  }

  // Turns a ticket and the player's input into the box. Asking again gives the
  // same box. An item that sold out since the ticket fails: nothing else is given.
  async redeem(t, bp, input, caps) {
    verifyFrom(this.keys, t.keyId, signedTicket(t), t.sig);
    checkBlueprintOf(ticketBox(t), bp);
    if (!same(commitInput(input), t.inputCommit)) fail(E.input);
    return this.fill(t, bp, input, caps);
  }

  // Draws a box in one call, with no player. The issuer is trusted here.
  async mint(bp, props, caps) {
    for (let i = 0; i <= bp.items.length; i++) {
      const req = newDrawRequest();
      const t = this.prepare(bp, req.commit, props, { caps });
      try {
        return await this.fill(t, bp, req.input, caps);
      } catch (err) {
        if (!isError(err, E.soldOut)) throw err;
      }
    }
    fail(E.soldOut);
  }

  // Replaces the properties and signs the next revision: same id, same contents.
  rewrite(ledger, b, props) {
    verifyBox(b, this.keys);
    checkProps(props);
    const next = { ...b, props, revision: ledger.advance(boxId(b), b.revision) };
    next.sig = this.signBox(next);
    return next;
  }

  // The open key, once per box and only to its owner. Old revisions are refused.
  release(ledger, b, owner) {
    verifyBox(b, this.keys);
    const user = b.props[PROP_USER];
    if (user !== undefined && user !== owner) fail(E.notOwner);
    if (ledger.claim(boxId(b), b.revision, owner) !== owner) fail(E.claimed);
    return this.key(b);
  }
}

// ------------------------------------------------- state, kept in memory here

export class MemLedger {
  rows = new Map();
  row(id, rev) {
    const key = hex(id);
    if (!this.rows.has(key)) this.rows.set(key, { revision: rev, owner: null });
    return this.rows.get(key);
  }
  claim(id, rev, owner) {
    const row = this.row(id, rev);
    if (row.revision > rev) fail(E.stale);
    row.owner ??= owner;
    return row.owner;
  }
  advance(id, rev) {
    const row = this.row(id, rev);
    row.revision = Math.max(row.revision, rev) + 1;
    return row.revision;
  }
}

export class MemCaps {
  taken = new Map();
  draws = new Map();
  full = new Set();
  soldOut() {
    return [...this.full];
  }
  // The next serial, or null once the cap is reached. A retry keeps its serial.
  take(_, item, cap, draw) {
    const key = `${item}:${hex(draw)}`;
    if (this.draws.has(key)) return this.draws.get(key);
    const n = this.taken.get(item) ?? 0n;
    if (cap > 0 && n >= BigInt(cap)) return null;
    this.taken.set(item, n + 1n);
    if (cap > 0 && n + 1n === BigInt(cap)) this.full.add(item);
    this.draws.set(key, n + 1n);
    return n + 1n;
  }
}
