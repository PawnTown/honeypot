// Works out which bytes of a real box or ticket belong to which field, so every
// picture on the site is drawn from the vectors and cannot drift from them.
const byteAt = (hex, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16);
const u16At = (hex, i) => (byteAt(hex, i) << 8) | byteAt(hex, i + 1);

export const SIG_SIZE = 3309;

function headerSegs(hex, start) {
  let at = start;
  const segs = [];
  const add = (len, label, kind, extra = {}) => {
    segs.push({ len, label, kind, ...extra });
    at += len;
  };
  add(8, "tag", "magic", { chars: true, legend: "tag" });
  add(1, "key id", "int", { legend: "numbers" });
  const series = byteAt(hex, at);
  add(1, "series length", "int", { legend: "numbers" });
  add(series, "series", "text", { chars: true, legend: "readable text" });
  const meta = u16At(hex, at);
  add(2, "meta length", "int", { legend: "numbers" });
  if (meta) add(meta, "meta", "text", { chars: true, legend: "readable text" });
  const drawn = byteAt(hex, at);
  add(1, "draw flag", "int", { legend: "numbers" });
  if (drawn) {
    add(32, "blueprint id", "hash", { legend: "ids and commitments" });
    add(32, "input commitment", "hash", { legend: "ids and commitments" });
    const sold = u16At(hex, at);
    add(2 + 2 * sold, `sold out list, ${sold} items`, "int", { legend: "numbers" });
  }
  add(16, "nonce", "key", { legend: "nonce and input" });
  return { segs, at, drawn: !!drawn };
}

function propSegs(hex, start) {
  let at = start;
  const n = byteAt(hex, at);
  const segs = [{ len: 1, label: "property count", kind: "int", legend: "numbers" }];
  at += 1;
  for (let i = 0; i < n; i++) {
    const name = byteAt(hex, at);
    const value = u16At(hex, at + 1 + name);
    segs.push({ len: 1, label: "name length", kind: "int", legend: "numbers" });
    segs.push({ len: name, label: "property name", kind: "text", chars: true, legend: "readable text" });
    segs.push({ len: 2, label: "value length", kind: "int", legend: "numbers" });
    if (value) segs.push({ len: value, label: "property value", kind: "text", chars: true, legend: "readable text" });
    at += 1 + name + 2 + value;
  }
  return { segs, at };
}

// Segments of a box. `sig` is how many signature bytes to keep in the picture.
export function boxSegs(hex, sig = SIG_SIZE) {
  const h = headerSegs(hex, 0);
  const segs = [...h.segs];
  let at = h.at;
  segs.push({ len: 32, label: "key commitment", kind: "hash", legend: "ids and commitments" });
  at += 32;
  if (h.drawn) {
    segs.push({ len: 32, label: "input", kind: "key", legend: "nonce and input" });
    at += 32;
  }
  const ct = u16At(hex, at);
  segs.push({ len: 2, label: "contents length", kind: "int", legend: "numbers" });
  segs.push({ len: ct, label: "sealed contents", kind: "seal", legend: "sealed contents" });
  at += 2 + ct;
  segs.push({ len: 4, label: "revision", kind: "int", legend: "numbers" });
  at += 4;
  const p = propSegs(hex, at);
  segs.push(...p.segs);
  at = p.at;
  segs.push({ len: sig, label: sig === SIG_SIZE ? "signature" : `signature, first ${sig} of ${SIG_SIZE} bytes`, kind: "sig", legend: "signature" });
  return { segs, hex: hex.slice(0, (at + sig) * 2) };
}

export function ticketSegs(hex, sig = SIG_SIZE) {
  const h = headerSegs(hex, 8);
  const segs = [{ len: 8, label: "ticket tag", kind: "magic", chars: true, legend: "tag" }, ...h.segs];
  segs.push({ len: 32, label: "key commitment", kind: "hash", legend: "ids and commitments" });
  const p = propSegs(hex, h.at + 32);
  segs.push(...p.segs);
  segs.push({ len: sig, label: sig === SIG_SIZE ? "signature" : `signature, first ${sig} of ${SIG_SIZE} bytes`, kind: "sig", legend: "signature" });
  return { segs, hex: hex.slice(0, (p.at + sig) * 2) };
}

export function blueprintSegs(hex) {
  let at = 8;
  const segs = [{ len: 8, label: "tag", kind: "magic" }];
  const series = byteAt(hex, at);
  segs.push({ len: 1, label: "series length", kind: "int" }, { len: series, label: "series", kind: "text" });
  at += 1 + series;
  const meta = u16At(hex, at);
  segs.push({ len: 2, label: "meta length", kind: "int" });
  if (meta) segs.push({ len: meta, label: "meta", kind: "text" });
  at += 2 + meta;
  const n = u16At(hex, at);
  segs.push({ len: 2, label: `item count, ${n}`, kind: "int" });
  at += 2;
  for (let i = 0; i < n; i++) {
    const id = byteAt(hex, at);
    segs.push({ len: 1, label: "id length", kind: "int" }, { len: id, label: "item id", kind: "text" }, { len: 4, label: "weight", kind: "hash" }, { len: 4, label: "cap", kind: "var" });
    at += 1 + id + 8;
  }
  return segs;
}
