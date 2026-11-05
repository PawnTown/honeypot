// The demo: the real protocol from honeypot.js, in a browser. Nothing is sent
// anywhere. The issuer, its ledger and its counter live in this tab.
import * as hp from "./honeypot.js";

const $ = (id) => document.getElementById(id);
const SERIES = "demo/hive";
const DEFAULTS = [
  ["wooden sword", 700, ""],
  ["silver shield", 250, ""],
  ["golden crown", 45, ""],
  ["dragon egg", 5, "3"],
];

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const short = (b) => `${hp.hex(b.subarray(0, 8))}…`;
const count = (n) => Number(n).toLocaleString("en-US");
const percent = (x) => `${(x * 100).toLocaleString("en-US", { maximumFractionDigits: 3 })} %`;
const paint = () => new Promise((done) => requestAnimationFrame(() => setTimeout(done, 0)));
const encoded = (s) => new TextEncoder().encode(s);

function show(id, html, tone) {
  const out = $(id);
  out.hidden = false;
  out.className = tone ? `result ${tone}` : "result";
  out.innerHTML = html;
}
const hide = (...ids) => ids.forEach((id) => ($(id).hidden = true));

let issuer;
let keys;
let blueprint = null;
let blueprintHex = "";
let caps = new hp.MemCaps();
let ledger = new hp.MemLedger();
let box = null;
let tookPart = false;
let flipped = null;
let cellMap = [];

// ---------------------------------------------------------------- blueprint

function addRow(id = "", weight = "", cap = "") {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><input class="item-id" aria-label="Item name" value="${esc(id)}" autocomplete="off" spellcheck="false"></td>
    <td class="num" data-label="Weight"><input class="item-weight" aria-label="Weight" inputmode="numeric" value="${esc(weight)}"></td>
    <td class="num" data-label="Cap"><input class="item-cap" aria-label="Cap" inputmode="numeric" placeholder="none" value="${esc(cap)}"></td>
    <td class="chance"></td>
    <td><button class="icon-btn" type="button">Remove</button></td>`;
  tr.addEventListener("input", readBlueprint);
  tr.querySelector("button").addEventListener("click", () => {
    tr.remove();
    readBlueprint();
  });
  $("items").append(tr);
}

function readBlueprint() {
  const rows = [...$("items").rows];
  const items = rows.map((tr) => {
    const cap = tr.querySelector(".item-cap").value.trim();
    return { id: tr.querySelector(".item-id").value.trim(), weight: Number(tr.querySelector(".item-weight").value), cap: cap === "" ? 0 : Number(cap) };
  });
  const total = items.reduce((t, it) => t + (Number.isFinite(it.weight) ? it.weight : 0), 0);
  rows.forEach((tr, i) => {
    const w = items[i].weight;
    tr.querySelector(".chance").innerHTML = w > 0 && total > 0 ? `${percent(w / total)}<small>${count(w)} in ${count(total)}</small>` : "";
  });
  let next = null;
  try {
    next = hp.newBlueprint(SERIES, null, items);
  } catch {
    $("bp-note").innerHTML = `<span class="err-line">Give every item its own name and a whole-number weight of at least 1. A cap is a whole number, or empty for no limit.</span>`;
  }
  blueprint = next;
  $("draw-btn").disabled = !next;
  $("odds-btn").disabled = !next;
  document.querySelectorAll("[data-cheat]").forEach((b) => (b.disabled = !next));
  if (!next) return;
  const id = hp.hex(hp.blueprintId(next));
  if (id !== blueprintHex) {
    blueprintHex = id;
    caps = new hp.MemCaps();
    clearBox();
    $("odds-out").innerHTML = "";
    $("guess").innerHTML = next.items.map((it) => `<option>${esc(it.id)}</option>`).join("");
  }
  $("bp-note").innerHTML = `Blueprint id <code>${id.slice(0, 16)}…</code>. Change anything and the id changes, so a box always names the exact odds it was drawn under.`;
}

function clearBox() {
  box = null;
  flipped = null;
  $("box").hidden = true;
  $("open").hidden = true;
  $("talk").innerHTML = "";
}

// --------------------------------------------------------------------- draw

function say(who, html, size) {
  const li = document.createElement("li");
  li.className = who === "You" ? "you" : "issuer";
  li.innerHTML = `<span class="who">${who}</span>${html}${size ? ` <span class="size">${count(size)} bytes</span>` : ""}`;
  $("talk").append(li);
}

async function draw() {
  clearBox();
  const owner = $("owner").value.trim();
  const props = owner ? { [hp.PROP_USER]: owner } : {};
  const mode = document.querySelector('input[name="mode"]:checked').value;
  tookPart = mode === "ticket";
  $("draw-btn").disabled = true;
  try {
    let drawn;
    if (tookPart) {
      const request = hp.newDrawRequest();
      say("You", `Picked a secret input and sent only a commitment to it: <code>${short(request.commit)}</code>`, 32);
      await paint();
      const ticket = hp.decodeTicket(hp.encodeTicket(issuer.ticket(blueprint, request.commit, props, { caps })));
      const gone = ticket.soldOut.map((i) => blueprint.items[i].id);
      say("Issuer", `Signed a ticket that fixes the box and its key, before seeing your input.${gone.length ? ` Sold out for this draw: ${esc(gone.join(", "))}.` : ""}`, hp.encodeTicket(ticket).length);
      await paint();
      hp.verifyTicket(ticket, keys, blueprint, request.commit);
      say("You", `Checked the ticket and its odds, then revealed your input: <code>${short(request.input)}</code>`, 32);
      await paint();
      drawn = await issuer.redeem(ticket, blueprint, request.input, caps);
      say("Issuer", "Worked out the item from the key and your input, sealed it and signed the box.", hp.encodeBox(drawn).length);
      await paint();
      hp.verifyBoxTicket(drawn, keys, ticket);
      say("You", "Checked that this is the box the ticket promised. You cannot read it yet.");
    } else {
      drawn = await issuer.mint(blueprint, props, caps);
      say("Issuer", "Picked an input by itself, worked out the item, sealed it and signed the box. Only the issuer knows whether it did this more than once.", hp.encodeBox(drawn).length);
    }
    box = hp.decodeBox(hp.encodeBox(drawn));
    renderBox();
  } catch (err) {
    if (hp.isError(err, hp.E.soldOut)) {
      const nothingLeft = blueprint.items.every((it) => it.cap > 0 && caps.soldOut().includes(it.id));
      say(
        "Issuer",
        nothingLeft
          ? "Every item has sold out, so there is nothing left to draw. Raise a cap in step 1, which makes a new blueprint."
          : "This draw landed on an item that sold out after the ticket was signed. The issuer may not give you something else, so this ticket is refunded. Draw again, and the next ticket lists the item as sold out.",
      );
    } else {
      say("Issuer", `<span class="err-line">${esc(err.message)}</span>`);
    }
  }
  $("draw-btn").disabled = !blueprint;
}

// ---------------------------------------------------------------------- box

const KINDS = {
  tag: "magic",
  "key id": "int",
  series: "text",
  meta: "int",
  "draw flag": "int",
  "blueprint id": "hash",
  "input commitment": "hash",
  "sold out list": "int",
  nonce: "key",
  "key commitment": "hash",
  input: "key",
  "contents length": "int",
  "sealed contents": "seal",
  revision: "int",
  properties: "text",
  signature: "sig",
};
const LETTERS = new Set(["tag", "series", "properties"]);
const FIELD_LABELS = [
  ["text", "readable text"],
  ["magic", "tag"],
  ["int", "numbers"],
  ["hash", "ids and commitments"],
  ["key", "nonce and input"],
  ["seal", "sealed contents"],
  ["sig", "signature"],
];

function cellText(code, letters) {
  return letters && code > 32 && code < 127 ? String.fromCharCode(code) : code.toString(16).padStart(2, "0");
}

function renderComb(changed = new Set()) {
  const raw = hp.encodeBox(box);
  const perRow = innerWidth < 560 ? 10 : 14;
  const fields = hp.boxFields(box);
  const bare = raw.length - hp.SIG_SIZE;
  const shown = bare + (perRow * Math.ceil((bare + 1) / perRow) - bare);
  cellMap = [];
  fields.forEach(([name, len]) => {
    for (let k = 0; k < len; k++) cellMap.push({ name, k, len });
  });
  const frag = document.createDocumentFragment();
  let row;
  for (let i = 0; i < shown; i++) {
    if (i % perRow === 0) {
      row = document.createElement("div");
      row.className = "comb-row";
      frag.append(row);
    }
    const { name } = cellMap[i];
    const cell = document.createElement("span");
    const letters = LETTERS.has(name);
    cell.className = `cell k-${KINDS[name]}${letters && raw[i] > 32 && raw[i] < 127 ? " letter" : ""}${changed.has(name) ? " changed" : ""}`;
    cell.dataset.i = i;
    cell.textContent = cellText(raw[i], letters);
    row.append(cell);
  }
  const grid = document.createElement("div");
  grid.className = "comb-grid";
  grid.style.setProperty("--n", perRow);
  grid.append(frag);
  $("comb").style.setProperty("--n", perRow);
  $("comb").replaceChildren(grid);
  const more = hp.SIG_SIZE - (shown - bare);
  $("comb-legend").innerHTML =
    FIELD_LABELS.map(([kind, label]) => `<span class="comb-key"><i class="cell k-${kind}"></i>${label}</span>`).join("") + `<span>Plus ${count(more)} more signature bytes.</span>`;
  flipped = null;
}

function renderFacts() {
  const owner = box.props[hp.PROP_USER];
  $("facts").innerHTML = `
    <dt>Owner</dt><dd>${owner === undefined ? "none, whoever claims it first" : esc(owner)}</dd>
    <dt>Revision</dt><dd>${box.revision}</dd>
    <dt>Series</dt><dd>${esc(hp.text(box.series))}</dd>
    <dt>Box id</dt><dd><code>${short(hp.boxId(box))}</code></dd>
    <dt>Blueprint</dt><dd><code>${short(box.draw.blueprintId)}</code></dd>
    <dt>Size</dt><dd>${count(hp.encodeBox(box).length)} bytes</dd>
    <dt>Contents</dt><dd>hidden</dd>`;
  hp.verifyBox(box, keys);
  $("genuine").textContent = "Genuine. The signature checks out against the issuer's public key.";
}

function renderBox() {
  $("box").hidden = false;
  $("open").hidden = false;
  hide("flip-result", "guess-result", "rewrite-result", "open-result", "reveal");
  $("open-btn").disabled = false;
  $("who").value = box.props[hp.PROP_USER] ?? "alice";
  renderComb();
  renderFacts();
  $("box").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

function flip(i) {
  const cells = $("comb").querySelectorAll(".cell");
  const raw = hp.encodeBox(box);
  const undo = flipped === i;
  if (flipped !== null) {
    const was = cells[flipped];
    was.classList.remove("flipped");
    was.textContent = cellText(raw[flipped], LETTERS.has(cellMap[flipped].name));
    flipped = null;
  }
  if (undo) {
    hide("flip-result");
    return;
  }
  raw[i] ^= 1;
  let answer;
  try {
    hp.verifyBox(hp.decodeBox(raw), keys);
    answer = "It still verifies, which should never happen.";
  } catch (err) {
    answer = `<code>${esc(err.message)}</code>`;
  }
  flipped = i;
  cells[i].classList.add("flipped");
  cells[i].textContent = cellText(raw[i], LETTERS.has(cellMap[i].name));
  show("flip-result", `You flipped one bit of the ${esc(cellMap[i].name)}, and the box no longer checks out: ${answer} Click the cell again to undo.`, "bad");
}

function guess() {
  const item = $("guess").value;
  const raw = hp.hex(hp.encodeBox(box));
  const name = encoded(item);
  const found = raw.includes(hp.hex(name)) || raw.includes(hp.hex(hp.sha256(name)));
  show(
    "guess-result",
    found
      ? `"${esc(item)}" appears in the box, which should never happen.`
      : `"${esc(item)}" is not in the box, and neither is its SHA-256 hash. You would get this same answer for every item. The only real test is the open key, a 256-bit secret.`,
  );
}

function rewrite() {
  const owner = $("new-owner").value.trim();
  if (!owner) {
    show("rewrite-result", "Enter a name for the new owner.", "bad");
    return;
  }
  const id = hp.hex(hp.boxId(box));
  box = hp.decodeBox(hp.encodeBox(issuer.rewrite(ledger, box, { ...box.props, [hp.PROP_USER]: owner })));
  renderComb(new Set(["revision", "properties", "signature"]));
  renderFacts();
  $("who").value = owner;
  hide("flip-result", "open-result");
  show(
    "rewrite-result",
    `Now owned by ${esc(owner)}, at revision ${box.revision}. The highlighted cells are all that changed. The box id is ${hp.hex(hp.boxId(box)) === id ? "the same" : "different"}, so the contents and the key are too. Only the main key can sign this.`,
    "good",
  );
}

// --------------------------------------------------------------------- open

async function openIt() {
  const who = $("who").value.trim();
  hide("open-result", "reveal");
  let key;
  try {
    key = issuer.release(ledger, box, who);
  } catch (err) {
    const hints = {
      [hp.E.notOwner]: `This box belongs to ${esc(box.props[hp.PROP_USER])}, so the issuer will not give ${esc(who || "you")} the key.`,
      [hp.E.claimed]: "Someone else already claimed this box, and a claim is final.",
    };
    const reason = Object.keys(hints).find((m) => hp.isError(err, m));
    show("open-result", `${reason ? hints[reason] : ""} <code>${esc(err.message)}</code>`, "bad");
    return;
  }
  const drawn = await hp.openItem(box, keys, blueprint, key);
  const plain = await hp.decrypt(box, keys, key);
  fillComb(plain);

  const it = drawn.item;
  const serial = it.cap > 0 ? `Number ${drawn.serial} of ${count(it.cap)} ever` : drawn.serial > 0n ? `Number ${count(drawn.serial)} of this item` : "";
  const proofs = [
    "This key is the one the box committed to, in its signed part.",
    `It decrypts the contents to exactly this item. Open key: <code>${short(key)}</code>`,
    `The input in the box matches its commitment${tookPart ? ", and it is the one you picked" : ""}.`,
    `Recomputed from the key and the input: ${count(drawn.r)} out of ${count(drawn.total)} lands on ${esc(it.id)}.`,
  ];
  if (it.cap > 0) proofs.push(`Its serial is within the cap of ${count(it.cap)}.`);
  proofs.push(`The ledger has one row for this box, claimed by ${esc(who)}. The key was derived just now and is stored nowhere.`);
  $("reveal").hidden = false;
  $("reveal").innerHTML = `
    <p class="reveal-item">${esc(it.id)}</p>
    <p class="reveal-sub">${serial ? `${serial}. ` : ""}Its chance in this draw was ${percent(it.weight / drawn.total)}.</p>
    <ul class="proofs">${proofs.map((p) => `<li><span>${p}</span></li>`).join("")}</ul>
    <p class="note">${tookPart ? "You took part in the draw, so the issuer could not aim for this item." : "The issuer drew this alone, so you are trusting it did not mint until it liked one. Try taking part in step 2."}</p>
    <div class="row"><button class="btn quiet" id="again" type="button">Draw another box</button></div>`;
  $("again").addEventListener("click", () => $("draw").scrollIntoView({ behavior: "smooth" }));
  $("facts").lastElementChild.textContent = it.id;
}

// The moment the protocol is about: the dark cells fill, and the item shows up.
function fillComb(plain) {
  const cells = [...$("comb").querySelectorAll(".cell")];
  let k = 0;
  cells.forEach((cell, i) => {
    if (cellMap[i].name !== "sealed contents") return;
    const isTag = k >= plain.length;
    if (!isTag) {
      const code = plain[k];
      cell.textContent = code > 32 && code < 127 ? String.fromCharCode(code) : code === 32 ? "␣" : code.toString(16).padStart(2, "0");
      cell.classList.toggle("letter", code >= 32 && code < 127);
    }
    cell.classList.add("opened");
    cell.classList.toggle("tagbyte", isTag);
    cell.style.setProperty("--d", `${k * 35}ms`);
    k++;
  });
  $("cell-info").textContent = "White cells: the decrypted contents. Brown cells: the authentication tag.";
}

// ------------------------------------------------------------------- cheats

const scratch = () =>
  hp.newBlueprint(
    `${SERIES}/scratch`,
    null,
    blueprint.items.map((it) => ({ id: it.id, weight: it.weight, cap: 0 })),
  );

const CHEATS = [
  {
    title: "Open a box with another box's key",
    why: "Each box has its own key, and its commitment admits no other.",
    run: async () => {
      const bp = scratch();
      const [a, b] = [await issuer.mint(bp, {}), await issuer.mint(bp, {})];
      await hp.openBox(a, keys, issuer.key(b));
    },
  },
  {
    title: "Claim a box that belongs to someone else",
    why: "The issuer compares the signed owner with whoever is asking.",
    run: async () => {
      const b = await issuer.mint(scratch(), { [hp.PROP_USER]: "alice" });
      issuer.release(new hp.MemLedger(), b, "mallory");
    },
  },
  {
    title: "Claim a box twice",
    why: "A claim takes one row. The first one wins, and the same owner asking again only gets the same key.",
    run: async () => {
      const l = new hp.MemLedger();
      const b = await issuer.mint(scratch(), {});
      issuer.release(l, b, "alice");
      issuer.release(l, b, "mallory");
    },
  },
  {
    title: "Give a box away, then open it with the old copy",
    why: "The old copy still verifies, because a signature cannot expire. The ledger knows it is old.",
    run: async () => {
      const l = new hp.MemLedger();
      const old = await issuer.mint(scratch(), { [hp.PROP_USER]: "alice" });
      issuer.rewrite(l, old, { [hp.PROP_USER]: "bob" });
      hp.verifyBox(old, keys);
      issuer.release(l, old, "alice");
    },
  },
  {
    title: "Set your own name on the box",
    why: "The signature covers the properties, and only the main key can sign.",
    run: async () => {
      const b = await issuer.mint(scratch(), { [hp.PROP_USER]: "alice" });
      hp.verifyBox({ ...b, props: { [hp.PROP_USER]: "mallory" } }, keys);
    },
  },
  {
    title: "Forge a box with another key",
    why: "Players pin the issuer's public key. This box is signed with a different one.",
    run: async () => {
      const other = new hp.Issuer(1, hp.randomBytes(32));
      hp.verifyBox(await other.mint(scratch(), {}), keys);
    },
  },
  {
    title: "As the issuer, send another box than the ticket promised",
    why: "The ticket fixed the key before the input was known, so a box with another key is rejected.",
    run: async () => {
      const bp = scratch();
      const request = hp.newDrawRequest();
      const ticket = issuer.ticket(bp, request.commit, {});
      hp.verifyBoxTicket(await issuer.mint(bp, {}), keys, ticket);
    },
  },
  {
    title: "As the issuer, deliver a cheaper item than the draw gave",
    why: "Anyone with the key recomputes the item from the key and the input. The signed box is proof of the fraud.",
    needsTwo: true,
    run: async () => {
      const bp = scratch();
      const request = hp.newDrawRequest();
      const ticket = issuer.ticket(bp, request.commit, {});
      const honest = await issuer.redeem(ticket, bp, request.input);
      const key = issuer.key(honest);
      const item = hp.pick(bp, key, request.input);
      const other = bp.items.find((it) => it.id !== item.id);
      const forged = await issuer.fill(ticket, { ...bp, items: [other] }, request.input);
      await hp.openItem(forged, keys, bp, key);
    },
  },
];

function renderCheats() {
  $("cheats").innerHTML = CHEATS.map(
    (c, i) => `<li>
      <div class="cheat-top"><b>${esc(c.title)}</b><button class="btn quiet" type="button" data-cheat="${i}">Try it</button></div>
      <p class="cheat-why" hidden>${esc(c.why)}</p>
      <p class="result" id="cheat-${i}" aria-live="polite" hidden></p>
    </li>`,
  ).join("");
  $("cheats").addEventListener("click", async (e) => {
    const button = e.target.closest("[data-cheat]");
    if (!button || !blueprint) return;
    const i = Number(button.dataset.cheat);
    const c = CHEATS[i];
    if (c.needsTwo && blueprint.items.length < 2) {
      show(`cheat-${i}`, "This needs at least two items in the blueprint.");
      return;
    }
    button.disabled = true;
    await paint();
    try {
      await c.run();
      show(`cheat-${i}`, "It went through, which should never happen.", "bad");
    } catch (err) {
      button.closest("li").querySelector(".cheat-why").hidden = false;
      show(`cheat-${i}`, `Stopped: <code>${esc(err.message)}</code>`, "good");
    }
    button.disabled = false;
  });
}

// --------------------------------------------------------------------- odds

async function checkOdds() {
  const n = Number($("odds-n").value);
  const bp = blueprint;
  const id = hp.blueprintId(bp);
  const counts = new Map(bp.items.map((it) => [it.id, 0]));
  const expected = new Map(bp.items.map((it) => [it.id, 0]));
  const soldAt = new Map();
  const gone = [];
  let drawn = 0;
  $("odds-btn").disabled = true;
  for (let i = 0; i < n && gone.length < bp.items.length; i++) {
    const items = hp.available(bp, gone);
    const total = hp.totalWeight(items);
    for (const it of items) expected.set(it.id, expected.get(it.id) + it.weight / total);
    const it = hp.itemAt(items, hp.roll(hp.randomBytes(32), id, hp.randomBytes(32), total).r);
    const c = counts.get(it.id) + 1;
    counts.set(it.id, c);
    drawn++;
    if (it.cap > 0 && c >= it.cap) {
      gone.push(bp.items.indexOf(it));
      gone.sort((a, b) => a - b);
      soldAt.set(it.id, drawn);
    }
    if (i % 500 === 499) {
      $("odds-progress").textContent = `${count(i + 1)} of ${count(n)}`;
      await paint();
    }
  }
  $("odds-progress").textContent = "";
  $("odds-btn").disabled = false;
  renderOdds(bp, counts, expected, soldAt, drawn, n);
}

function chiSquare(bp, counts, expected) {
  let chi = 0;
  let df = -1;
  for (const it of bp.items) {
    const e = expected.get(it.id);
    if (e < 5) continue;
    chi += (counts.get(it.id) - e) ** 2 / e;
    df++;
  }
  if (df < 1) return null;
  // The 99.9 % point of chi-square, exact up to 10 degrees of freedom and then
  // the Wilson-Hilferty approximation.
  const TABLE = [10.83, 13.82, 16.27, 18.47, 20.52, 22.46, 24.32, 26.12, 27.88, 29.59];
  const a = 2 / (9 * df);
  return { chi, df, limit: TABLE[df - 1] ?? df * (1 - a + 3.09 * Math.sqrt(a)) ** 3 };
}

function renderOdds(bp, counts, expected, soldAt, drawn, asked) {
  const total = bp.items.reduce((t, it) => t + it.weight, 0);
  const rows = [...bp.items].sort((a, b) => b.weight - a.weight);
  const scale = Math.max(...rows.map((it) => Math.max(counts.get(it.id), expected.get(it.id)))) / drawn;
  const body = rows
    .map((it) => {
      const got = counts.get(it.id) / drawn;
      const want = expected.get(it.id) / drawn;
      const tip = `${esc(it.id)}: ${count(counts.get(it.id))} of ${count(drawn)} boxes. Published chance ${percent(it.weight / total)}, expected share ${percent(want)}.`;
      return `<tr data-tip="${tip}">
        <td>${esc(it.id)}<span class="odds-sub">published ${percent(it.weight / total)}, ${count(counts.get(it.id))} boxes</span></td>
        <td class="col-pub">${percent(it.weight / total)}</td>
        <td>${percent(got)}</td>
        <td class="col-count">${count(counts.get(it.id))}</td>
        <td class="barcell"><div class="bar-track"><div class="bar" style="width:${((got / scale) * 100).toFixed(2)}%"></div><div class="tick" style="left:${((want / scale) * 100).toFixed(2)}%"></div></div></td>
      </tr>`;
    })
    .join("");
  const stat = chiSquare(bp, counts, expected);
  const verdict = !stat
    ? "Too few boxes for a statistical check. Draw more."
    : stat.chi <= stat.limit
      ? `The gap from the expected share is what chance alone gives: chi-square ${stat.chi.toFixed(2)}, under the 99.9 % limit of ${stat.limit.toFixed(2)}.`
      : `The gap is bigger than chance usually gives: chi-square ${stat.chi.toFixed(2)}, over the 99.9 % limit of ${stat.limit.toFixed(2)}. About 1 run in 1000 does this by chance, so run it again.`;
  const notes = [...soldAt]
    .map(([id, at]) => {
      const it = bp.items.find((x) => x.id === id);
      return `${esc(id)} sold out after ${count(at)} boxes, at its cap of ${count(it.cap)}. The rest kept their weights over a smaller total.`;
    })
    .join(" ");
  $("odds-out").innerHTML = `
    <p class="viz-title">Drawn share of ${count(drawn)} boxes, against the expected share</p>
    <div class="viz-legend"><span><i class="lg-bar"></i>drawn</span><span><i class="lg-tick"></i>expected, counting sold out items</span></div>
    <div class="table-wrap">
    <table class="odds">
      <thead><tr><th scope="col">Item</th><th scope="col" class="col-pub">Published</th><th scope="col">Drawn</th><th scope="col" class="col-count">Boxes</th><th scope="col"><span class="sr-only">Chart</span></th></tr></thead>
      <tbody>${body}</tbody>
    </table>
    </div>
    <p class="note">${verdict}</p>
    ${notes ? `<p class="note">${notes}</p>` : ""}
    ${drawn < asked ? `<p class="note">Every item sold out after ${count(drawn)} boxes, so the run stopped there.</p>` : ""}`;
}

function oddsTooltip() {
  const tip = document.createElement("div");
  tip.className = "viz-tip";
  tip.hidden = true;
  document.body.append(tip);
  const out = $("odds-out");
  out.addEventListener("pointermove", (e) => {
    const row = e.target.closest("[data-tip]");
    tip.hidden = !row;
    if (!row) return;
    tip.textContent = row.dataset.tip;
    const x = Math.min(e.clientX + 14, innerWidth - tip.offsetWidth - 8);
    const y = e.clientY - tip.offsetHeight - 12;
    tip.style.left = `${x}px`;
    tip.style.top = `${Math.max(8, y)}px`;
  });
  out.addEventListener("pointerleave", () => (tip.hidden = true));
}

// --------------------------------------------------------------------- start

async function start() {
  if (!crypto.subtle) {
    $("issuer-note").innerHTML = `<span class="err-line">This page needs a secure context for AES-GCM. Open it over https or on localhost.</span>`;
    return;
  }
  await paint();
  issuer = new hp.Issuer(1, hp.randomBytes(hp.KEY_SIZE));
  keys = issuer.keys;
  $("issuer-note").innerHTML = `Throwaway issuer ready. Its public key is <code>${short(issuer.publicKey)}</code>, ${count(issuer.publicKey.length)} bytes. The main key, ledger and counter live only in this tab.`;
  renderCheats();
  DEFAULTS.forEach((d) => addRow(...d));
  readBlueprint();
  oddsTooltip();
  $("add-item").addEventListener("click", () => {
    addRow(`item ${$("items").rows.length + 1}`, "10", "");
    readBlueprint();
  });
  $("draw-btn").addEventListener("click", draw);
  $("flip-random").addEventListener("click", () => flip(Math.floor(Math.random() * $("comb").querySelectorAll(".cell").length)));
  $("guess-btn").addEventListener("click", guess);
  $("rewrite-btn").addEventListener("click", rewrite);
  $("open-btn").addEventListener("click", openIt);
  $("odds-btn").addEventListener("click", checkOdds);
  $("comb").addEventListener("click", (e) => {
    const cell = e.target.closest(".cell");
    if (cell) flip(Number(cell.dataset.i));
  });
  $("comb").addEventListener("pointerover", (e) => {
    const cell = e.target.closest(".cell");
    if (!cell) return;
    const { name, k, len } = cellMap[Number(cell.dataset.i)];
    $("cell-info").textContent = `${name}, byte ${k + 1} of ${count(len)}`;
  });
}

start();
