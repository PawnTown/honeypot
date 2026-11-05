// Diagram helpers for the docs. Everything renders to static HTML or SVG at
// build time, so the published pages need no script to show a picture.

export const esc = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// ------------------------------------------------------------- byte layouts

// A layout strip: one box per field, its width growing with the field's size
// (square root, so a 64-byte signature does not crush a 1-byte op).
//   fields: [{ name, size: number | "var" | string, kind, note }]
export function layout(title, fields, { total, caption } = {}) {
  const cells = fields
    .map((f) => {
      const n = typeof f.size === "number" ? f.size : 2;
      const grow = Math.max(1, Math.sqrt(n) * 1.6).toFixed(2);
      const size = typeof f.size === "number" ? `${f.size} B` : f.size;
      return `<div class="lf k-${f.kind || "int"}" style="flex-grow:${grow}" tabindex="0">
  <span class="lf-name">${f.name}</span>
  <span class="lf-size">${esc(size)}</span>
  ${f.note ? `<span class="lf-note">${f.note}</span>` : ""}
</div>`;
    })
    .join("");
  return `<figure class="layout">
  <figcaption><span class="layout-title">${title}</span>${total ? `<span class="layout-total">${esc(total)}</span>` : ""}</figcaption>
  <div class="lf-row">${cells}</div>
  ${caption ? `<p class="layout-cap">${caption}</p>` : ""}
</figure>`;
}

// A real hex dump, coloured by field. `segments` are [{ len, label, kind }];
// a segment of len "rest" takes what is left. Throws when the segments do not
// add up, so a drawing never lies about a vector.
export function hexdump(hex, segments, { title, perRow = 16 } = {}) {
  const bytes = hex.match(/../g) || [];
  let at = 0;
  const marks = [];
  for (const s of segments) {
    const len = s.len === "rest" ? bytes.length - at : s.len;
    marks.push({ ...s, from: at, to: at + len });
    at += len;
  }
  if (at !== bytes.length) throw new Error(`hexdump ${title}: segments cover ${at} of ${bytes.length} bytes`);
  const segOf = (i) => marks.find((m) => i >= m.from && i < m.to);
  let rows = "";
  for (let r = 0; r < bytes.length; r += perRow) {
    let cells = "";
    for (let i = r; i < Math.min(r + perRow, bytes.length); i++) {
      const m = segOf(i);
      const first = i === m.from ? " first" : "";
      cells += `<span class="hb k-${m.kind}${first}" data-f="${esc(m.label)} · byte ${i - m.from + 1} of ${m.to - m.from}">${bytes[i]}</span>`;
    }
    rows += `<div class="hx-row"><span class="hx-off">${r.toString(16).padStart(4, "0")}</span><span class="hx-bytes">${cells}</span></div>`;
  }
  const legend = marks
    .map((m) => `<span class="hx-leg k-${m.kind}"><i></i>${esc(m.label)} <b>${m.to - m.from}</b></span>`)
    .join("");
  return `<figure class="hexdump">
  ${title ? `<figcaption><span class="layout-title">${title}</span><span class="layout-total">${bytes.length} bytes</span></figcaption>` : ""}
  <div class="hx">${rows}</div>
  <p class="hx-readout" aria-live="polite"></p>
  <div class="hx-legend">${legend}</div>
</figure>`;
}

// ------------------------------------------------------------- sequence

// Every svg gets its own marker ids: a hidden variant must never own the
// markers a visible one points at.
let uid = 0;

// Rough text width for the label font (mono, ~0.6 em per character).
const textW = (str, px) => String(str).length * px * 0.7;

// A message sequence between lanes (players, server). Drawn twice: a wide
// picture for screens with room, and a narrow one at phone scale, so labels
// stay readable without zooming.
//   lanes: [{ id, label, tone: "white" | "black" | "server" }]
//   rows:  [{ arrows: [{ from, to, label, tone, dashed, cut }], note: { at, text, tone, span } , gap }]
// tone: "ok" | "bad" | "warn" | "muted" | undefined
export function sequence(lanes, rows, { width = 720, title } = {}) {
  const wide = drawSequence(lanes, rows, { width, pad: 70, head: 104, label: 12.5, note: 12.5 });
  const narrow = drawSequence(lanes, rows, { width: 360, pad: 48, head: 84, label: 11, note: 11.5 });
  const aria = esc(title || "sequence diagram");
  return `<figure class="diagram">${title ? `<figcaption>${title}</figcaption>` : ""}<svg class="v-wide" viewBox="${wide.box}" role="img" aria-label="${aria}">${wide.svg}</svg><svg class="v-narrow" viewBox="${narrow.box}" role="img" aria-label="${aria}">${narrow.svg}</svg></figure>`;
}

function drawSequence(lanes, rows, { width, pad, head, label, note }) {
  const id = `sq${++uid}`;
  const step = (width - 2 * pad) / Math.max(1, lanes.length - 1);
  const x = Object.fromEntries(lanes.map((l, i) => [l.id, pad + i * step]));
  const clamp = (cx, w) => Math.min(Math.max(cx, w / 2 + 4), width - w / 2 - 4);
  let y = 74;
  let body = "";
  for (const row of rows) {
    const arrows = row.arrows || [];
    // Two messages that cross (sent at the same moment between the same two
    // lanes, in opposite directions) are drawn as an X: each slopes down
    // from its sender, labelled where it leaves.
    const crossing =
      arrows.length === 2 && arrows[0].from === arrows[1].to && arrows[0].to === arrows[1].from && !arrows.some((a) => a.cut);
    if (crossing) {
      const drop = 46;
      for (const a of arrows) {
        const x1 = x[a.from];
        const x2 = x[a.to];
        const dir = x2 > x1 ? 1 : -1;
        const tone = a.tone || "plain";
        body += `<line class="sq-line t-${tone}${a.dashed ? " dashed" : ""}" x1="${x1 + dir * 8}" y1="${y + 18}" x2="${x2 - dir * 10}" y2="${y + 18 + drop}" marker-end="url(#${id}-${tone})"/>`;
        const px = Math.min(label, (Math.abs(x2 - x1) / 2 - 6) / Math.max(1, String(a.label || "").length * 0.7));
        body += `<text class="sq-label t-${tone}" style="font-size:${px.toFixed(1)}px" x="${x1 + dir * 6}" y="${y + 8}" text-anchor="${dir > 0 ? "start" : "end"}">${esc(a.label || "")}</text>`;
      }
      y += Math.max(row.gap || 0, drop + 34);
      continue;
    }
    const h = row.gap || 52;
    for (const a of arrows) {
      const x1 = x[a.from];
      const x2 = x[a.to];
      const dir = x2 > x1 ? 1 : -1;
      const tone = a.tone || "plain";
      const end = a.cut ? (x1 + x2) / 2 : x2 - dir * 8;
      body += `<line class="sq-line t-${tone}${a.dashed ? " dashed" : ""}" x1="${x1 + dir * 8}" y1="${y + 14}" x2="${end}" y2="${y + 14}" ${a.cut ? "" : `marker-end="url(#${id}-${tone})"`}/>`;
      if (a.cut) {
        body += `<g class="sq-cut"><line x1="${end - 7}" y1="${y + 7}" x2="${end + 7}" y2="${y + 21}"/><line x1="${end - 7}" y1="${y + 21}" x2="${end + 7}" y2="${y + 7}"/></g>`;
      }
      const lx = (a.cut ? (x1 + end) / 2 : (x1 + x2) / 2) + (width > 500 ? a.dx || 0 : (a.dx || 0) / 2);
      // a label that cannot fit the picture gets a smaller font, never a cut
      const px = Math.min(label, (width - 12) / Math.max(1, String(a.label || "").length * 0.7));
      body += `<text class="sq-label t-${tone}" style="font-size:${px.toFixed(1)}px" x="${clamp(lx, textW(a.label || "", px))}" y="${y + 6}" text-anchor="middle">${esc(a.label || "")}</text>`;
    }
    if (row.note) {
      const n = row.note;
      const cx = n.span ? (x[n.span[0]] + x[n.span[1]]) / 2 : x[n.at];
      const w = Math.min(width - 12, Math.max(n.w && width > 500 ? n.w : 0, 96, n.text.length * note * 0.56 + 26));
      const left = Math.min(Math.max(cx - w / 2, 6), width - 6 - w);
      body += `<g class="sq-note t-${n.tone || "plain"}"><rect x="${left}" y="${y}" width="${w}" height="28" rx="14"/><text style="font-size:${note}px" x="${left + w / 2}" y="${y + 18.5}" text-anchor="middle">${esc(n.text)}</text></g>`;
    }
    y += h;
  }
  const height = y + 10;
  const lifelines = lanes
    .map(
      (l) => `<line class="sq-life" x1="${x[l.id]}" y1="52" x2="${x[l.id]}" y2="${height - 8}"/>
<g class="sq-head l-${l.tone || "server"}"><rect x="${x[l.id] - head / 2}" y="14" width="${head}" height="32" rx="16"/><text x="${x[l.id]}" y="35" text-anchor="middle">${esc(l.label)}</text></g>`,
    )
    .join("");
  const markers = ["plain", "ok", "bad", "warn", "muted"]
    .map(
      (t) => `<marker id="${id}-${t}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="ah t-${t}" d="M0,0 L10,5 L0,10 z"/></marker>`,
    )
    .join("");
  return { box: `0 0 ${width} ${height}`, svg: `<defs>${markers}</defs>${lifelines}${body}` };
}

// ------------------------------------------------------------- small blocks

export const callout = (kind, title, html) =>
  `<aside class="callout c-${kind}"><p class="callout-title">${title}</p>${html}</aside>`;

export const kbdTag = (s) => `<code class="tag">${esc(s)}</code>`;

// An attack card: what the cheater tries, why it fails, what it costs.
export function attack({ id, name, who, tries, caught, outcome, tone = "lose", fig = "" }) {
  const toneLabel = { lose: "caught", void: "refused", none: "no gain", limit: "not stopped" }[tone];
  return `<article class="attack a-${tone}" id="${id}">
  <header><h3>${name}</h3><span class="attack-badge">${toneLabel}</span></header>
  ${who ? `<p class="attack-who">${who}</p>` : ""}
  <div class="attack-cols">
    <div><p class="attack-k">The trick</p><p>${tries}</p></div>
    <div><p class="attack-k">What happens</p><p>${caught}</p></div>
  </div>
  ${fig}
  <p class="attack-out"><span>Outcome</span> ${outcome}</p>
</article>`;
}

// ------------------------------------------------------------- the comb

// One hexagon per byte of a real box. Segments are [{ len, label, kind, chars }]:
// a segment with chars shows its bytes as letters, because those are readable.
export function comb(hex, segments, { perRow = 12, title, more } = {}) {
  const bytes = hex.match(/../g) || [];
  let at = 0;
  const marks = segments.map((s) => {
    const m = { ...s, from: at, to: at + s.len };
    at += s.len;
    return m;
  });
  if (at !== bytes.length) throw new Error(`comb ${title}: segments cover ${at} of ${bytes.length} bytes`);
  const cell = (i) => {
    const m = marks.find((x) => i >= x.from && i < x.to);
    const code = parseInt(bytes[i], 16);
    const shown = m.chars && code > 32 && code < 127 ? esc(String.fromCharCode(code)) : bytes[i];
    return `<span class="cell k-${m.kind}${m.chars ? " letter" : ""}" title="${esc(m.label)}">${shown}</span>`;
  };
  let rows = "";
  for (let r = 0; r < bytes.length; r += perRow) {
    let cells = "";
    for (let i = r; i < Math.min(r + perRow, bytes.length); i++) cells += cell(i);
    rows += `<div class="comb-row">${cells}</div>`;
  }
  const legend = [...new Map(marks.filter((m) => m.legend).map((m) => [m.legend, m])).values()]
    .map((m) => `<span class="comb-key"><i class="cell k-${m.kind}"></i>${esc(m.legend)}</span>`)
    .join("");
  return `<figure class="comb" style="--n:${perRow}">
  ${title ? `<figcaption>${title}</figcaption>` : ""}
  <div class="comb-grid" aria-hidden="true">${rows}</div>
  ${legend ? `<div class="comb-legend">${legend}</div>` : ""}
  ${more ? `<p class="comb-more">${more}</p>` : ""}
</figure>`;
}
