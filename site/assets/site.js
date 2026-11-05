// Phone drawer, copy buttons on code, scroll hints on wide diagrams and the
// "On this page" highlight.
(() => {
  const body = document.body;
  const toggle = document.querySelector(".nav-toggle");
  const setOpen = (open) => {
    body.classList.toggle("nav-open", open);
    toggle?.setAttribute("aria-expanded", String(open));
    toggle?.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
  };
  toggle?.addEventListener("click", () => setOpen(!body.classList.contains("nav-open")));
  document.querySelector(".drawer")?.addEventListener("click", (e) => {
    if (e.target.closest("[data-close], a")) setOpen(false);
  });
  addEventListener("keydown", (e) => e.key === "Escape" && setOpen(false));
  matchMedia("(min-width: 861px)").addEventListener("change", (m) => m.matches && setOpen(false));

  for (const pre of document.querySelectorAll(".prose pre")) {
    const b = document.createElement("button");
    b.className = "copy";
    b.type = "button";
    b.textContent = "copy";
    b.addEventListener("click", async () => {
      await navigator.clipboard.writeText(pre.querySelector("code")?.innerText ?? pre.innerText);
      b.textContent = "copied";
      setTimeout(() => (b.textContent = "copy"), 1400);
    });
    pre.appendChild(b);
  }

  // A table wider than the screen fades at its right edge until scrolled
  // to the end, with a small hint under it.
  const scrollers = [...document.querySelectorAll(".table-wrap, .diagram .scroll-x")];
  const mark = (el) => {
    const can = el.scrollWidth > el.clientWidth + 8;
    el.classList.toggle("can-scroll", can);
    el.classList.toggle("at-end", can && el.scrollLeft + el.clientWidth >= el.scrollWidth - 2);
    const hint = el.nextElementSibling;
    if (hint?.classList.contains("scroll-hint")) hint.hidden = !can;
  };
  for (const el of scrollers) {
    const hint = document.createElement("span");
    hint.className = "scroll-hint";
    hint.textContent = el.classList.contains("table-wrap") ? "Swipe to see the whole table" : "Swipe to see the whole diagram";
    el.after(hint);
    el.addEventListener("scroll", () => mark(el), { passive: true });
    mark(el);
  }
  addEventListener("resize", () => scrollers.forEach(mark));
  // widths change once the web fonts arrive
  document.fonts?.ready.then(() => scrollers.forEach(mark));

  // Byte dumps: hover or tap a byte to read which field it belongs to.
  for (const dump of document.querySelectorAll(".hexdump")) {
    const out = dump.querySelector(".hx-readout");
    let on = null;
    const show = (hb) => {
      on?.classList.remove("on");
      on = hb;
      hb.classList.add("on");
      out.textContent = `${hb.textContent}  ${hb.dataset.f}`;
    };
    dump.addEventListener("pointerover", (e) => e.target.matches?.(".hb") && show(e.target));
    dump.addEventListener("click", (e) => e.target.matches?.(".hb") && show(e.target));
  }

  // The attack map starts folded on phones, where it is a long list.
  if (matchMedia("(max-width: 860px)").matches) document.querySelectorAll("details.attack-map").forEach((d) => (d.open = false));

  const links = [...document.querySelectorAll(".toc a")];
  if (!links.length) return;
  const byId = new Map(links.map((a) => [a.getAttribute("href").slice(1), a]));
  const seen = new Set();
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) e.isIntersecting ? seen.add(e.target.id) : seen.delete(e.target.id);
      const first = [...byId.keys()].find((id) => seen.has(id));
      if (!first) return;
      links.forEach((a) => a.classList.toggle("on", a === byId.get(first)));
    },
    { rootMargin: "-80px 0px -65% 0px" },
  );
  for (const id of byId.keys()) {
    const h = document.getElementById(id);
    if (h) io.observe(h);
  }
})();
