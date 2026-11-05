export default {
  title: "Try it",
  nav: "Try it",
  wide: true,
  script: "demo.js",
  lead: "This is the real protocol, running in your browser: real ML-DSA-65 signatures and AES-256-GCM, byte for byte the same as the Go library. A throwaway issuer is created when the page loads and is gone when you close it.",
  description: "Set the odds, draw a real Honeypot box, flip its bytes, open it and try to cheat, in your browser.",
  body: () => `
<noscript><p class="result bad">This demo needs JavaScript. Everything it does runs in your browser.</p></noscript>
<p class="note" id="issuer-note" aria-live="polite">Creating the issuer.</p>

<section class="step" id="odds">
  <h2><span class="step-no" aria-hidden="true">1</span>Set the odds</h2>
  <p class="step-lead">This is the blueprint: what a box can hold and how likely each item is. Weights are whole numbers, so a chance is an exact fraction. A cap is optional and limits how many of an item will ever exist.</p>
  <div class="panel">
    <table class="items">
      <thead><tr><th scope="col">Item</th><th scope="col">Weight</th><th scope="col">Cap</th><th scope="col">Chance</th><th scope="col"><span class="sr-only">Remove</span></th></tr></thead>
      <tbody id="items"></tbody>
    </table>
    <div class="row"><button class="btn quiet" id="add-item" type="button">Add an item</button></div>
    <p class="note" id="bp-note" aria-live="polite"></p>
  </div>
</section>

<section class="step" id="draw">
  <h2><span class="step-no" aria-hidden="true">2</span>Draw a box</h2>
  <p class="step-lead">If you take part, each side commits before seeing the other's part, so the issuer cannot aim for an item. If the issuer draws alone, the odds are still exact, but you are trusting it not to mint until it likes the result.</p>
  <div class="panel">
    <div class="row" style="margin-top:0">
      <div class="seg" role="radiogroup" aria-label="Who draws">
        <label><input type="radio" name="mode" value="ticket" checked><span>You take part</span></label>
        <label><input type="radio" name="mode" value="mint"><span>The issuer draws alone</span></label>
      </div>
      <label class="field">Owner <input id="owner" value="alice" size="10" autocomplete="off" spellcheck="false"></label>
      <button class="btn primary" id="draw-btn" type="button" disabled>Draw a box</button>
    </div>
    <ol class="talk" id="talk" aria-live="polite"></ol>
  </div>
</section>

<section class="step" id="box" hidden>
  <h2><span class="step-no" aria-hidden="true">3</span>Look at the box</h2>
  <p class="step-lead">One cell per byte. Everything is public, and only the dark cells are sealed. Click any cell to flip a bit and see the signature catch it.</p>
  <div class="box-grid">
    <div>
      <div class="demo-comb">
        <div class="comb" id="comb"></div>
        <p class="cell-info" id="cell-info" aria-live="polite">Point at a cell to see what it is.</p>
        <div class="comb-legend" id="comb-legend"></div>
      </div>
    </div>
    <div>
      <dl class="facts" id="facts"></dl>
      <p class="result good" id="genuine" aria-live="polite"></p>
      <div class="row"><button class="btn quiet" id="flip-random" type="button">Flip a random byte</button></div>
      <p class="result" id="flip-result" aria-live="polite" hidden></p>
      <h3>Guess what is inside</h3>
      <div class="row" style="margin-top:0">
        <label class="field">Guess <select id="guess"></select></label>
        <button class="btn quiet" id="guess-btn" type="button">Test this guess</button>
      </div>
      <p class="result" id="guess-result" aria-live="polite" hidden></p>
      <h3>Give it away</h3>
      <div class="row" style="margin-top:0">
        <label class="field">New owner <input id="new-owner" value="bob" size="10" autocomplete="off" spellcheck="false"></label>
        <button class="btn quiet" id="rewrite-btn" type="button">Rewrite the owner</button>
      </div>
      <p class="result" id="rewrite-result" aria-live="polite" hidden></p>
    </div>
  </div>
</section>

<section class="step" id="open" hidden>
  <h2><span class="step-no" aria-hidden="true">4</span>Open it</h2>
  <p class="step-lead">The issuer derives the key only now, from its main key and the box, and records one claim. Then you check everything yourself.</p>
  <div class="panel">
    <div class="row" style="margin-top:0">
      <label class="field">Claim as <input id="who" size="10" autocomplete="off" spellcheck="false"></label>
      <button class="btn primary" id="open-btn" type="button">Claim and open</button>
    </div>
    <p class="result" id="open-result" aria-live="polite" hidden></p>
    <div class="reveal" id="reveal" hidden></div>
  </div>
</section>

<section class="step" id="cheat">
  <h2><span class="step-no" aria-hidden="true">5</span>Try to cheat</h2>
  <p class="step-lead">Each button really tries it, on a fresh box of its own, and shows what the protocol answers.</p>
  <ul class="cheats" id="cheats"></ul>
</section>

<section class="step" id="check">
  <h2><span class="step-no" aria-hidden="true">6</span>Check the odds</h2>
  <p class="step-lead">One box proves little about odds, so draw many. Each draw uses the same pick as a real box, with a fresh key and input. Signing and encryption are skipped so it finishes quickly. Caps count, and an item at its cap sells out for the draws after it.</p>
  <div class="panel">
    <div class="row" style="margin-top:0">
      <label class="field">Boxes
        <select id="odds-n"><option value="1000">1,000</option><option value="10000" selected>10,000</option><option value="100000">100,000</option></select>
      </label>
      <button class="btn primary" id="odds-btn" type="button" disabled>Draw them</button>
      <span class="note" id="odds-progress" style="margin:0" aria-live="polite"></span>
    </div>
    <div id="odds-out"></div>
  </div>
</section>
`,
};
