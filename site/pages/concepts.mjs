export default {
  title: "How it works",
  lead: "One secret, a box anyone can check and nobody can read, and a key that exists only when someone asks for it.",
  body: ({ layout, sequence, callout, href }) => `
<h2>One secret</h2>
<p>The issuer keeps a <strong>main key</strong>: 32 random bytes. One function, HMAC-SHA-256 over a tag and the data, splits it in two.</p>
<pre><code>sign_seed = KDF(main, "HPSIGN01")    signs boxes (ML-DSA-65)
open_root = KDF(main, "HPROOT01")    derives open keys</code></pre>
<p>Players and games pin the public key under a one-byte <code>key_id</code>, so a main key can be rotated. Use one per season or series: whoever has it can read and forge every box under it.</p>

<h2>Sealing a box</h2>
${layout(
  "A box",
  [
    { name: "header", size: "var", kind: "text", note: "tag, key id, series, meta, draw, nonce" },
    { name: "key_commit", size: 32, kind: "hash", note: "pins the one key" },
    { name: "contents", size: "var", kind: "seal", note: "encrypted" },
    { name: "revision", size: 4, kind: "int" },
    { name: "properties", size: "var", kind: "text", note: "owner and more" },
    { name: "signature", size: 3309, kind: "sig", note: "over all of it" },
  ],
  { total: "about 3.5 KB" },
)}
<pre><code>key_input  = SHA-256(header)
open_key   = KDF(open_root, "HPKEY001", key_input)
key_commit = KDF(open_key, "HPCOMT01")
contents   = AES-256-GCM(KDF(open_key, "HPENC001"), plaintext)
box_id     = SHA-256(header | key_commit | contents)</code></pre>
<ul>
<li><strong>The key comes from the header, not the whole box.</strong> The contents need the key, so the key cannot depend on them.</li>
<li><strong><code>key_commit</code> is what fixes the contents.</strong> AES-GCM alone does not commit to its key: whoever picks the keys could make one ciphertext decrypt to two different things. The signed commitment admits one key.</li>
<li><strong>Every box of a kind is the same size,</strong> padded to fit the longest item. Otherwise the size of a box would give away a rare item with a longer name.</li>
</ul>

<h2>Two checks</h2>
<p>Neither says what is inside.</p>
<table>
<tr><th>Check</th><th>Against</th><th>Tells you</th></tr>
<tr><td><code>box.Verify(keys)</code></td><td>the issuer's public key</td><td>the issuer made this and nothing changed since</td></tr>
<tr><td><code>box.VerifyKey(key)</code></td><td>the box's <code>key_commit</code></td><td>this is the one key for this box</td></tr>
</table>
<p>They chain: the public key vouches for the box, and the box vouches for the key. An open key needs no signature of its own.</p>

<h2>Why a guess cannot be tested</h2>
<p>Box contents come from small sets. If a box published <code>SHA-256(payload)</code>, anyone could hash <code>"sword"</code>, <code>"shield"</code> and every other item until one matched. So no public field can be computed from the item without a secret. Testing a guess needs the 256-bit open key. Two boxes with the same item share nothing, so they cannot be compared either.</p>

<h2>Opening</h2>
${sequence(
  [
    { id: "p", label: "Player", tone: "white" },
    { id: "i", label: "Issuer", tone: "server" },
  ],
  [
    { note: { at: "p", text: "holds the verified box, pays" } },
    { arrows: [{ from: "p", to: "i", label: "the box, the owner", tone: "plain" }] },
    { note: { at: "i", text: "signature, owner, claim, then key" } },
    { arrows: [{ from: "i", to: "p", label: "open_key", tone: "ok" }] },
    { note: { at: "p", text: "checks the key, decrypts" } },
  ],
  { title: "The order matters: the box before the payment, the claim before the key." },
)}
<p>A retry is safe. The same owner asking again gets the same key, because it is derived and not used up, so a lost response costs nothing.</p>

<h2>What "one time" means</h2>
<p>A key opens one box. That much is mathematics. A key cannot be made to work only once: nothing stops someone who has a box and its key from decrypting again or passing the key on, and no check without state can tell a first use from a replay.</p>
<p>So "one time" is a rule about the <strong>claim</strong>. It takes one row per opened box, and <code>Release</code> is that rule in code. A leaked key shows the contents but grants nothing, because the grant goes through the ledger.</p>
${callout("rule", "The rule for servers", `<p>Never expose <code>Key</code> directly. It answers for any box. Go through <code>Release</code>, which checks the signature, the owner and the claim first.</p>`)}
<p>Next: <a href="${href("draw")}">how the item gets chosen</a>.</p>
`,
};
