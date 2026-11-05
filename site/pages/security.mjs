export default {
  title: "What it proves",
  lead: "What a box can and cannot prove, why it holds up against quantum computers, and what it leaves to you.",
  body: ({ callout }) => `
<h2>What a box can prove</h2>
<table>
<tr><th></th><th>Box alone</th><th>Box and open key</th></tr>
<tr><td>The issuer sealed it, and it is unchanged</td><td>yes</td><td>yes</td></tr>
<tr><td>The contents were fixed when it was sealed</td><td>yes</td><td>yes</td></tr>
<tr><td>Its properties, and that the issuer stated them</td><td>yes</td><td>yes</td></tr>
<tr><td>What the contents are</td><td>no</td><td>yes</td></tr>
<tr><td>Whether a guess is right</td><td>no</td><td>yes</td></tr>
<tr><td>This key belongs to this box and opens no other</td><td></td><td>yes</td></tr>
<tr><td>The item follows from the published odds</td><td>no</td><td>yes, for a drawn box</td></tr>
<tr><td>The issuer did not choose the item</td><td>no</td><td>yes, for the player who took part</td></tr>
<tr><td>These properties are still the latest</td><td>no</td><td>no: the ledger does that</td></tr>
<tr><td>The box was opened only once</td><td>no</td><td>no: the ledger does that</td></tr>
<tr><td>When it was sealed</td><td>no</td><td>no: signatures say what, never when</td></tr>
</table>

<h2>Post-quantum</h2>
<p>A large quantum computer breaks elliptic curves and RSA, and speeds up key search. Honeypot uses nothing it breaks.</p>
<table>
<tr><th>Used for</th><th>Primitive</th><th>Against a quantum computer</th></tr>
<tr><td>Signatures</td><td>ML-DSA-65 (FIPS 204)</td><td>Built for it, NIST category 3</td></tr>
<tr><td>Key derivation, the draw</td><td>HMAC-SHA-256 with 256-bit keys</td><td>Grover leaves about 2^128 work</td></tr>
<tr><td>Contents</td><td>AES-256-GCM</td><td>Grover leaves about 2^128 work</td></tr>
<tr><td>Box id, commitments</td><td>SHA-256</td><td>Collisions rate category 2, and only a cheating issuer gains from one</td></tr>
</table>
<p><strong>Contents cannot be harvested.</strong> A box uses no public-key encryption. Someone who records a box today learns nothing about its contents when quantum computers arrive, even with the issuer's public key.</p>
${callout("warn", "The rest of the path matters too", `<p>Deliver open keys over TLS with a post-quantum key exchange (X25519MLKEM768, the default in Go since 1.24). Otherwise someone recording the traffic can recover released keys later.</p>`)}

<h2>What it leaves to you</h2>
<ul>
<li><strong>Keep the main key safe.</strong> Whoever has it can read every box under it, forge new ones and rewrite any property. Nothing in the protocol can stop that. Keep it in a KMS and rotate it per series.</li>
<li><strong>Keep the ledger.</strong> Losing it makes old revisions and spent boxes valid again.</li>
<li><strong>Publish the blueprint ids in use.</strong> Otherwise some players could be given worse odds without anyone noticing.</li>
<li><strong>Use tickets when a player is online.</strong> <code>Mint</code> means trusting the issuer.</li>
<li><strong>Never publish live counts of capped items.</strong> They reveal what is in a box.</li>
</ul>

<h2>Audit after a series</h2>
<p>Publishing the <code>open_root</code> of a retired key lets anyone derive every open key and read every box, while the signing key stays secret, so nobody can forge one. Each derived key is checked against its commitment, so a false root is caught at once. Only do this when no unopened box under that key still matters.</p>

<h2>Not designed yet</h2>
<p>A <strong>series manifest</strong>: a signed Merkle root over all boxes of a series, fixed before the first sale, with public randomness mixed in afterwards. It would prove a whole batch to everyone rather than one draw to one player, including that a cap was really reached, and would cover draws with no player present.</p>
`,
};
