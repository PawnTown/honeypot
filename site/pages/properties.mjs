export default {
  title: "Properties",
  lead: "Public facts on the box, such as who owns it. Anyone can read them with no key and no server. Only the main key can change them.",
  body: ({ layout, callout, esc }) => `
<h2>What they are</h2>
${layout(
  "Properties",
  [
    { name: "count", size: 1, kind: "int" },
    { name: "name", size: "1 + name", kind: "text" },
    { name: "value", size: "2 + value", kind: "text" },
  ],
  { caption: "Name and value repeat per entry, sorted by name, so there is one byte form." },
)}
<p>Values are text, so any tool can show them. The protocol knows one name, <strong><code>userId</code></strong>: a box that has it goes to that user only. A box without it goes to whoever claims it first. All other names are up to you.</p>
<table>
<tr><th></th><th>series, meta</th><th>properties</th></tr>
<tr><td>Readable by anyone</td><td>yes</td><td>yes</td></tr>
<tr><td>Signed by the issuer</td><td>yes</td><td>yes</td></tr>
<tr><td>Can change</td><td>never: another value is another box with another key</td><td>with the main key: next revision, new signature</td></tr>
</table>
${callout("warn", "They are public for good", `<p>Anyone who keeps a copy keeps them. Use an opaque <code>userId</code>, not an e-mail address, and put nothing in them that says what the box holds.</p>`)}

<h2>Rewriting</h2>
<pre><code>next, err := issuer.Rewrite(ledger, box, map[string]string{honeypot.PropUser: "bob"})</code></pre>
<p>A rewrite replaces all properties and signs again at the next revision. The sealed part does not change, so the box keeps its <code>box_id</code>, its open key and its contents. It cannot change what is inside, because other contents would be another <code>box_id</code>. A holder who keeps those 32 bytes can tell, through any number of rewrites.</p>
<p>A rewrite does not take back an open key that was already released, and a claim is final: rewriting a box later does not open it a second time.</p>

<h2>Old revisions</h2>
<p><strong>A signature cannot expire.</strong> After a rewrite, the old revision still verifies forever, and anyone may have kept a copy. <code>Verify</code> proves "the issuer stated this at revision N". It cannot prove that N is the latest, and no check on the box alone can.</p>
<table>
<tr><th>Who is checking</th><th>How they get the latest</th></tr>
<tr><td>The issuer releasing a key</td><td>The ledger refuses a revision below the one on record. Built into <code>Release</code>.</td></tr>
<tr><td>Anyone holding two copies</td><td>The higher revision of the same <code>box_id</code> wins (<code>Supersedes</code>).</td></tr>
<tr><td>A service acting on a property, such as a trade</td><td>Asks the issuer or the ledger for the current revision.</td></tr>
<tr><td>An offline device</td><td>A profile can add an <code>expires</code> property and re-sign regularly. That limits the window and does not close it.</td></tr>
</table>
<p>Treat a property read from a box alone as "true at some point". Two signed copies at one revision with different properties are portable proof that the issuer cheated.</p>

<h2>What it stores</h2>
<pre><code>${esc(`-- Advance(box_id, revision): the next revision.
INSERT INTO honeypot_boxes (box_id, revision) VALUES ($1, $2 + 1)
ON CONFLICT (box_id) DO UPDATE
  SET revision = GREATEST(honeypot_boxes.revision, $2) + 1
RETURNING revision;

-- Claim(box_id, revision, owner): the owner on record.
-- No row back: a newer revision exists, the box is stale.
INSERT INTO honeypot_boxes (box_id, revision, owner) VALUES ($1, $2, $3)
ON CONFLICT (box_id) DO UPDATE
  SET owner = COALESCE(honeypot_boxes.owner, $3)
  WHERE honeypot_boxes.revision <= $2
RETURNING owner;`)}</code></pre>
<p>A box that was neither rewritten nor opened costs nothing. Losing this table makes old revisions and spent boxes valid again, so back it up like the data it is.</p>
`,
};
