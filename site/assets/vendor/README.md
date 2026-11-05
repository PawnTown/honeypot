# Vendored

`noble.js` bundles `ml_dsa65` from `@noble/post-quantum` 0.7.1, and `hmac` and
`sha256` from `@noble/hashes` 2.4.0, by Paul Miller (MIT, see `LICENSE`). It is what
lets the demo sign real boxes in a browser, which has no ML-DSA of its own.

To rebuild it, install both packages and run esbuild on a file that re-exports them:

```js
export { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
export { hmac } from "@noble/hashes/hmac.js";
export { sha256 } from "@noble/hashes/sha2.js";
```

```bash
esbuild entry.mjs --bundle --format=esm --minify --target=es2022 --legal-comments=none --outfile=noble.js
```
