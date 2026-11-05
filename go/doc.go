// Package honeypot is the Go reference implementation of the Honeypot protocol
// (spec/HONEYPOT.md): the main key, sealing boxes, blueprints with exact odds and
// the draw that picks from them, verifying a box against the issuer's public key
// or an open key, public properties only the issuer can rewrite, deriving open
// keys lazily, opening, and the one-time release. It is
// post-quantum safe: boxes are signed with ML-DSA-65 and everything else is
// symmetric.
//
// Everything here is byte-for-byte pinned by the vectors in ../vectors; any
// other implementation must reproduce them.
package honeypot
