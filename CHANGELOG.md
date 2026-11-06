# Changelog

## Unreleased

First draft of the Honeypot protocol.

- Specification (`spec/HONEYPOT.md`).
- Go implementation: the main key, sealing, verifying a box against the public
  key or an open key, public properties only the issuer can rewrite, lazy open
  keys, opening, and the one-time release.
- Blueprints with exact whole-number odds, and an unbiased draw: `Mint` in one call,
  or a ticket exchange that keeps the issuer from choosing the item.
- Optional caps per item, with serials as proof of the cap. A blueprint with no caps
  stays stateless.
- Post-quantum safe: ML-DSA-65 signatures, everything else symmetric.
- Dart implementation (`dart/`), for Flutter and the VM: the player's checks and the
  issuer, pure Dart, the vectors byte for byte.
- Conformance vectors (`vectors/`) and 100 % test coverage.
- Docs site and a live demo running the real protocol in the browser (`site/`), tested
  against the vectors.
