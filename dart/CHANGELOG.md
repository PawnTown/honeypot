# Changelog

## 0.1.0 (unreleased)

First Dart implementation of the Honeypot protocol.

- Blueprints, the roll and the pick, draw requests, boxes and tickets: encoding,
  decoding, verifying against the issuer's key or an open key, opening, and
  `openItem`, which recomputes the item from the key and the input.
- The issuer: the main key split, sealing, tickets, redeeming, `mint`, rewrites,
  open keys and the one-time release, with a ledger and caps in memory.
- Pure Dart, for Flutter and the VM: ML-DSA-65 from `pqcrypto`, AES-256-GCM from
  `pointycastle`.
- Passes the conformance vectors byte for byte, signatures included, with 100 %
  test coverage.
