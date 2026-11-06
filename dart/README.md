# honeypot (Dart)

Dart implementation of the Honeypot protocol (`../spec/HONEYPOT.md`), byte-for-byte
pinned to the Go library by the vectors in `../vectors`. Pure Dart: it runs in
Flutter apps and on the Dart VM. It has both sides: the player's checks, and the
issuer with its main key, with a ledger and caps in memory for tests.

| For | Package |
|---|---|
| ML-DSA-65 (FIPS 204) | [`pqcrypto`](https://pub.dev/packages/pqcrypto), pure Dart. Its deterministic signatures match the vectors byte for byte |
| AES-256-GCM | [`pointycastle`](https://pub.dev/packages/pointycastle) |
| HMAC-SHA-256, SHA-256 | [`crypto`](https://pub.dev/packages/crypto) |

```bash
dart pub get
dart test
tool/coverage.sh     # fails below 100 % lines, branches, functions
```

In a Flutter app, depend on it by git or path:

```yaml
dependencies:
  honeypot:
    git:
      url: https://github.com/PawnTown/honeypot
      path: dart
```

```dart
final issuer = Issuer(1, mainKey);
final blueprint = newBlueprint('acme/season-1/gold', null, const [
  Item('wooden sword', 900),
  Item('silver shield', 99),
  Item('legendary sword', 1, 10), // a cap: at most 10
]);
final keys = {1: issuer.publicKey};

// A draw the issuer cannot steer: each side commits before seeing the other's part.
final request = newDrawRequest();                                                  // player
final ticket = await issuer.ticket(blueprint, request.commit, caps: caps);           // issuer
ticket.verify(keys, blueprint, request.commit);                                    // player
final box = await issuer.redeem(ticket, blueprint, request.input, caps: caps);      // issuer
box.verifyTicket(keys, ticket);                                                    // player

// Later: the key, once per box, and the item recomputed from it under the odds.
final openKey = await issuer.release(ledger, box, 'alice');
final drawn = box.openItem(keys, blueprint, openKey); // drawn.item, drawn.serial
```

Every check throws a `HoneypotError` with the message of the Go library. There is
one instance of each, so compare with `==`.

How it differs from Go:

- `Ledger` and `Caps` may answer with a `Future`, since a real one is a database.
  So the issuer's methods that use them return futures. The player's checks are
  synchronous.
- Serials are `BigInt`, since they are `u64`.
- A blueprint's series must be UTF-8: a Dart string cannot hold anything else.

## Speed

ML-DSA in pure Dart is fast enough for a player. On an Apple M-series machine:

| | AOT (Flutter release) | JIT (`dart test`) |
|---|---|---|
| decode and verify a box | 1.2 ms | 1.5 ms, 11 ms the first time |
| decode and `openItem` | 1.3 ms | 2.1 ms, 12 ms the first time |
| sign (issuer) | 6.8 ms | |

`test/timing_test.dart` prints the JIT numbers. On a phone, run the checks off
the UI isolate (`Isolate.run`), so an animation never waits for them.
