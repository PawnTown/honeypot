import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:honeypot/honeypot.dart';
import 'package:pointycastle/api.dart' show AEADParameters, KeyParameter;
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:test/test.dart';

// Deterministic keys and entropy, the same as the Go tests and the vectors.
Uint8List seed(String tag) => sha256(utf8.encode(tag));
Uint8List entropyOf(String tag) => seed(tag);

const mainTag = 'honeypot test main';
const otherTag = 'honeypot test other';

final Map<String, Issuer> _issuers = {};
Issuer issuerOf([int keyId = 1, String tag = mainTag]) => _issuers.putIfAbsent('$keyId $tag', () => Issuer(keyId, seed(tag)));

final chest = Spec(series: 'acme/season-1/gold', meta: utf8.encode('{"name":"Gold chest"}'), size: 64);

/// A chest that belongs to a user.
Spec assigned(String user) => Spec(series: chest.series, meta: chest.meta, props: {propUser: user}, size: chest.size);

Spec withProps(Map<String, String> props) => Spec(series: chest.series, meta: chest.meta, props: props, size: chest.size);

/// Seals with fixed entropy.
Box sealAt(Issuer issuer, String tag, Spec spec, List<int> payload) => issuer.seal(spec, payload, entropy: entropyOf(tag));

/// A blueprint with a rare item, and a longer id for the rare one.
Blueprint gold() =>
    newBlueprint(chest.series, chest.meta, const [Item('wooden sword', 900), Item('silver shield', 99), Item('legendary sword of the first dawn', 1)]);

/// Another plaintext in the box, encrypted under its own key and signed, the
/// way a dishonest issuer could.
Box reseal(Issuer issuer, Box b, List<int> plain) {
  final openKey = issuer.key(b);
  final encKey = crypto.Hmac(crypto.sha256, openKey).convert(utf8.encode('HPENC001')).bytes;
  final gcm = GCMBlockCipher(AESEngine())..init(true, AEADParameters(KeyParameter(Uint8List.fromList(encKey)), 128, Uint8List(12), b.keyInput));
  final out = b.copyWith(ciphertext: gcm.process(Uint8List.fromList(plain)));
  return out.copyWith(sig: issuer.signBox(out));
}

Uint8List u64(int v) => Uint8List(8)..buffer.asByteData().setUint64(0, v);

Uint8List flip(List<int> x, int i) => Uint8List.fromList(x)..[i] ^= 1;

Uint8List bytes(List<int> a) => Uint8List.fromList(a);

/// Whether a box or ticket that was tampered with is caught: it does not
/// decode, or does not verify.
void caught(void Function() decodeAndVerify, String what) {
  try {
    decodeAndVerify();
  } on HoneypotError {
    return;
  }
  fail('$what still verifies');
}

/// The whole exchange.
Future<(DrawRequest, Ticket, Box)> fairDraw(Issuer issuer, Blueprint bp, [Map<String, String> props = const {}]) async {
  final req = newDrawRequest();
  final t = await issuer.ticket(bp, req.commit, props: props);
  return (req, t, await issuer.redeem(t, bp, req.input));
}

Matcher fails(HoneypotError e) => throwsA(e);
