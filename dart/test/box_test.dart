// Boxes sealed by hand, properties, rewrites and the release: the Go tests in
// honeypot_test.go.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:honeypot/honeypot.dart';
import 'package:test/test.dart';

import 'helpers.dart';

/// A ledger whose database is down.
class DownLedger implements Ledger {
  @override
  String claim(Uint8List id, int revision, String owner) => throw StateError('db down');

  @override
  int advance(Uint8List id, int revision) => throw StateError('db down');
}

bool contains(List<int> haystack, List<int> needle) {
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    var all = true;
    for (var j = 0; j < needle.length && all; j++) {
      all = haystack[i + j] == needle[j];
    }
    if (all) return true;
  }
  return false;
}

void main() {
  final issuer = issuerOf();
  final keys = issuer.keys;

  test('a main key splits the same way, into independent keys', () {
    expect(() => Issuer(1, Uint8List(31)), fails(HoneypotError.keySize));
    expect(() => Issuer(256, seed(mainTag)), throwsRangeError);
    final again = Issuer(1, seed(mainTag));
    expect(again.publicKey, issuer.publicKey);
    expect(again.openRoot, issuer.openRoot);
    expect(issuer.openRoot, isNot(issuer.signSeed));
    expect(issuer.publicKey.length, publicKeySize);
  });

  test('seal and open', () {
    for (final payload in [<int>[], utf8.encode('sword'), List.filled(chest.size - 2, 7)]) {
      final b = issuer.seal(chest, payload);
      final got = decodeBox(b.encode());
      got.verify(keys);
      // The key comes from the decoded box, as it would on a key server.
      final key = issuer.key(got);
      got.verifyKey(key);
      expect(got.open(keys, key), payload);
      expect(utf8.decode(got.series), chest.series);
      expect(got.meta, chest.meta);
      expect(got.sig.length, sigSize);
    }
  });

  test('seal rejects', () {
    expect(() => issuer.seal(Spec(series: 'x' * 256, size: 8), []), fails(HoneypotError.tooLong));
    expect(() => issuer.seal(Spec(meta: Uint8List(65536), size: 8), []), fails(HoneypotError.tooLong));
    expect(() => issuer.seal(const Spec(size: 6), utf8.encode('sword')), fails(HoneypotError.size));
    expect(() => issuer.seal(const Spec(size: maxSize + 1), []), fails(HoneypotError.size));
    expect(() => issuer.seal(const Spec(size: 8), [], entropy: Uint8List(31)), throwsArgumentError);
    expect(issuer.seal(const Spec(size: maxSize), []).ciphertext.length, maxSize + 16);
  });

  test('the size of a box does not say what it holds', () {
    final common = issuer.seal(chest, utf8.encode('x'));
    final legendary = issuer.seal(chest, List.filled(chest.size - 2, 0x4c));
    expect(common.encode().length, legendary.encode().length);
  });

  test('nothing public lets a guess of the contents be tested', () {
    final payload = utf8.encode('legendary sword');
    final raw = sealAt(issuer, 'a', chest, payload).encode();
    expect(contains(raw, payload) || contains(raw, sha256(payload)), isFalse);
    // Same payload, different box: two boxes cannot be compared either.
    final a = sealAt(issuer, 'a', chest, payload), b = sealAt(issuer, 'b', chest, payload);
    expect(a.nonce, isNot(b.nonce));
    expect(a.keyCommit, isNot(b.keyCommit));
    expect(a.ciphertext, isNot(b.ciphertext));
  });

  test('a broken RNG never reuses a key', () {
    final a = sealAt(issuer, 'stuck', chest, utf8.encode('sword'));
    final b = sealAt(issuer, 'stuck', chest, utf8.encode('shield'));
    expect(a.id, isNot(b.id));
    expect(issuer.key(a), isNot(issuer.key(b)));
    expect(sealAt(issuer, 'stuck', chest, utf8.encode('sword')).encode(), a.encode());
  });

  test('a key opens one box', () {
    final a = sealAt(issuer, 'a', chest, utf8.encode('sword'));
    final b = sealAt(issuer, 'b', chest, utf8.encode('sword'));
    expect(() => b.verifyKey(issuer.key(a)), fails(HoneypotError.wrongKey));
    expect(() => b.open(keys, issuer.key(a)), fails(HoneypotError.wrongKey));
    expect(() => a.open(keys, issuer.key(a).sublist(0, 31)), fails(HoneypotError.keySize));
    // A key of the other issuer, or one for an altered header, is a different key.
    expect(() => a.verifyKey(issuerOf(1, otherTag).key(a)), fails(HoneypotError.wrongKey));
    final moved = a.copyWith(series: utf8.encode('acme/season-1/bronze'));
    expect(() => a.verifyKey(issuer.key(moved)), fails(HoneypotError.wrongKey));
  });

  test('verify', () {
    final b = sealAt(issuer, 'a', assigned('alice'), utf8.encode('sword'));
    b.verify(keys);
    expect(() => b.verify({2: issuer.publicKey}), fails(HoneypotError.unknownKey));
    expect(() => b.verify({1: issuerOf(1, otherTag).publicKey}), fails(HoneypotError.signature));
    expect(() => b.verify({1: Uint8List(31)}), fails(HoneypotError.signature));
    expect(() => b.copyWith(sig: b.sig.sublist(0, sigSize - 1)).verify(keys), fails(HoneypotError.signature));
    // Every single byte of a box is covered: flip each one.
    final raw = b.encode();
    for (var i = 0; i < raw.length; i++) {
      caught(() => decodeBox(flip(raw, i)).verify(keys), 'flipped byte $i');
    }
    expect(() => b.open({}, issuer.key(b)), fails(HoneypotError.unknownKey));
  });

  test('decoding rejects', () {
    final raw = sealAt(issuer, 'a', assigned('alice'), utf8.encode('sword')).encode();
    expect(() => decodeBox([]), fails(HoneypotError.short));
    expect(() => decodeBox([...ascii.encode('HPBOX999'), ...raw.sublist(8)]), fails(HoneypotError.tag));
    expect(() => decodeBox([...raw, 0]), fails(HoneypotError.trailing));
    for (var n = 0; n < raw.length; n++) {
      expect(() => decodeBox(raw.sublist(0, n)), throwsA(isA<HoneypotError>()), reason: 'truncated to $n bytes');
    }
  });

  test('opening rejects a dishonest issuer', () {
    const spec = Spec(series: 'x', size: 8);
    final b = sealAt(issuer, 'a', spec, utf8.encode('sword'));
    final key = issuer.key(b);
    final broken = b.copyWith(ciphertext: flip(b.ciphertext, 0));
    expect(() => broken.copyWith(sig: issuer.signBox(broken)).open(keys, key), fails(HoneypotError.ciphertext));
    for (final MapEntry(key: name, value: plain) in {
      'too short': [0],
      'length past end': [0, 9, 1, 2],
      'bytes in padding': [0, 1, 0x78, 0, 1],
    }.entries) {
      expect(() => reseal(issuer, b, plain).open(keys, key), fails(HoneypotError.padding), reason: name);
    }
  });

  test('properties are on the box, and only the main key changes them', () {
    final props = {propUser: 'alice', 'level': '3', 'é': '✓', 'empty': ''};
    final raw = sealAt(issuer, 'a', withProps(props), utf8.encode('sword')).encode();
    final got = decodeBox(raw);
    got.verify(keys);
    expect(got.props, props);
    expect(got.encode(), raw);
    expect(contains(raw, utf8.encode('alice')), isTrue);
    expect(() => got.copyWith(props: {...props, propUser: 'mallory'}).verify(keys), fails(HoneypotError.signature));
    expect(() => got.copyWith(revision: 7).verify(keys), fails(HoneypotError.signature));
    expect(() => got.copyWith(props: {}).verify(keys), fails(HoneypotError.signature));
    // A leading byte order mark is part of the text.
    final bom = sealAt(issuer, 'a', withProps({'﻿name': '﻿value'}), []);
    expect(decodeBox(bom.encode()).encode(), bom.encode());
  });

  test('properties that break the rules', () async {
    final many = {for (var i = 0; i < 256; i++) String.fromCharCode(0x100 + i): ''};
    for (final MapEntry(key: name, value: props) in {
      'too many': many,
      'empty name': {'': 'x'},
      'long name': {'n' * 256: 'x'},
      'long value': {'n': 'v' * 65536},
      'lone surrogate in a name': {'\uD800': 'x'},
      'lone surrogate in a value': {'n': '\uDC00'},
    }.entries) {
      expect(() => issuer.seal(withProps(props), []), fails(HoneypotError.property), reason: name);
      final ledger = MemLedger();
      await expectLater(issuer.rewrite(ledger, sealAt(issuer, 'a', chest, []), props), fails(HoneypotError.property), reason: name);
      expect(ledger.length, 0, reason: 'a refused rewrite took a revision');
    }
  });

  test('decoding rejects properties', () {
    final b = sealAt(issuer, 'a', chest, []);
    for (final MapEntry(key: name, value: props) in {
      'out of order': [2, 1, 0x62, 0, 0, 1, 0x61, 0, 0],
      'duplicate': [2, 1, 0x61, 0, 0, 1, 0x61, 0, 0],
      'empty name': [1, 0, 0, 0],
      'binary name': [1, 1, 0xff, 0, 0],
      'binary value': [1, 1, 0x61, 0, 1, 0xff],
    }.entries) {
      final raw = [...b.sealed, 0, 0, 0, 0, ...props, ...b.sig];
      expect(() => decodeBox(raw), fails(HoneypotError.property), reason: name);
    }
  });

  test('rewrite', () async {
    final ledger = MemLedger();
    final old = sealAt(issuer, 'a', assigned('alice'), utf8.encode('sword'));
    final key = issuer.key(old);
    final oldRaw = old.encode();

    final moved = await issuer.rewrite(ledger, old, {propUser: 'bob'});
    final got = decodeBox(moved.encode());
    got.verify(keys);
    expect(got.revision, 1);
    expect(got.props[propUser], 'bob');
    expect(old.encode(), oldRaw, reason: 'a rewrite must not touch the box it started from');

    // The contents and the key are untouched.
    expect(got.id, old.id);
    expect(issuer.key(got), key);
    expect(utf8.decode(got.open(keys, key)), 'sword');
    expect(got.supersedes(old), isTrue);
    expect(old.supersedes(got), isFalse);
    expect(got.supersedes(got), isFalse);
    expect(got.supersedes(sealAt(issuer, 'b', chest, utf8.encode('sword'))), isFalse);
    // A rewrite cannot swap the contents and keep the id.
    final swapped = got.copyWith(ciphertext: flip(got.ciphertext, 0));
    expect(swapped.supersedes(old), isFalse);
    expect(swapped.id, isNot(old.id));

    // The old revision still verifies: a signature cannot expire.
    old.verify(keys);

    // Rewriting from an old base takes the next revision and never hands one out twice.
    final again = await issuer.rewrite(ledger, old, {propUser: 'carol'});
    expect(again.revision, 2);
    // A base from above the ledger, as after restoring a backup, still moves up.
    final ahead = again.copyWith(revision: 9);
    final next = await issuer.rewrite(ledger, ahead.copyWith(sig: issuer.signBox(ahead)), {});
    expect(next.revision, 10);

    // Only the main key can rewrite.
    await expectLater(issuerOf(1, otherTag).rewrite(ledger, old, {}), fails(HoneypotError.signature));
    await expectLater(issuerOf(2).rewrite(ledger, old, {}), fails(HoneypotError.unknownKey));
    await expectLater(issuer.rewrite(DownLedger(), old, {}), throwsStateError);
  });

  test('rewrites at once hand out each revision once', () async {
    final ledger = MemLedger();
    final b = sealAt(issuer, 'a', chest, utf8.encode('sword'));
    final revisions = await Future.wait([for (var i = 0; i < 8; i++) issuer.rewrite(ledger, b, {})]);
    expect(revisions.map((r) => r.revision).toSet().length, 8);
  });

  test('release', () async {
    final ledger = MemLedger();
    final b = sealAt(issuer, 'a', chest, utf8.encode('sword'));
    final key = await issuer.release(ledger, b, 'alice');
    expect(utf8.decode(b.open(keys, key)), 'sword');
    // A retry gets the same key, and nothing was stored but the claim.
    expect(await issuer.release(ledger, b, 'alice'), key);
    await expectLater(issuer.release(ledger, b, 'bob'), fails(HoneypotError.claimed));

    // Another signature on the same box is the same row in the ledger.
    expect(b.copyWith(sig: Uint8List(sigSize)).id, b.id);

    // Only verified boxes reach the ledger.
    final forged = sealAt(issuerOf(1, otherTag), 'a', chest, utf8.encode('sword'));
    final fresh = MemLedger();
    await expectLater(issuer.release(fresh, forged, 'bob'), fails(HoneypotError.signature));
    expect(fresh.length, 0, reason: 'a forged box took a row');
    await expectLater(issuer.release(ledger, sealAt(issuerOf(2), 'a', chest, []), 'bob'), fails(HoneypotError.unknownKey));
    await expectLater(issuer.release(DownLedger(), sealAt(issuer, 'b', chest, []), 'bob'), throwsStateError);
  });

  test('a transfer really moves the box', () async {
    final ledger = MemLedger();
    final old = sealAt(issuer, 'a', assigned('alice'), utf8.encode('sword'));
    await expectLater(issuer.release(ledger, old, 'bob'), fails(HoneypotError.notOwner));
    expect(ledger.length, 0, reason: 'a refused claim took a row');

    final moved = await issuer.rewrite(ledger, old, {propUser: 'bob'});
    await expectLater(issuer.release(ledger, old, 'alice'), fails(HoneypotError.stale));
    await expectLater(issuer.release(ledger, moved, 'alice'), fails(HoneypotError.notOwner));
    final key = await issuer.release(ledger, moved, 'bob');
    expect(utf8.decode(moved.open(keys, key)), 'sword');

    // The claim is final: a later rewrite does not open the box a second time.
    final back = await issuer.rewrite(ledger, moved, {propUser: 'alice'});
    await expectLater(issuer.release(ledger, back, 'alice'), fails(HoneypotError.claimed));
    await expectLater(issuer.release(ledger, moved, 'bob'), fails(HoneypotError.stale));
  });

  test('claims at once have one winner', () async {
    final ledger = MemLedger();
    final b = sealAt(issuer, 'a', chest, utf8.encode('sword'));
    Future<String?> claim(String owner) async {
      try {
        await issuer.release(ledger, b, owner);
        return owner;
      } on HoneypotError {
        return null;
      }
    }

    final won = await Future.wait([for (final owner in 'abcdefgh'.split('')) claim(owner)]);
    expect(won.whereType<String>().length, 1);
  });

  test('the fields of a box add up to the box', () async {
    final hand = sealAt(issuer, 'a', assigned('alice'), utf8.encode('sword'));
    final (_, _, drawn) = await fairDraw(issuer, gold(), {propUser: 'alice'});
    for (final b in [hand, drawn]) {
      expect(b.fields.fold<int>(0, (n, f) => n + f.$2), b.encode().length);
    }
  });

  test('the errors say what the Go library says', () {
    final go = {
      for (final f in Directory('../go').listSync().whereType<File>().where((f) => f.path.endsWith('.go') && !f.path.endsWith('_test.go')))
        for (final m in RegExp(r'errors\.New\("honeypot: ([^"]+)"\)').allMatches(f.readAsStringSync())) m[1]!,
    };
    expect({for (final e in HoneypotError.values) e.message}, go);
    // And the JavaScript library, by name.
    final js = File('../site/assets/honeypot.js').readAsStringSync();
    final table = js.substring(js.indexOf('export const E = {'), js.indexOf('};', js.indexOf('export const E = {')));
    expect({for (final e in HoneypotError.values) e.code: e.message}, {for (final m in RegExp(r'(\w+): "([^"]+)"').allMatches(table)) m[1]!: m[2]!});
    expect(HoneypotError.signature.toString(), 'honeypot: bad signature');
  });

  test('bytes', () {
    expect(toHex(fromHex('00ff')), '00ff');
    expect(() => fromHex('0'), throwsFormatException);
    expect(() => fromHex('zz'), throwsFormatException);
    expect(randomBytes(32), hasLength(32));
  });
}
