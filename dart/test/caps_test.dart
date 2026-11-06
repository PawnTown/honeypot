// Caps: the Go tests in caps_test.go.
import 'dart:typed_data';

import 'package:honeypot/honeypot.dart';
import 'package:test/test.dart';

import 'helpers.dart';

/// Mostly the capped item, so it sells out quickly.
Blueprint limited(int cap) => newBlueprint('acme/limited', null, [const Item('plain', 1), Item('rare', 1000000, cap)]);

/// Says an item is gone when asked to take it, but never lists it sold out.
class LiarCaps extends MemCaps {
  @override
  BigInt? take(Uint8List blueprintId, String item, int cap, Uint8List draw) => null;
}

/// A counter whose database is down, for reading what is sold out or for taking
/// a unit.
class DownCaps extends MemCaps {
  bool soldOutDown = false;
  bool takeDown = false;

  @override
  List<String> soldOut(Uint8List blueprintId) => soldOutDown ? throw StateError('db down') : super.soldOut(blueprintId);

  @override
  BigInt? take(Uint8List blueprintId, String item, int cap, Uint8List draw) =>
      takeDown ? throw StateError('db down') : super.take(blueprintId, item, cap, draw);
}

/// A counter on the other side of a network.
class AsyncCaps implements Caps {
  final MemCaps inner = MemCaps();

  @override
  Future<List<String>> soldOut(Uint8List blueprintId) async => inner.soldOut(blueprintId);

  @override
  Future<BigInt?> take(Uint8List blueprintId, String item, int cap, Uint8List draw) async => inner.take(blueprintId, item, cap, draw);
}

void main() {
  final issuer = issuerOf();
  final keys = issuer.keys;

  test('the cap is part of the blueprint', () {
    final a = limited(10), b = limited(11);
    expect(a.id, isNot(b.id));
    expect(decodeBlueprint(a.encode()).items[1].cap, 10);
    expect(a.capped, isTrue);
    expect(gold().capped, isFalse);
  });

  test('no caps needs no state', () async {
    final bp = gold();
    final b = await issuer.mint(bp);
    final drawn = b.openItem(keys, bp, issuer.key(b));
    expect(drawn.serial, BigInt.zero);
    expect(b.draw!.soldOut, isEmpty);
  });

  test('caps are required if the blueprint has caps', () async {
    final bp = limited(1);
    await expectLater(issuer.mint(bp), fails(HoneypotError.noCaps));
    await expectLater(issuer.ticket(bp, Uint8List(32)), fails(HoneypotError.noCaps));
    final req = newDrawRequest();
    final ticket = await issuer.ticket(bp, req.commit, caps: MemCaps());
    await expectLater(issuer.redeem(ticket, bp, req.input), fails(HoneypotError.noCaps));
  });

  test('never more than the cap, with every serial handed out once', () async {
    final caps = AsyncCaps();
    const cap = 5;
    final bp = limited(cap);
    final boxes = await Future.wait([for (var i = 0; i < 40; i++) issuer.mint(bp, caps: caps)]);
    final serials = <BigInt>{};
    for (final b in boxes) {
      final drawn = b.openItem(keys, bp, issuer.key(b));
      if (drawn.item.id != 'rare') continue;
      expect(serials.add(drawn.serial), isTrue, reason: 'serial ${drawn.serial} twice');
      expect(drawn.serial >= BigInt.one && drawn.serial <= BigInt.from(cap), isTrue);
    }
    expect(serials.length, cap);
  });

  test('the ticket fixes what is sold out before the input', () async {
    final caps = MemCaps();
    final bp = limited(1);

    // Two tickets at once, both still with the rare item in reach.
    final first = newDrawRequest(), second = newDrawRequest();
    final t1 = await issuer.ticket(bp, first.commit, caps: caps);
    final t2 = await issuer.ticket(bp, second.commit, caps: caps);
    expect(t1.available(bp), hasLength(2));
    final b1 = await issuer.redeem(t1, bp, first.input, caps: caps);
    final drawn = b1.openItem(keys, bp, issuer.key(b1));
    expect(drawn.item.id, 'rare');
    expect(drawn.serial, BigInt.one);

    // A retry keeps the box and takes no second unit.
    expect((await issuer.redeem(t1, bp, first.input, caps: caps)).encode(), b1.encode());
    expect(caps.taken('rare'), BigInt.one);

    // The second draw lands on it too and may not get something else instead.
    await expectLater(issuer.redeem(t2, bp, second.input, caps: caps), fails(HoneypotError.soldOut));

    // The next ticket says so, signed, before the player gives up an input.
    final third = newDrawRequest();
    final decoded = decodeTicket((await issuer.ticket(bp, third.commit, caps: caps)).encode());
    decoded.verify(keys, bp, third.commit);
    expect(decoded.available(bp).map((it) => it.id), ['plain']);
    final b3 = await issuer.redeem(decoded, bp, third.input, caps: caps);
    b3.verifyTicket(keys, decoded);
    final held = decodeBox(b3.encode());
    final plain = held.openItem(keys, bp, issuer.key(held));
    expect(plain.item.id, 'plain');
    expect(plain.serial, BigInt.one);
  });

  test('capped boxes look alike', () async {
    final caps = MemCaps();
    final bp = limited(1);
    final a = await issuer.mint(bp, caps: caps), b = await issuer.mint(bp, caps: caps);
    expect(a.ciphertext.length, b.ciphertext.length);
  });

  test('sold out everywhere', () async {
    final caps = MemCaps();
    final bp = newBlueprint('acme/run', null, const [Item('a', 1, 1), Item('b', 1, 1)]);
    await issuer.mint(bp, caps: caps);
    await issuer.mint(bp, caps: caps);
    await expectLater(issuer.mint(bp, caps: caps), fails(HoneypotError.soldOut));
    await expectLater(issuer.ticket(bp, Uint8List(32), caps: caps), fails(HoneypotError.soldOut));
  });

  test('a counter that keeps saying no cannot hang mint', () async {
    await expectLater(issuer.mint(limited(1), caps: LiarCaps()), fails(HoneypotError.soldOut));
  });

  test('a counter that is down', () async {
    final bp = limited(1);
    final caps = DownCaps();
    final req = newDrawRequest();
    final ticket = await issuer.ticket(bp, req.commit, caps: caps);
    caps.takeDown = true;
    await expectLater(issuer.mint(bp, caps: caps), throwsStateError);
    await expectLater(issuer.redeem(ticket, bp, req.input, caps: caps), throwsStateError);
    caps.soldOutDown = true;
    await expectLater(issuer.mint(bp, caps: caps), throwsStateError);
    await expectLater(issuer.ticket(bp, req.commit, caps: caps), throwsStateError);
  });

  test('what a dishonest issuer could sign, and what catches it', () async {
    final caps = MemCaps();
    final bp = limited(3);
    Uint8List payload(int serial, String id) => Uint8List.fromList([...u64(serial), ...id.codeUnits]);
    Uint8List padded(List<int> p) => Uint8List(bp.size)
      ..[0] = p.length >> 8
      ..[1] = p.length & 0xff
      ..setAll(2, p);

    final b = await issuer.mint(bp, caps: caps);
    final id = b.openItem(keys, bp, issuer.key(b)).item.id;
    final otherId = id == 'rare' ? 'plain' : 'rare';
    for (final MapEntry(key: name, value: p) in {
      'no serial': [0x78],
      'serial zero': payload(0, id),
      'above the cap': payload(4, id),
      'another item': payload(1, otherId),
    }.entries) {
      expect(() => reseal(issuer, b, padded(p)).openItem(keys, bp, issuer.key(b)), fails(HoneypotError.draw), reason: name);
    }

    // An item with no cap in a capped blueprint needs a serial too.
    Box plainBox;
    do {
      plainBox = await issuer.mint(bp, caps: caps);
    } while (plainBox.openItem(keys, bp, issuer.key(plainBox)).item.id != 'plain');
    expect(() => reseal(issuer, plainBox, padded(payload(0, 'plain'))).openItem(keys, bp, issuer.key(plainBox)), fails(HoneypotError.draw));
    // ...with no limit on it.
    final big = reseal(issuer, plainBox, padded(payload(1 << 40, 'plain')));
    expect(big.openItem(keys, bp, issuer.key(plainBox)).serial, BigInt.from(1 << 40));

    // A blueprint with no caps has no serial.
    final g = gold();
    final (_, _, nocap) = await fairDraw(issuer, g);
    final item = nocap.openItem(keys, g, issuer.key(nocap)).item.id;
    expect(
      () => reseal(issuer, nocap, Uint8List(g.size)..setAll(0, [0, 8 + item.length, ...payload(1, item)])).openItem(keys, g, issuer.key(nocap)),
      fails(HoneypotError.draw),
    );

    // Only an item with a cap can be sold out, and something must be left.
    Future<Ticket> forge(List<int> soldOut) async {
      final t = (await issuer.ticket(bp, newDrawRequest().commit, caps: caps)).copyWith(soldOut: soldOut);
      return t.copyWith(sig: issuer.signTicket(t));
    }

    for (final MapEntry(key: name, value: soldOut) in {
      'item with no cap': [0],
      'out of range': [9],
      'repeated': [1, 1],
      'nothing left': [0, 1],
    }.entries) {
      final t = await forge(soldOut);
      expect(() => t.verify(keys, bp, t.inputCommit), fails(HoneypotError.drawField), reason: name);
    }

    // The list has one byte form.
    expect(() async => decodeTicket((await forge([1, 1])).encode()), fails(HoneypotError.drawField));
  });

  // The rest keep their weights over a smaller total. 13.82 is the 99.9 % point
  // of chi-square with 2 degrees of freedom; the seeds are fixed.
  test('the odds after a sell out are exact', () {
    final bp = newBlueprint('acme/odds', null, const [Item('a', 700), Item('b', 250), Item('gone', 45, 7), Item('c', 50)]);
    final soldOut = [bp.items.indexWhere((it) => it.id == 'gone')];
    const n = 200000;
    final counts = <String, int>{};
    final key = seed('odds key');
    for (var i = 0; i < n; i++) {
      final id = bp.pick(key, entropyOf('in$i'), soldOut).id;
      counts[id] = (counts[id] ?? 0) + 1;
    }
    expect(counts['gone'], isNull);
    var chi = 0.0;
    final rest = bp.available(soldOut);
    final total = rest.fold<int>(0, (t, it) => t + it.weight);
    for (final it in rest) {
      final expected = n * it.weight / total;
      final d = (counts[it.id] ?? 0) - expected;
      chi += d * d / expected;
    }
    expect(chi, lessThan(13.82), reason: '$counts');
  });
}
