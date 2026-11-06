// Blueprints, the draw and tickets: the Go tests in draw_test.go.
import 'dart:convert';
import 'dart:typed_data';

import 'package:honeypot/honeypot.dart';
import 'package:test/test.dart';

import 'helpers.dart';

/// Chi-square of the observed counts against the weights.
double chiSquare(List<Item> items, Map<String, int> counts, int n) {
  final total = items.fold<int>(0, (t, it) => t + it.weight);
  var chi = 0.0;
  for (final it in items) {
    final expected = n * it.weight / total;
    final d = (counts[it.id] ?? 0) - expected;
    chi += d * d / expected;
  }
  return chi;
}

void main() {
  final issuer = issuerOf();
  final keys = issuer.keys;

  test('a blueprint', () {
    final a = gold();
    final b = newBlueprint(chest.series, chest.meta, const [
      Item('legendary sword of the first dawn', 1),
      Item('wooden sword', 900),
      Item('silver shield', 99),
    ]);
    expect(b.id, a.id, reason: 'the order of the items must not matter');
    expect(a.total, 1000);
    final got = decodeBlueprint(a.encode());
    expect(got.id, a.id);
    expect(got.encode(), a.encode());
    expect(got.items, a.items);
    // Other odds, other id.
    final c = newBlueprint(chest.series, chest.meta, const [
      Item('legendary sword of the first dawn', 2),
      Item('wooden sword', 900),
      Item('silver shield', 99),
    ]);
    expect(c.id, isNot(a.id));
    expect(a.items.first, const Item('legendary sword of the first dawn', 1));
    expect(a.items.first.hashCode, const Item('legendary sword of the first dawn', 1).hashCode);
    expect(a.items.first.toString(), 'Item(legendary sword of the first dawn, 1, 0)');
  });

  test('blueprints that break the rules', () {
    for (final MapEntry(key: name, value: items) in {
      'no items': <Item>[],
      'empty id': [const Item('', 1)],
      'long id': [Item('x' * 256, 1)],
      'lone surrogate': [const Item('\uD800', 1)],
      'duplicate': [const Item('a', 1), const Item('a', 2)],
      'zero weight': [const Item('a', 0)],
      'weight past u32': [const Item('a', 1 << 32)],
      'negative cap': [const Item('a', 1, -1)],
      'cap past u32': [const Item('a', 1, 1 << 32)],
      'too many': [for (var i = 0; i < 65536; i++) Item('$i', 1)],
    }.entries) {
      expect(() => newBlueprint('s', null, items), fails(HoneypotError.blueprint), reason: name);
    }
    const ok = [Item('a', 1)];
    expect(() => newBlueprint('s' * 256, null, ok), fails(HoneypotError.tooLong));
    expect(() => newBlueprint('s', Uint8List(65536), ok), fails(HoneypotError.tooLong));

    final raw = gold().encode();
    expect(() => decodeBlueprint([]), fails(HoneypotError.short));
    expect(() => decodeBlueprint([...ascii.encode('HPBLP999'), ...raw.sublist(8)]), fails(HoneypotError.tag));
    expect(() => decodeBlueprint([...raw, 0]), fails(HoneypotError.trailing));
    for (var n = 0; n < raw.length; n++) {
      expect(() => decodeBlueprint(raw.sublist(0, n)), throwsA(isA<HoneypotError>()), reason: 'truncated to $n bytes');
    }
    final unsorted = Blueprint(series: 's', items: const [Item('b', 1), Item('a', 1)]);
    expect(() => decodeBlueprint(unsorted.encode()), fails(HoneypotError.blueprint));
    final zero = Blueprint(series: 's', items: const [Item('a', 0)]);
    expect(() => decodeBlueprint(zero.encode()), fails(HoneypotError.blueprint));
    // Ids and the series are text.
    final binaryId = [...ascii.encode('HPBLP001'), 1, 0x73, 0, 0, 0, 1, 1, 0xff, 0, 0, 0, 1, 0, 0, 0, 0];
    expect(() => decodeBlueprint(binaryId), fails(HoneypotError.blueprint));
    final binarySeries = [...ascii.encode('HPBLP001'), 1, 0xff, 0, 0, 0, 1, 1, 0x61, 0, 0, 0, 1, 0, 0, 0, 0];
    expect(() => decodeBlueprint(binarySeries), fails(HoneypotError.blueprint));
  });

  test('every item covers exactly its weight of the numbers', () {
    final bp = gold();
    final counts = <String, int>{};
    for (var r = 0; r < bp.total; r++) {
      final id = itemAt(bp.items, BigInt.from(r)).id;
      counts[id] = (counts[id] ?? 0) + 1;
    }
    for (final it in bp.items) {
      expect(counts[it.id], it.weight);
    }
  });

  test('rejection removes the modulo bias', () {
    final two64 = BigInt.one << 64;
    for (final total in [1, 2, 3, 7, 10, 1000, 1 << 32, (1 << 32) - 1, 281470681677825]) {
      final t = BigInt.from(total);
      expect((two64 - two64 % t) % t, BigInt.zero);
    }
  });

  test('the roll retries on rejection and stays in range', () {
    final total = (BigInt.one << 63) + BigInt.one;
    final key = seed('roll key'), id = sha256(utf8.encode('blueprint'));
    var retried = false;
    for (var i = 0; i < 64; i++) {
      final got = roll(key, id, entropyOf('$i'), total);
      if (got.rejected > 0) retried = true;
      expect(got.r < total, isTrue);
    }
    expect(retried, isTrue);
  });

  // The seeds are fixed, so this cannot flake. 13.82 is the 99.9 % point of
  // chi-square with 2 degrees of freedom.
  test('a draw matches the odds if either side is honest', () {
    final bp = gold();
    const n = 200000;
    final fixedKey = seed('issuer fixes this key'), fixedInput = entropyOf('player fixes this input');
    for (final MapEntry(key: name, value: next) in {
      'issuer fixes the key': (int i) => (fixedKey, entropyOf('in$i')),
      'player fixes the input': (int i) => (seed('key$i'), fixedInput),
    }.entries) {
      final counts = <String, int>{};
      for (var i = 0; i < n; i++) {
        final (key, input) = next(i);
        final id = bp.pick(key, input).id;
        counts[id] = (counts[id] ?? 0) + 1;
      }
      expect(chiSquare(bp.items, counts, n), lessThan(13.82), reason: '$name: $counts');
    }
  });

  test('mint', () async {
    final bp = gold();
    final counts = <String, int>{};
    int? size;
    for (var i = 0; i < 300; i++) {
      final b = await issuer.mint(bp, props: {propUser: 'alice'});
      final raw = b.encode();
      expect(raw.length, size ?? raw.length, reason: 'the size of a box says which item it holds');
      size = raw.length;
      final got = decodeBox(raw);
      final drawn = got.openItem(keys, bp, issuer.key(got));
      expect(got.props[propUser], 'alice');
      expect(got.draw!.blueprintId, bp.id);
      expect(utf8.decode(got.series), bp.series);
      // The key decrypts the payload, and the payload names the item.
      final payload = got.open(keys, issuer.key(got));
      expect(utf8.decode(payload.sublist(8)), drawn.item.id);
      expect(drawn.serial, BigInt.zero);
      counts[drawn.item.id] = (counts[drawn.item.id] ?? 0) + 1;
    }
    expect(counts['wooden sword'], greaterThan(200));
  });

  test('mint and ticket reject', () async {
    final bp = gold();
    expect(() => newDrawRequest(Uint8List(31)), throwsArgumentError);
    await expectLater(issuer.ticket(bp, Uint8List(32), entropy: Uint8List(31)), throwsArgumentError);
    await expectLater(issuer.mint(Blueprint()), fails(HoneypotError.blueprint));
    await expectLater(issuer.ticket(bp, Uint8List(32), props: {'': 'x'}), fails(HoneypotError.property));
  });

  test('the ticket exchange', () async {
    final bp = gold();
    final props = {propUser: 'alice'};

    // The player commits, the issuer promises.
    final req = newDrawRequest();
    final ticket = await issuer.ticket(bp, req.commit, props: props);
    final got = decodeTicket(ticket.encode());
    expect(got.encode(), ticket.encode(), reason: 'a ticket has one byte form');
    got.verify(keys, bp, req.commit);
    expect(got.available(bp), bp.items);

    // The player reveals, the issuer fills the box.
    final box = await issuer.redeem(got, bp, req.input);
    final held = decodeBox(box.encode());
    held.verifyTicket(keys, got);

    // Asking again gives the very same box, so a ticket is one box, with no state.
    expect((await issuer.redeem(got, bp, req.input)).encode(), box.encode());

    // Claim and open, as for any box.
    final ledger = MemLedger();
    final key = await issuer.release(ledger, held, 'alice');
    final drawn = held.openItem(keys, bp, key);
    expect(drawn.item, bp.pick(key, req.input));
    expect(drawn.total, BigInt.from(1000));
    expect(drawn.available, bp.items);

    // A rewrite keeps the draw, and the ticket check still passes.
    final moved = await issuer.rewrite(ledger, held, {propUser: 'bob'});
    moved.verifyTicket(keys, got);
    expect(moved.openItem(keys, bp, key).item, drawn.item);
  });

  test("the player's guarantees", () async {
    final other = issuerOf(1, otherTag);
    final bp = gold();
    final other2 = newBlueprint(bp.series, bp.meta, const [Item('x', 1)]);
    final (req, ticket, box) = await fairDraw(issuer, bp);

    // A ticket that is not for this player, this blueprint or this issuer.
    expect(() => ticket.verify(keys, bp, Uint8List(32)..[0] = 1), fails(HoneypotError.input));
    expect(() => ticket.verify(keys, other2, req.commit), fails(HoneypotError.wrongBlueprint));
    expect(() => ticket.verify(keys, Blueprint(), req.commit), fails(HoneypotError.blueprint));
    expect(() => ticket.verify(other.keys, bp, req.commit), fails(HoneypotError.signature));
    expect(() => ticket.verify({}, bp, req.commit), fails(HoneypotError.unknownKey));
    final otherSeries = newBlueprint('other', bp.meta, bp.items);
    final moved = ticket.copyWith(blueprintId: otherSeries.id);
    expect(() => moved.copyWith(sig: issuer.signTicket(moved)).verify(keys, otherSeries, req.commit), fails(HoneypotError.wrongBlueprint));
    final otherMeta = newBlueprint(bp.series, utf8.encode('{}'), bp.items);
    final remeta = ticket.copyWith(blueprintId: otherMeta.id);
    expect(() => remeta.copyWith(sig: issuer.signTicket(remeta)).verify(keys, otherMeta, req.commit), fails(HoneypotError.wrongBlueprint));

    // The issuer only redeems its own tickets, with the one input.
    await expectLater(issuer.redeem(ticket, bp, Uint8List(32)..[0] = 1), fails(HoneypotError.input));
    await expectLater(issuer.redeem(ticket, other2, req.input), fails(HoneypotError.wrongBlueprint));
    await expectLater(other.redeem(ticket, bp, req.input), fails(HoneypotError.signature));

    // A box other than the promised one: the issuer changed the key after seeing
    // the input, which is what the ticket exists to stop.
    final (_, _, otherBox) = await fairDraw(issuer, bp);
    expect(() => otherBox.verifyTicket(keys, ticket), fails(HoneypotError.ticket));
    final swapped = box.copyWith(keyCommit: flip(box.keyCommit, 0));
    expect(() => swapped.copyWith(sig: issuer.signBox(swapped)).verifyTicket(keys, ticket), fails(HoneypotError.ticket));
    final assignedBox = box.copyWith(props: {propUser: 'mallory'});
    expect(() => assignedBox.copyWith(sig: issuer.signBox(assignedBox)).verifyTicket(keys, ticket), fails(HoneypotError.ticket));

    // Input other than the committed one.
    final d = box.draw!;
    final wrong = box.copyWith(
      draw: Draw(blueprintId: d.blueprintId, inputCommit: d.inputCommit, soldOut: d.soldOut, input: flip(d.input!, 0)),
    );
    final wrongSigned = wrong.copyWith(sig: issuer.signBox(wrong));
    expect(() => wrongSigned.verifyTicket(keys, ticket), fails(HoneypotError.input));
    expect(() => wrongSigned.openItem(keys, bp, issuer.key(wrongSigned)), fails(HoneypotError.input));

    // Not signed, and not drawn at all.
    expect(() => box.verifyTicket(other.keys, ticket), fails(HoneypotError.signature));
    final hand = sealAt(issuer, 'a', chest, utf8.encode('sword'));
    expect(() => hand.verifyTicket(keys, ticket), fails(HoneypotError.notDrawn));
    expect(() => hand.openItem(keys, bp, issuer.key(hand)), fails(HoneypotError.notDrawn));

    // Opening checks the blueprint and the key.
    expect(() => box.openItem(keys, other2, issuer.key(box)), fails(HoneypotError.wrongBlueprint));
    expect(() => box.openItem(keys, bp, Uint8List(keySize)), fails(HoneypotError.wrongKey));
  });

  test('opening catches an issuer that picks the item', () async {
    final bp = gold();
    final (_, _, b) = await fairDraw(issuer, bp);
    final key = issuer.key(b);
    final drawn = bp.pick(key, b.draw!.input!);
    final other = bp.items.firstWhere((it) => it != drawn);
    final plain = Uint8List(bp.size)
      ..[1] = 8 + utf8.encode(other.id).length
      ..setAll(10, utf8.encode(other.id));
    final forged = reseal(issuer, b, plain);
    forged.verify(keys);
    expect(() => forged.openItem(keys, bp, key), fails(HoneypotError.draw));
  });

  test('decoding rejects draws', () async {
    final bp = gold();
    final (_, ticket, box) = await fairDraw(issuer, bp);
    final raw = ticket.encode();
    expect(() => decodeTicket([]), fails(HoneypotError.short));
    expect(() => decodeTicket([...ascii.encode('HPTKT999'), ...raw.sublist(8)]), fails(HoneypotError.tag));
    expect(() => decodeTicket([...raw, 0]), fails(HoneypotError.trailing));
    for (var n = 0; n < raw.length; n++) {
      expect(() => decodeTicket(raw.sublist(0, n)), throwsA(isA<HoneypotError>()), reason: 'truncated to $n bytes');
    }
    // A ticket always has a draw.
    final hand = sealAt(issuer, 'a', chest, utf8.encode('sword'));
    final noDraw = [...ascii.encode(tagTicket), ...hand.header, ...hand.keyCommit, 0, ...hand.sig];
    expect(() => decodeTicket(noDraw), fails(HoneypotError.drawField));

    // The flag has two values.
    final bad = box.encode()..[box.prefix.length - 67] = 2; // before two ids and an empty list
    expect(() => decodeBox(bad), fails(HoneypotError.drawField));

    // Every byte of a drawn box and of a ticket is covered: flip each one.
    final rawBox = box.encode();
    for (var i = 0; i < rawBox.length; i++) {
      caught(() => decodeBox(flip(rawBox, i)).verify(keys), 'box byte $i');
    }
    for (var i = 0; i < raw.length; i++) {
      caught(() => decodeTicket(flip(raw, i)).verify(keys, bp, ticket.inputCommit), 'ticket byte $i');
    }
  });
}
