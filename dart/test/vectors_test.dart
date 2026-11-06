// The shared vectors: every byte here must match the Go library, which writes
// them (go test . -update in go/).
import 'dart:convert';
import 'dart:io';

import 'package:honeypot/honeypot.dart';
import 'package:test/test.dart';

import 'helpers.dart';

void main() {
  final v = jsonDecode(File('../vectors/core.json').readAsStringSync()) as Map<String, dynamic>;
  final issuer = Issuer(v['issuer']['key_id'] as int, fromHex(v['issuer']['main_key'] as String));
  final keys = issuer.keys;
  Blueprint blueprint(String name) => decodeBlueprint(fromHex(v['blueprints'][name]['hex'] as String));
  Map<String, String> props(Object? p) => p == null ? {} : (p as Map).cast<String, String>();
  List<Map<String, dynamic>> list(String name) => (v[name] as List).cast<Map<String, dynamic>>();

  test('the main key splits the same way', () {
    expect(toHex(issuer.signSeed), v['issuer']['sign_seed']);
    expect(toHex(issuer.openRoot), v['issuer']['open_root']);
    expect(toHex(issuer.publicKey), v['issuer']['public']);
  });

  test('boxes sealed by hand', () {
    for (final c in list('boxes')) {
      final name = c['name'] as String;
      final spec = Spec(series: c['series'] as String, meta: fromHex(c['meta'] as String), props: props(c['properties']), size: c['size'] as int);
      final b = issuer.seal(spec, fromHex(c['payload'] as String), entropy: fromHex(c['entropy'] as String));
      expect(toHex(b.nonce), c['nonce'], reason: name);
      expect(toHex(b.keyInput), c['key_input'], reason: name);
      expect(toHex(issuer.key(b)), c['open_key'], reason: name);
      expect(toHex(b.keyCommit), c['key_commit'], reason: name);
      expect(toHex(b.ciphertext), c['ciphertext'], reason: name);
      expect(toHex(b.id), c['box_id'], reason: name);
      expect(toHex(b.sig), c['sig'], reason: name);
      expect(toHex(b.encode()), c['box'], reason: name);

      final got = decodeBox(fromHex(c['box'] as String));
      got.verify(keys);
      got.verifyKey(fromHex(c['open_key'] as String));
      expect(toHex(got.decrypt(keys, fromHex(c['open_key'] as String))), c['plain'], reason: name);
      expect(toHex(got.open(keys, fromHex(c['open_key'] as String))), c['payload'], reason: name);
      expect(got.props, props(c['properties']), reason: name);
      expect(toHex(got.encode()), c['box'], reason: name);
    }
  });

  test('a rewrite signs the same bytes', () async {
    final first = decodeBox(fromHex(v['boxes'][0]['box'] as String));
    for (final c in list('rewrites')) {
      final b = await issuer.rewrite(MemLedger(), first, props(c['properties']));
      expect(b.revision, c['revision']);
      expect(toHex(b.sig), c['sig']);
      expect(toHex(b.encode()), c['box']);
      final held = decodeBox(fromHex(c['box'] as String));
      held.verify(keys);
      expect(held.supersedes(first), isTrue);
      expect(toHex(held.id), toHex(first.id));
      // The rewrite opens with the same key.
      expect(toHex(held.open(keys, fromHex(v['boxes'][0]['open_key'] as String))), v['boxes'][0]['payload']);
    }
  });

  test('blueprints', () {
    for (final MapEntry(key: name, value: c) in (v['blueprints'] as Map<String, dynamic>).entries) {
      final items = [for (final it in c['items'] as List) Item(it['ID'] as String, it['Weight'] as int, it['Cap'] as int)];
      final built = newBlueprint(c['series'] as String, fromHex(c['meta'] as String), items.reversed);
      expect(toHex(built.encode()), c['hex'], reason: name);
      expect(toHex(built.id), c['id'], reason: name);
      expect(built.total, c['total'], reason: name);
      expect(built.size, c['size'], reason: name);
      expect(toHex(blueprint(name).encode()), c['hex'], reason: name);
    }
  });

  test('the roll, with its retry', () {
    var retried = false;
    for (final c in list('rolls')) {
      final key = fromHex(c['Key'] as String);
      final got = roll(key, fromHex(c['BlueprintID'] as String), fromHex(c['Input'] as String), BigInt.parse(c['Total'] as String));
      expect(got.r.toString(), c['R']);
      if (got.rejected > 0) retried = true;
    }
    expect(retried, isTrue);
  });

  test('draws, through the whole ticket exchange', () async {
    for (final c in list('draws')) {
      final name = c['name'] as String;
      final bp = blueprint(c['blueprint'] as String);
      final req = newDrawRequest(fromHex(c['input'] as String));
      expect(toHex(req.commit), c['input_commit'], reason: name);
      final ticket = await issuer.ticket(bp, req.commit, props: props(c['properties']), entropy: fromHex(c['entropy'] as String));
      expect(toHex(ticket.nonce), c['nonce'], reason: name);
      expect(toHex(ticket.keyCommit), c['key_commit'], reason: name);
      expect(toHex(ticket.encode()), c['ticket'], reason: name);

      final decoded = decodeTicket(fromHex(c['ticket'] as String));
      expect(toHex(decoded.encode()), c['ticket'], reason: name);
      decoded.verify(keys, bp, req.commit);
      final b = await issuer.redeem(decoded, bp, req.input);
      expect(toHex(b.keyInput), c['key_input'], reason: name);
      expect(toHex(issuer.key(b)), c['open_key'], reason: name);
      expect(toHex(b.ciphertext), c['ciphertext'], reason: name);
      expect(toHex(b.id), c['box_id'], reason: name);
      expect(toHex(b.encode()), c['box'], reason: name);

      final held = decodeBox(fromHex(c['box'] as String));
      held.verifyTicket(keys, decoded);
      expect(toHex(held.decrypt(keys, fromHex(c['open_key'] as String))), c['plain'], reason: name);
      final drawn = held.openItem(keys, bp, fromHex(c['open_key'] as String));
      expect(drawn.item.id, c['item'], reason: name);
      expect(drawn.serial, BigInt.zero, reason: name);
      expect(bp.pick(fromHex(c['open_key'] as String), req.input).id, c['item'], reason: name);
    }
  });

  test('capped draws, with the counter and the sold out list', () async {
    final bp = blueprint('limited');
    final caps = MemCaps();
    var soldOutSeen = 0;
    for (final c in list('capped_draws')) {
      final name = c['name'] as String;
      final req = newDrawRequest(fromHex(c['input'] as String));
      final ticket = await issuer.ticket(bp, req.commit, caps: caps, entropy: fromHex(c['entropy'] as String));
      expect(toHex(ticket.encode()), c['ticket'], reason: name);
      expect(ticket.soldOut, (c['sold_out'] as List?) ?? const [], reason: name);
      if (ticket.soldOut.isNotEmpty) soldOutSeen++;
      final b = await issuer.redeem(ticket, bp, req.input, caps: caps);
      expect(toHex(b.encode()), c['box'], reason: name);
      final drawn = decodeBox(fromHex(c['box'] as String)).openItem(keys, bp, fromHex(c['open_key'] as String));
      expect(drawn.item.id, c['item'], reason: name);
      expect(drawn.serial, BigInt.from(c['serial'] as int), reason: name);
    }
    expect(soldOutSeen, greaterThan(0));
  });

  test('what must be rejected', () {
    final invalid = v['invalid'] as Map<String, dynamic>;
    for (final MapEntry(key: name, value: s) in (invalid['undecodable'] as Map<String, dynamic>).entries) {
      expect(() => decodeBox(fromHex(s as String)), throwsA(isA<HoneypotError>()), reason: name);
    }
    for (final MapEntry(key: name, value: s) in (invalid['bad_signature'] as Map<String, dynamic>).entries) {
      caught(() => decodeBox(fromHex(s as String)).verify(keys), name);
    }
    final first = decodeBox(fromHex(v['boxes'][0]['box'] as String));
    for (final s in (invalid['wrong_key'] as Map<String, dynamic>).values) {
      expect(() => first.open(keys, fromHex(s as String)), fails(HoneypotError.wrongKey));
    }
  });

  test('every byte of a drawn box is covered', () {
    final raw = fromHex(v['draws'][0]['box'] as String);
    for (var i = 0; i < raw.length; i += 7) {
      caught(() => decodeBox(flip(raw, i)).verify(keys), 'byte $i');
    }
  });

  test('ownership, transfer and the one-time claim', () async {
    final bp = blueprint('gold');
    final ledger = MemLedger();
    final old = await issuer.mint(bp, props: {propUser: 'alice'});
    await expectLater(issuer.release(ledger, old, 'bob'), fails(HoneypotError.notOwner));
    final moved = await issuer.rewrite(ledger, old, {propUser: 'bob'});
    await expectLater(issuer.release(ledger, old, 'alice'), fails(HoneypotError.stale));
    final key = await issuer.release(ledger, moved, 'bob');
    expect(toHex(await issuer.release(ledger, moved, 'bob')), toHex(key));
    final back = await issuer.rewrite(ledger, moved, {propUser: 'alice'});
    await expectLater(issuer.release(ledger, back, 'alice'), fails(HoneypotError.claimed));
    expect(moved.openItem(keys, bp, key).serial, BigInt.zero);
  });

  test('the issuer cannot swap the item', () async {
    final bp = blueprint('even');
    final req = newDrawRequest();
    final ticket = await issuer.ticket(bp, req.commit);
    final good = await issuer.redeem(ticket, bp, req.input);
    final key = issuer.key(good);
    final drawn = bp.pick(key, req.input);
    final other = bp.items.firstWhere((it) => it.id != drawn.id);
    final liar = Blueprint(series: bp.series, meta: bp.meta, items: [Item(other.id, other.weight)]);
    final forged = await issuer.fill(ticket, liar, req.input);
    forged.verify(keys);
    expect(() => forged.openItem(keys, bp, key), fails(HoneypotError.draw));
  });
}
