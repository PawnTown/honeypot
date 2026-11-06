part of '../honeypot.dart';

/// One thing a box can hold. Its chance is exactly [weight] / total, with no
/// floating point anywhere. [cap] is optional: at most this many will ever
/// exist, and 0 means no limit (spec "Caps").
class Item {
  const Item(this.id, this.weight, [this.cap = 0]);

  final String id;
  final int weight;
  final int cap;

  @override
  bool operator ==(Object other) => other is Item && other.id == id && other.weight == weight && other.cap == cap;

  @override
  int get hashCode => Object.hash(id, weight, cap);

  @override
  String toString() => 'Item($id, $weight, $cap)';
}

/// The public list of what a box can hold and how likely each item is (spec
/// "Blueprints"). Items are sorted by the bytes of their id, so a blueprint has
/// one byte form and one id.
///
/// The constructor checks nothing: build one with [newBlueprint] or
/// [decodeBlueprint].
class Blueprint {
  Blueprint({this.series = '', List<int>? meta, this.items = const []}) : meta = Uint8List.fromList(meta ?? const []);

  final String series;
  final Uint8List meta;
  final List<Item> items;

  void _check() {
    if (utf8.encode(series).length > 255 || meta.length > 65535) throw HoneypotError.tooLong;
    if (items.isEmpty || items.length > 65535) throw HoneypotError.blueprint;
    List<int> last = const [];
    for (final it in items) {
      final id = utf8.encode(it.id);
      final whole = it.weight >= 1 && it.weight <= 0xffffffff && it.cap >= 0 && it.cap <= 0xffffffff;
      if (_compare(id, last) <= 0 || id.length > 255 || !_validString(it.id) || !whole) throw HoneypotError.blueprint;
      last = id;
    }
  }

  /// The blueprint as it is published.
  Uint8List encode() {
    final s = utf8.encode(series);
    return _cat([
      ascii.encode(tagBlueprint),
      _u8(s.length),
      s,
      _u16(meta.length),
      meta,
      _u16(items.length),
      for (final it in items) ...[_u8(utf8.encode(it.id).length), utf8.encode(it.id), _u32(it.weight), _u32(it.cap)],
    ]);
  }

  /// The hash of its bytes. Other odds are another id.
  Uint8List get id => sha256(encode());

  /// The sum of the weights. It cannot overflow: at most 65535 items of at
  /// most 2^32 - 1 each.
  int get total => _totalWeight(items);

  /// Whether any item has a cap, which is what makes a draw need state.
  bool get capped => items.any((it) => it.cap > 0);

  /// What a draw can give once the items at [soldOut] are left out.
  List<Item> available([List<int> soldOut = const []]) => [
    for (var i = 0; i < items.length; i++)
      if (!soldOut.contains(i)) items[i],
  ];

  /// The plaintext size of every box of this blueprint: enough for a serial and
  /// the longest id, so the size of a box says nothing about which item it holds.
  int get size => items.map((it) => utf8.encode(it.id).length).fold(0, max) + 2 + 8;

  /// The draw: the item an open key and an input give, out of what was not sold
  /// out when the issuer signed the ticket.
  Item pick(List<int> openKey, List<int> input, [List<int> soldOut = const []]) {
    final left = available(soldOut);
    return itemAt(left, roll(openKey, id, input, BigInt.from(_totalWeight(left))).r);
  }
}

int _totalWeight(List<Item> items) => items.fold(0, (t, it) => t + it.weight);

/// Sorts the items and checks the rules: 1 to 65535 items, ids that are text,
/// not empty, at most 255 bytes and not repeated, and every weight at least 1.
Blueprint newBlueprint(String series, List<int>? meta, Iterable<Item> items) {
  final sorted = [...items]..sort((a, b) => _byName(a.id, b.id));
  return Blueprint(series: series, meta: meta, items: List.unmodifiable(sorted)).._check();
}

/// Decodes one blueprint and checks the rules. Its series must be UTF-8 here:
/// a Dart string cannot hold anything else.
Blueprint decodeBlueprint(List<int> raw) {
  final r = _Reader(raw)..tag(tagBlueprint);
  final series = r.take(r.u8());
  final meta = r.take(r.u16());
  final n = r.u16();
  final items = <Item>[];
  for (var i = 0; i < n && r.err == null; i++) {
    final id = r.take(r.u8());
    if (r.err == null && _text(id) == null) r.err = HoneypotError.blueprint;
    items.add(Item(_lenient(id), r.u32(), r.u32()));
  }
  if (r.err == null && _text(series) == null) r.err = HoneypotError.blueprint;
  r.done();
  return Blueprint(series: _lenient(series), meta: meta, items: List.unmodifiable(items)).._check();
}

/// A number exactly uniform in [0, total), if the KDF output is uniform, and how
/// many values were rejected on the way. It takes 64 bits and drops the
/// 2^64 mod total lowest values, so what is left divides evenly by total and
/// x mod total has no bias.
({BigInt r, int rejected}) roll(List<int> openKey, List<int> blueprintId, List<int> input, BigInt total) {
  final reject = (BigInt.one << 64) % total;
  for (var j = 0; ; j++) {
    final x = _readU64(_kdf(openKey, _tagRoll, [blueprintId, input, _u32(j)]));
    if (x >= reject) return (r: x % total, rejected: j);
  }
}

/// The item a number below the total weight maps to: each item covers exactly
/// its weight of the numbers.
Item itemAt(List<Item> items, BigInt r) {
  var left = r;
  var i = 0;
  while (left >= BigInt.from(items[i].weight)) {
    left -= BigInt.from(items[i].weight);
    i++;
  }
  return items[i];
}
