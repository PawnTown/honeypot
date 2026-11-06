part of '../honeypot.dart';

/// The smallest [Ledger], in memory, for tests and demos. A real one is the two
/// statements in the spec ("One time").
class MemLedger implements Ledger {
  final Map<String, ({int revision, String? owner})> _rows = {};

  /// How many boxes have a row.
  int get length => _rows.length;

  @override
  String claim(Uint8List id, int revision, String owner) {
    final key = toHex(id);
    final row = _rows[key] ?? (revision: revision, owner: null);
    if (row.revision > revision) throw HoneypotError.stale;
    final claimed = row.owner ?? owner;
    _rows[key] = (revision: row.revision, owner: claimed);
    return claimed;
  }

  @override
  int advance(Uint8List id, int revision) {
    final key = toHex(id);
    final row = _rows[key] ?? (revision: revision, owner: null);
    final next = max(row.revision, revision) + 1;
    _rows[key] = (revision: next, owner: row.owner);
    return next;
  }
}

/// The smallest [Caps], in memory, for tests and demos, for one blueprint at a
/// time. A real one is the statements in the spec ("Caps").
class MemCaps implements Caps {
  final Map<String, BigInt> _taken = {};
  final Map<String, BigInt> _draws = {};
  final Set<String> _full = {};

  /// How many units of [item] were handed out.
  BigInt taken(String item) => _taken[item] ?? BigInt.zero;

  @override
  List<String> soldOut(Uint8List blueprintId) => [..._full];

  /// The next serial, or null once the cap is reached. A retry keeps its serial.
  @override
  BigInt? take(Uint8List blueprintId, String item, int cap, Uint8List draw) {
    final key = '$item:${toHex(draw)}';
    if (_draws[key] case final serial?) return serial;
    final next = taken(item) + BigInt.one;
    if (cap > 0 && next > BigInt.from(cap)) return null;
    _taken[item] = next;
    if (cap > 0 && next == BigInt.from(cap)) _full.add(item);
    _draws[key] = next;
    return next;
  }
}
