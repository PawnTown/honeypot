// How long the player's checks take in pure Dart. Prints, and fails only if a
// check gets far slower than a pack opening can hide.
import 'dart:convert';
import 'dart:io';

import 'package:honeypot/honeypot.dart';
import 'package:test/test.dart';

void main() {
  final v = jsonDecode(File('../vectors/core.json').readAsStringSync()) as Map<String, dynamic>;
  final keys = {v['issuer']['key_id'] as int: fromHex(v['issuer']['public'] as String)};
  final draw = (v['draws'] as List).first as Map<String, dynamic>;
  final raw = fromHex(draw['box'] as String);
  final openKey = fromHex(draw['open_key'] as String);
  final bp = decodeBlueprint(fromHex(v['blueprints'][draw['blueprint']]['hex'] as String));

  /// The first run and the median of the next [n], in microseconds.
  (int, int) time(void Function() fn, [int n = 20]) {
    final first = Stopwatch()..start();
    fn();
    final cold = first.elapsedMicroseconds;
    final runs = <int>[];
    for (var i = 0; i < n; i++) {
      final sw = Stopwatch()..start();
      fn();
      runs.add(sw.elapsedMicroseconds);
    }
    runs.sort();
    return (cold, runs[n ~/ 2]);
  }

  String ms(int us) => '${(us / 1000).toStringAsFixed(2)} ms';

  test('one ML-DSA-65 verify and one whole openItem', () {
    final (verifyCold, verify) = time(() => decodeBox(raw).verify(keys));
    final (openCold, open) = time(() => decodeBox(raw).openItem(keys, bp, openKey));
    // ignore: avoid_print
    print('decode + verify: first ${ms(verifyCold)}, then ${ms(verify)}; decode + openItem: first ${ms(openCold)}, then ${ms(open)}');
    expect(open, lessThan(250000));
  });
}
