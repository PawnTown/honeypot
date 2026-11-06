part of '../honeypot.dart';

/// The size of a main key and of an open key.
const int keySize = 32;

/// The size of an issuer public key (ML-DSA-65).
const int publicKeySize = 1952;

/// The size of a signature (ML-DSA-65).
const int sigSize = 3309;

/// The largest plaintext a box can hold: the ciphertext, with its 16-byte tag,
/// has a u16 length.
const int maxSize = 65535 - 16;

/// The property that assigns a box to a user: [Issuer.release] gives the open
/// key to this user only.
const String propUser = 'userId';

/// Starts every box (spec "Naming"). A changed layout gets a new tag.
const String tagBox = 'HPBOX001';

/// Starts every ticket.
const String tagTicket = 'HPTKT001';

/// Starts every blueprint.
const String tagBlueprint = 'HPBLP001';

// Derivation tags (spec "Keys").
const String _tagSign = 'HPSIGN01';
const String _tagRoot = 'HPROOT01';
const String _tagNonce = 'HPNONC01';
const String _tagKey = 'HPKEY001';
const String _tagEnc = 'HPENC001';
const String _tagCommit = 'HPCOMT01';
const String _tagInput = 'HPINPT01';
const String _tagRoll = 'HPROLL01';

/// A Honeypot error. [message] is the one of the Go and JavaScript libraries,
/// [code] the name of the JavaScript library's error. There is one instance of
/// each, so compare with ==.
final class HoneypotError implements Exception {
  HoneypotError._(this.code, this.message);

  final String code;
  final String message;

  static final short = HoneypotError._('short', 'input too short');
  static final tag = HoneypotError._('tag', 'wrong message tag');
  static final trailing = HoneypotError._('trailing', 'bytes after the message');
  static final drawField = HoneypotError._('drawField', 'malformed draw fields');
  static final tooLong = HoneypotError._('tooLong', 'series longer than 255 bytes or meta longer than 65535');
  static final property = HoneypotError._('property', 'malformed properties');
  static final size = HoneypotError._('size', 'payload does not fit the series size');
  static final keySize = HoneypotError._('keySize', 'key must be 32 bytes');
  static final unknownKey = HoneypotError._('unknownKey', 'unknown issuer key');
  static final signature = HoneypotError._('signature', 'bad signature');
  static final wrongKey = HoneypotError._('wrongKey', 'open key does not belong to this box');
  static final ciphertext = HoneypotError._('ciphertext', 'ciphertext does not decrypt');
  static final padding = HoneypotError._('padding', 'malformed plaintext');
  static final blueprint = HoneypotError._('blueprint', 'malformed blueprint');
  static final notDrawn = HoneypotError._('notDrawn', 'box was not drawn from a blueprint');
  static final wrongBlueprint = HoneypotError._('wrongBlueprint', 'not the blueprint of this box');
  static final input = HoneypotError._('input', 'input does not match its commitment');
  static final ticket = HoneypotError._('ticket', 'box does not match the ticket');
  static final draw = HoneypotError._('draw', 'contents are not what the draw gives');
  static final noCaps = HoneypotError._('noCaps', 'this blueprint has caps and needs Caps');
  static final soldOut = HoneypotError._('soldOut', 'sold out');
  static final claimed = HoneypotError._('claimed', 'box already claimed by another owner');
  static final notOwner = HoneypotError._('notOwner', 'box is assigned to another user');
  static final stale = HoneypotError._('stale', 'a newer revision of this box exists');

  /// Every error.
  static final List<HoneypotError> values = List.unmodifiable([
    short,
    tag,
    trailing,
    drawField,
    tooLong,
    property,
    size,
    keySize,
    unknownKey,
    signature,
    wrongKey,
    ciphertext,
    padding,
    blueprint,
    notDrawn,
    wrongBlueprint,
    input,
    ticket,
    draw,
    noCaps,
    soldOut,
    claimed,
    notOwner,
    stale,
  ]);

  @override
  String toString() => 'honeypot: $message';
}

/// SHA-256.
Uint8List sha256(List<int> b) => Uint8List.fromList(crypto.sha256.convert(b).bytes);

String toHex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Throws a [FormatException] for anything but an even number of hex digits.
Uint8List fromHex(String s) {
  if (s.length.isOdd || RegExp('[^0-9a-fA-F]').hasMatch(s)) throw FormatException('not hex', s);
  return Uint8List.fromList([for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);
}

final Random _rng = Random.secure();

/// [n] bytes from the platform's CSPRNG.
Uint8List randomBytes(int n) => Uint8List.fromList([for (var i = 0; i < n; i++) _rng.nextInt(256)]);

Uint8List _cat(List<List<int>> parts) {
  final out = BytesBuilder(copy: false);
  for (final p in parts) {
    out.add(p);
  }
  return out.toBytes();
}

Uint8List _u8(int v) => Uint8List.fromList([v & 0xff]);
Uint8List _u16(int v) => Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);
Uint8List _u32(int v) => Uint8List.fromList([(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);
Uint8List _u64(BigInt v) => Uint8List.fromList([for (var i = 56; i >= 0; i -= 8) ((v >> i) & BigInt.from(0xff)).toInt()]);

/// The first 8 bytes of [b], big-endian.
BigInt _readU64(List<int> b) {
  var v = BigInt.zero;
  for (var i = 0; i < 8; i++) {
    v = (v << 8) | BigInt.from(b[i]);
  }
  return v;
}

/// Equality in constant time, for anything secret.
bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Byte order, which is how names and ids are sorted.
int _compare(List<int> a, List<int> b) {
  for (var i = 0; i < min(a.length, b.length); i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

int _byName(String a, String b) => _compare(utf8.encode(a), utf8.encode(b));

/// The text of [b] if it is valid UTF-8, else null. A leading byte order mark
/// stays part of the text: Dart's decoder drops one at the very start, so the
/// decoding starts one byte earlier.
String? _text(List<int> b) {
  try {
    return utf8.decode([0x20, ...b]).substring(1);
  } on FormatException {
    return null;
  }
}

/// The text of [b], with anything that is not UTF-8 replaced, for display.
String _lenient(List<int> b) => utf8.decode([0x20, ...b], allowMalformed: true).substring(1);

/// Whether [s] is text that survives UTF-8: no lone surrogates.
bool _validString(String s) => _text(utf8.encode(s)) == s;

/// KDF(key, tag, data...) = HMAC-SHA-256(key, tag | data...), the only
/// derivation in the protocol. Every input but the last has a fixed length or
/// delimits itself.
Uint8List _kdf(List<int> key, String tag, [List<List<int>> data = const []]) =>
    Uint8List.fromList(crypto.Hmac(crypto.sha256, key).convert(_cat([utf8.encode(tag), ...data])).bytes);

/// Walks a byte list; the first failure sticks and every later read returns
/// zeros.
class _Reader {
  _Reader(this.b);

  final List<int> b;
  int at = 0;
  HoneypotError? err;

  int get left => b.length - at;

  Uint8List take(int n) {
    if (err != null) return Uint8List(n);
    if (n > left) {
      err = HoneypotError.short;
      return Uint8List(n);
    }
    at += n;
    return Uint8List.fromList(b.sublist(at - n, at));
  }

  int u8() => take(1)[0];

  int u16() {
    final x = take(2);
    return x[0] << 8 | x[1];
  }

  int u32() {
    final x = take(4);
    return x[0] << 24 | x[1] << 16 | x[2] << 8 | x[3];
  }

  void tag(String want) {
    final got = take(want.length);
    if (err == null && !_same(got, ascii.encode(want))) err = HoneypotError.tag;
  }

  /// Throws the first failure, or [HoneypotError.trailing] for bytes left over.
  void done() {
    if (err == null && left != 0) err = HoneypotError.trailing;
    if (err != null) throw err!;
  }
}
