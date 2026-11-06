part of '../honeypot.dart';

/// Where the contents of a box came from. All of it is public, and none of it
/// says what the item is without the open key.
class Draw {
  Draw({required this.blueprintId, required this.inputCommit, this.soldOut = const [], this.input});

  final Uint8List blueprintId;
  final Uint8List inputCommit;

  /// Positions of the items left out of this draw, ascending.
  final List<int> soldOut;

  /// The player's input. Null in the box a ticket promises, which comes before it.
  final Uint8List? input;
}

/// A sealed box (spec "Sealing a box"). Everything but the payload is public.
/// [revision] and [props] are the only part that can change, and only the
/// issuer can change them.
///
/// [series] and [meta] are the bytes as signed. Use [decodeBox] for a box that
/// arrived, and [Issuer.seal] or [Issuer.redeem] to make one.
class Box {
  Box({
    required this.keyId,
    required this.series,
    required this.meta,
    this.draw,
    required this.nonce,
    required this.keyCommit,
    required this.ciphertext,
    this.revision = 0,
    this.props = const {},
    required this.sig,
  });

  /// Which main key sealed it.
  final int keyId;
  final Uint8List series;
  final Uint8List meta;

  /// Set if the contents were drawn from a blueprint.
  final Draw? draw;
  final Uint8List nonce;
  final Uint8List keyCommit;
  final Uint8List ciphertext;
  final int revision;
  final Map<String, String> props;
  final Uint8List sig;

  Box copyWith({
    Uint8List? series,
    Draw? draw,
    Uint8List? nonce,
    Uint8List? keyCommit,
    Uint8List? ciphertext,
    int? revision,
    Map<String, String>? props,
    Uint8List? sig,
  }) => Box(
    keyId: keyId,
    series: series ?? this.series,
    meta: meta,
    draw: draw ?? this.draw,
    nonce: nonce ?? this.nonce,
    keyCommit: keyCommit ?? this.keyCommit,
    ciphertext: ciphertext ?? this.ciphertext,
    revision: revision ?? this.revision,
    props: props ?? this.props,
    sig: sig ?? this.sig,
  );

  /// The header up to the nonce; the nonce is derived from it.
  Uint8List get prefix {
    final d = draw;
    return _cat([
      ascii.encode(tagBox),
      _u8(keyId),
      _u8(series.length),
      series,
      _u16(meta.length),
      meta,
      if (d == null) _u8(0) else ...[_u8(1), d.blueprintId, d.inputCommit, _u16(d.soldOut.length), ...d.soldOut.map(_u16)],
    ]);
  }

  Uint8List get header => _cat([prefix, nonce]);

  /// The hash of the header: the open key comes from it, since the ciphertext
  /// cannot exist before the key.
  Uint8List get keyInput => sha256(header);

  /// Everything that never changes.
  Uint8List get sealed => _cat([header, keyCommit, draw?.input ?? const [], _u16(ciphertext.length), ciphertext]);

  /// What the signature covers.
  Uint8List get signed => _cat([sealed, _u32(revision), _encodeProps(props)]);

  /// Identifies a box: the hash of its sealed part, and so of its contents. A
  /// rewrite keeps it. It leaves out the revision and the properties, which
  /// change, and the signature, which a dishonest signer can vary.
  Uint8List get id => sha256(sealed);

  /// The box as it travels: the signed part and the signature.
  Uint8List encode() => _cat([signed, sig]);

  /// Where each field of the encoded box sits, as (name, length), for drawing it.
  List<(String, int)> get fields => [
    ('tag', 8),
    ('key id', 1),
    ('series', 1 + series.length),
    ('meta', 2 + meta.length),
    ('draw flag', 1),
    if (draw case final d?) ...[('blueprint id', 32), ('input commitment', 32), ('sold out list', 2 + 2 * d.soldOut.length)],
    ('nonce', 16),
    ('key commitment', 32),
    if (draw != null) ('input', 32),
    ('contents length', 2),
    ('sealed contents', ciphertext.length),
    ('revision', 4),
    ('properties', _encodeProps(props).length),
    ('signature', sig.length),
  ];

  /// Checks the box against the pinned public keys of the issuer. It says who
  /// sealed the box and that the issuer stated these properties at this
  /// revision, and nothing about what is inside. It cannot say the revision is
  /// still the latest: a signature does not expire (spec "Old revisions").
  void verify(Map<int, List<int>> keys) => _verifyFrom(keys, keyId, signed, sig);

  /// Checks an open key against the box without decrypting. Only the one key
  /// the box was sealed with passes.
  void verifyKey(List<int> openKey) {
    if (openKey.length != keySize) throw HoneypotError.keySize;
    if (!_same(_kdf(openKey, _tagCommit), keyCommit)) throw HoneypotError.wrongKey;
  }

  /// Whether this is a later revision of [old]: the same box, so the same
  /// contents and the same open key, with newer properties. Verify both first.
  bool supersedes(Box old) => _same(id, old.id) && revision > old.revision;

  /// Verifies the box and the open key and returns the whole plaintext,
  /// padding included.
  Uint8List decrypt(Map<int, List<int>> keys, List<int> openKey) {
    verify(keys);
    verifyKey(openKey);
    try {
      return _aead(false, openKey, keyInput, ciphertext);
    } on InvalidCipherTextException {
      throw HoneypotError.ciphertext;
    }
  }

  /// Verifies the box and the open key and returns the payload.
  Uint8List open(Map<int, List<int>> keys, List<int> openKey) => _unpad(decrypt(keys, openKey));

  /// Opens a drawn box and checks the draw: anyone can recompute that the open
  /// key and the input give exactly the item inside, under the published odds,
  /// and that its serial is within the item's cap.
  Drawn openItem(Map<int, List<int>> keys, Blueprint bp, List<int> openKey) {
    final payload = open(keys, openKey);
    final d = _checkBlueprintOf(this, bp);
    if (!_same(_commitInput(d.input!), d.inputCommit)) throw HoneypotError.input;
    if (payload.length < 8) throw HoneypotError.draw;
    final serial = _readU64(payload);
    final left = bp.available(d.soldOut);
    final total = BigInt.from(_totalWeight(left));
    final (:r, :rejected) = roll(openKey, d.blueprintId, d.input!, total);
    final item = itemAt(left, r);
    if (!_same(utf8.encode(item.id), payload.sublist(8)) || !_validSerial(bp, item, serial)) throw HoneypotError.draw;
    return Drawn(item: item, serial: serial, r: r, total: total, rejected: rejected, available: left);
  }

  /// The player's check on a box that came for a ticket: it is the promised
  /// box, so the issuer did not choose the key after seeing the input. Check
  /// the ticket with [Ticket.verify] first.
  void verifyTicket(Map<int, List<int>> keys, Ticket t) {
    verify(keys);
    final d = draw;
    if (d == null) throw HoneypotError.notDrawn;
    if (!_same(header, t._box.header) || !_same(keyCommit, t.keyCommit)) throw HoneypotError.ticket;
    if (revision == 0 && !_same(_encodeProps(props), _encodeProps(t.props))) throw HoneypotError.ticket;
    if (!_same(_commitInput(d.input!), d.inputCommit)) throw HoneypotError.input;
  }
}

/// Decodes one box. A box has exactly one byte form: anything after the
/// signature is an error.
Box decodeBox(List<int> raw) {
  final r = _Reader(raw);
  final h = _readHeader(r);
  final keyCommit = r.take(32);
  final draw = h.draw?.withInput(r.take(32));
  final ciphertext = r.take(r.u16());
  final revision = r.u32();
  final props = _readProps(r);
  final sig = r.take(sigSize);
  r.done();
  return Box(
    keyId: h.keyId,
    series: h.series,
    meta: h.meta,
    draw: draw,
    nonce: h.nonce,
    keyCommit: keyCommit,
    ciphertext: ciphertext,
    revision: revision,
    props: props,
    sig: sig,
  );
}

extension on Draw {
  Draw withInput(Uint8List input) => Draw(blueprintId: blueprintId, inputCommit: inputCommit, soldOut: soldOut, input: input);
}

/// The fields of the header, which a ticket carries too.
({int keyId, Uint8List series, Uint8List meta, Draw? draw, Uint8List nonce}) _readHeader(_Reader r) {
  r.tag(tagBox);
  final keyId = r.u8();
  final series = r.take(r.u8());
  final meta = r.take(r.u16());
  Draw? draw;
  final flag = r.u8();
  if (flag == 1) {
    final blueprintId = r.take(32);
    final inputCommit = r.take(32);
    final n = r.u16();
    final soldOut = <int>[];
    for (var i = 0; i < n && r.err == null; i++) {
      final v = r.u16();
      if (r.err == null && i > 0 && v <= soldOut[i - 1]) r.err = HoneypotError.drawField;
      soldOut.add(v);
    }
    draw = Draw(blueprintId: blueprintId, inputCommit: inputCommit, soldOut: List.unmodifiable(soldOut));
  } else if (flag != 0 && r.err == null) {
    r.err = HoneypotError.drawField;
  }
  return (keyId: keyId, series: series, meta: meta, draw: draw, nonce: r.take(16));
}

// --------------------------------------------------------------- properties

/// The rule for one property: a name and readable text.
bool _validProp(String name, String value) {
  final n = utf8.encode(name).length;
  return n > 0 && n <= 255 && utf8.encode(value).length <= 65535 && _validString(name) && _validString(value);
}

void _checkProps(Map<String, String> props) {
  if (props.length > 255 || !props.entries.every((e) => _validProp(e.key, e.value))) throw HoneypotError.property;
}

/// The properties sorted by the bytes of their name, so they have one byte form.
Uint8List _encodeProps(Map<String, String> props) {
  final names = props.keys.toList()..sort(_byName);
  return _cat([
    _u8(names.length),
    for (final name in names) ...[_u8(utf8.encode(name).length), utf8.encode(name), _u16(utf8.encode(props[name]!).length), utf8.encode(props[name]!)],
  ]);
}

Map<String, String> _readProps(_Reader r) {
  final props = <String, String>{};
  List<int> last = const [];
  final n = r.u8();
  for (var i = 0; i < n && r.err == null; i++) {
    final name = r.take(r.u8());
    final value = r.take(r.u16());
    if (r.err == null && (_compare(name, last) <= 0 || _text(name) == null || _text(value) == null)) r.err = HoneypotError.property;
    last = name;
    if (r.err == null) props[_text(name)!] = _text(value)!;
  }
  return props;
}

// ---------------------------------------------------------------- crypto

void _verifyFrom(Map<int, List<int>> keys, int keyId, Uint8List msg, Uint8List sig) {
  final pub = keys[keyId];
  if (pub == null) throw HoneypotError.unknownKey;
  if (!MlDsa.verify(Uint8List.fromList(pub), msg, sig, DilithiumParams.mlDsa65)) throw HoneypotError.signature;
}

/// AES-256-GCM under the encryption key of an open key. The nonce is 12 zero
/// bytes, which is safe because an open key encrypts exactly one plaintext.
Uint8List _aead(bool seal, List<int> openKey, Uint8List keyInput, Uint8List data) {
  final params = AEADParameters(KeyParameter(_kdf(openKey, _tagEnc)), 128, Uint8List(12), keyInput);
  return Uint8List.fromList((GCMBlockCipher(AESEngine())..init(seal, params)).process(data));
}

/// Gives every plaintext of a series the same length, so the size of a box
/// says nothing about what it holds.
Uint8List _pad(List<int> payload, int size) {
  if (size > maxSize || payload.length + 2 > size) throw HoneypotError.size;
  return Uint8List(size)
    ..setAll(0, _u16(payload.length))
    ..setAll(2, payload);
}

Uint8List _unpad(Uint8List plain) {
  final r = _Reader(plain);
  final payload = r.take(r.u16());
  if (r.err != null || plain.skip(r.at).any((c) => c != 0)) throw HoneypotError.padding;
  return payload;
}
