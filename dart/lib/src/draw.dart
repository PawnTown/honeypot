part of '../honeypot.dart';

/// What a drawn box held. [serial] is 0 if its blueprint has no caps. The rest
/// is how the draw got there: the number [r] out of [total], after [rejected]
/// retries, over the [available] items.
class Drawn {
  const Drawn({required this.item, required this.serial, required this.r, required this.total, required this.rejected, required this.available});

  final Item item;
  final BigInt serial;
  final BigInt r;
  final BigInt total;
  final int rejected;
  final List<Item> available;
}

/// The player's part of a draw. Make a new one for every draw: once an input is
/// known, an issuer can choose a nonce that suits it.
class DrawRequest {
  const DrawRequest(this.input, this.commit);

  /// Secret until the ticket arrives.
  final Uint8List input;

  /// Goes to the issuer first.
  final Uint8List commit;
}

/// Draws an input from the CSPRNG and commits to it. [input] is for tests.
DrawRequest newDrawRequest([List<int>? input]) {
  final i = Uint8List.fromList(input ?? randomBytes(32));
  if (i.length != 32) throw ArgumentError.value(i.length, 'input', 'must be 32 bytes');
  return DrawRequest(i, _commitInput(i));
}

Uint8List _commitInput(List<int> input) => _kdf(input, _tagInput);

/// Counts the items of a blueprint with caps (spec "Caps"). A blueprint with
/// no caps never touches it. Either method may return a [Future].
abstract interface class Caps {
  /// The items of a blueprint whose cap has been reached.
  FutureOr<List<String>> soldOut(Uint8List blueprintId);

  /// Atomically gives a draw the next serial of an item, starting at 1, or null
  /// if the cap has been reached. A cap of 0 has no limit. The same draw always
  /// gets the same answer, so a retry keeps its serial.
  FutureOr<BigInt?> take(Uint8List blueprintId, String item, int cap, Uint8List draw);
}

/// What the issuer promises before it sees the player's input: the box it will
/// fill, down to the open key (spec "Drawing"). A box has to match it.
class Ticket {
  Ticket({
    required this.keyId,
    required this.series,
    required this.meta,
    required this.blueprintId,
    required this.inputCommit,
    this.soldOut = const [],
    required this.nonce,
    required this.keyCommit,
    this.props = const {},
    required this.sig,
  });

  final int keyId;
  final Uint8List series;
  final Uint8List meta;
  final Uint8List blueprintId;
  final Uint8List inputCommit;

  /// Positions of the items this draw cannot give.
  final List<int> soldOut;
  final Uint8List nonce;
  final Uint8List keyCommit;
  final Map<String, String> props;
  final Uint8List sig;

  Ticket copyWith({Uint8List? blueprintId, List<int>? soldOut, Uint8List? nonce, Uint8List? keyCommit, Uint8List? sig}) => Ticket(
    keyId: keyId,
    series: series,
    meta: meta,
    blueprintId: blueprintId ?? this.blueprintId,
    inputCommit: inputCommit,
    soldOut: soldOut ?? this.soldOut,
    nonce: nonce ?? this.nonce,
    keyCommit: keyCommit ?? this.keyCommit,
    props: props,
    sig: sig ?? this.sig,
  );

  /// The box a ticket promises, without the input and the contents.
  Box get _box => Box(
    keyId: keyId,
    series: series,
    meta: meta,
    draw: Draw(blueprintId: blueprintId, inputCommit: inputCommit, soldOut: soldOut),
    nonce: nonce,
    keyCommit: keyCommit,
    ciphertext: Uint8List(0),
    props: props,
    sig: Uint8List(0),
  );

  /// What this draw can give, with its exact odds: each weight out of the sum
  /// of the weights. Read it before giving up the input.
  List<Item> available(Blueprint bp) => bp.available(soldOut);

  /// What the signature covers.
  Uint8List get signed => _cat([ascii.encode(tagTicket), _box.header, keyCommit, _encodeProps(props)]);

  /// The ticket as it travels.
  Uint8List encode() => _cat([signed, sig]);

  /// The player's check before giving up the input: the issuer signed this, for
  /// this blueprint, against this player's commitment.
  void verify(Map<int, List<int>> keys, Blueprint bp, List<int> inputCommit) {
    _verifyFrom(keys, keyId, signed, sig);
    _checkBlueprintOf(_box, bp);
    if (!_same(this.inputCommit, inputCommit)) throw HoneypotError.input;
  }
}

/// Decodes one ticket.
Ticket decodeTicket(List<int> raw) {
  final r = _Reader(raw)..tag(tagTicket);
  final h = _readHeader(r);
  if (r.err == null && h.draw == null) r.err = HoneypotError.drawField;
  final keyCommit = r.take(32);
  final props = _readProps(r);
  final sig = r.take(sigSize);
  r.done();
  final d = h.draw!;
  return Ticket(
    keyId: h.keyId,
    series: h.series,
    meta: h.meta,
    blueprintId: d.blueprintId,
    inputCommit: d.inputCommit,
    soldOut: d.soldOut,
    nonce: h.nonce,
    keyCommit: keyCommit,
    props: props,
    sig: sig,
  );
}

/// Says the box was drawn from this blueprint, and returns its draw.
Draw _checkBlueprintOf(Box b, Blueprint bp) {
  final d = b.draw;
  if (d == null) throw HoneypotError.notDrawn;
  bp._check();
  if (!_same(d.blueprintId, bp.id) || !_same(b.series, utf8.encode(bp.series)) || !_same(b.meta, bp.meta)) {
    throw HoneypotError.wrongBlueprint;
  }
  _checkSoldOut(bp, d.soldOut);
  return d;
}

/// Says a sold out list is possible at all: only items with a cap can sell
/// out, and something must be left to draw.
void _checkSoldOut(Blueprint bp, List<int> soldOut) {
  if (soldOut.length >= bp.items.length) throw HoneypotError.drawField;
  for (var i = 0; i < soldOut.length; i++) {
    final pos = soldOut[i];
    if (pos >= bp.items.length || bp.items[pos].cap == 0 || (i > 0 && pos <= soldOut[i - 1])) throw HoneypotError.drawField;
  }
}

/// The scarcity rule: a capped item has a serial from 1 to its cap.
bool _validSerial(Blueprint bp, Item it, BigInt serial) {
  if (!bp.capped) return serial == BigInt.zero;
  if (it.cap > 0) return serial >= BigInt.one && serial <= BigInt.from(it.cap);
  return serial >= BigInt.one;
}
