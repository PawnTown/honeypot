part of '../honeypot.dart';

/// What a box sealed by hand shows before it is opened.
class Spec {
  const Spec({this.series = '', this.meta = const [], this.props = const {}, required this.size});

  /// Namespace and kind of box, signed, public, fixed.
  final String series;

  /// Anything else public and fixed, opaque to the protocol.
  final List<int> meta;

  /// Public, readable, only the issuer can rewrite them.
  final Map<String, String> props;

  /// Plaintext size, one per series, at least the payload and 2 bytes.
  final int size;
}

/// The state that signatures and derivation cannot provide: who claimed which
/// box, and which revision is current. Open keys are not stored; this is one
/// row per box that was rewritten or opened. Either method may return a
/// [Future].
abstract interface class Ledger {
  /// Atomically records [owner] for the box and returns the owner on record,
  /// which is an earlier one if a claim exists. Throws [HoneypotError.stale],
  /// and records nothing, if a revision above [revision] is on record.
  FutureOr<String> claim(Uint8List id, int revision, String owner);

  /// Atomically raises the revision on record above both its current value and
  /// [revision], and returns it. A box never rewritten is at revision 0.
  FutureOr<int> advance(Uint8List id, int revision);
}

/// Holds a main key: it seals and draws boxes, rewrites their properties and
/// derives their open keys.
class Issuer {
  Issuer._(this.keyId, this.signSeed, this.openRoot, this.publicKey, this._secretKey);

  /// Splits a main key, 32 bytes from a CSPRNG, into the signing key and the
  /// root of the open keys (spec "Keys"). [keyId] names the main key in its
  /// boxes, so it can be rotated.
  factory Issuer(int keyId, List<int> main) {
    RangeError.checkValueInInterval(keyId, 0, 255, 'keyId');
    if (main.length != keySize) throw HoneypotError.keySize;
    final seed = _kdf(main, _tagSign);
    final (pk, sk) = MlDsa.generateKeyPairSeeded(DilithiumParams.mlDsa65, seed);
    return Issuer._(keyId, seed, _kdf(main, _tagRoot), pk, sk);
  }

  final int keyId;

  /// The ML-DSA-65 seed. Secret: it signs boxes.
  final Uint8List signSeed;

  /// The root of the open keys. Secret, until an audit publishes it (spec
  /// "Audit").
  final Uint8List openRoot;

  /// The public key verifiers pin under [keyId].
  final Uint8List publicKey;
  final Uint8List _secretKey;

  /// The keys to verify this issuer's boxes with.
  Map<int, Uint8List> get keys => {keyId: publicKey};

  /// ML-DSA-65, deterministic: one box at one revision has one signature.
  Uint8List sign(Uint8List msg) => MlDsa.signDeterministic(_secretKey, msg, DilithiumParams.mlDsa65);

  Uint8List signBox(Box b) => sign(b.signed);

  Uint8List signTicket(Ticket t) => sign(t.signed);

  /// The open key of a box. It is not stored anywhere and is the same every
  /// time. It answers for any box, so never expose it without a check that the
  /// caller may have the key: that is [release].
  Uint8List key(Box b) => _kdf(openRoot, _tagKey, [b.keyInput]);

  /// Creates a box at revision 0. [entropy] is 32 bytes, from the CSPRNG unless
  /// given. The nonce comes from the plaintext as well, so a broken RNG can
  /// repeat a box but never reuse an open key for a second plaintext.
  Box seal(Spec spec, List<int> payload, {List<int>? entropy}) {
    final series = utf8.encode(spec.series);
    if (series.length > 255 || spec.meta.length > 65535) throw HoneypotError.tooLong;
    _checkProps(spec.props);
    final plain = _pad(payload, spec.size);
    final b = Box(
      keyId: keyId,
      series: series,
      meta: Uint8List.fromList(spec.meta),
      nonce: Uint8List(16),
      keyCommit: Uint8List(32),
      ciphertext: Uint8List(0),
      props: Map.of(spec.props),
      sig: Uint8List(0),
    );
    return _close(b.copyWith(nonce: _kdf(openRoot, _tagNonce, [_entropy(entropy), b.prefix, plain]).sublist(0, 16)), plain);
  }

  /// Commits to the open key, encrypts [plain] and signs: the box with its
  /// header in place, done.
  Box _close(Box b, Uint8List plain) {
    final openKey = key(b);
    final sealed = b.copyWith(keyCommit: _kdf(openKey, _tagCommit), ciphertext: _aead(true, openKey, b.keyInput, plain));
    return sealed.copyWith(sig: signBox(sealed));
  }

  /// An unsigned ticket. The nonce leaves out the plaintext, which does not
  /// exist yet; one input gives one plaintext, so a key still encrypts only one
  /// thing. It fixes what is sold out now, before anyone can know the result.
  Future<Ticket> prepare(Blueprint bp, List<int> inputCommit, {Map<String, String> props = const {}, Caps? caps, List<int>? entropy}) async {
    bp._check();
    _checkProps(props);
    final id = bp.id;
    final soldOut = <int>[];
    if (bp.capped) {
      if (caps == null) throw HoneypotError.noCaps;
      final gone = await caps.soldOut(id);
      for (var i = 0; i < bp.items.length; i++) {
        if (bp.items[i].cap > 0 && gone.contains(bp.items[i].id)) soldOut.add(i);
      }
      if (soldOut.length == bp.items.length) throw HoneypotError.soldOut;
    }
    final draft = Ticket(
      keyId: keyId,
      series: utf8.encode(bp.series),
      meta: bp.meta,
      blueprintId: id,
      inputCommit: Uint8List.fromList(inputCommit),
      soldOut: List.unmodifiable(soldOut),
      nonce: Uint8List(16),
      keyCommit: Uint8List(32),
      props: Map.of(props),
      sig: Uint8List(0),
    );
    final t = draft.copyWith(nonce: _kdf(openRoot, _tagNonce, [_entropy(entropy), draft._box.prefix]).sublist(0, 16));
    return t.copyWith(keyCommit: _kdf(key(t._box), _tagCommit));
  }

  /// Answers a player's commitment with a signed promise of one box. It holds no
  /// state. Each ticket is one box, so give out one per purchase. [props] are
  /// the box's properties at revision 0. [caps] may be null if the blueprint
  /// has no caps.
  Future<Ticket> ticket(Blueprint bp, List<int> inputCommit, {Map<String, String> props = const {}, Caps? caps, List<int>? entropy}) async {
    final t = await prepare(bp, inputCommit, props: props, caps: caps, entropy: entropy);
    return t.copyWith(sig: signTicket(t));
  }

  /// Fills the box a ticket promised, without checking the ticket. The same
  /// ticket and input always give the same box. Every draw of a capped
  /// blueprint takes a serial, whatever the item, so the time it takes does not
  /// tell a capped item from any other.
  Future<Box> fill(Ticket t, Blueprint bp, List<int> input, {Caps? caps}) async {
    final promised = t._box;
    final b = promised.copyWith(draw: promised.draw!.withInput(Uint8List.fromList(input)));
    final openKey = key(b);
    final item = bp.pick(openKey, input, t.soldOut);
    var serial = BigInt.zero;
    if (bp.capped) {
      if (caps == null) throw HoneypotError.noCaps;
      final taken = await caps.take(t.blueprintId, item.id, item.cap, b.keyInput);
      if (taken == null) throw HoneypotError.soldOut;
      serial = taken;
    }
    return _close(b, _pad(_cat([_u64(serial), utf8.encode(item.id)]), bp.size));
  }

  /// Turns a ticket and the player's input into the box. The commitment admits
  /// one input, and asking again returns the same box, so a retry is safe and a
  /// ticket cannot give two boxes. With caps, an item that sold out since the
  /// ticket throws [HoneypotError.soldOut], and the ticket is refunded.
  Future<Box> redeem(Ticket t, Blueprint bp, List<int> input, {Caps? caps}) async {
    _verifyFrom(keys, t.keyId, t.signed, t.sig);
    _checkBlueprintOf(t._box, bp);
    if (!_same(_commitInput(input), t.inputCommit)) throw HoneypotError.input;
    return fill(t, bp, input, caps: caps);
  }

  /// Creates a box with an item drawn from the blueprint, in one call, with no
  /// player involved. The odds are exact and nobody without the main key can
  /// predict the item, but the issuer is trusted not to mint again until it
  /// likes the result. When a player is there to take part, use [ticket] and
  /// [redeem] instead. An item that sells out during the call is left out of a
  /// new draw.
  Future<Box> mint(Blueprint bp, {Map<String, String> props = const {}, Caps? caps}) async {
    // Each new try has one more item sold out, so this many are enough.
    for (var i = 0; i <= bp.items.length; i++) {
      final req = newDrawRequest();
      final t = await prepare(bp, req.commit, props: props, caps: caps);
      try {
        return await fill(t, bp, req.input, caps: caps);
      } catch (e) {
        if (e != HoneypotError.soldOut) rethrow;
      }
    }
    throw HoneypotError.soldOut;
  }

  /// Replaces the properties of a box and returns its next revision. The
  /// contents, the id and the open key stay the same. It takes the whole new set
  /// of properties, and any earlier revision of the box as its base: after a
  /// lost response, rewriting again just takes the next revision.
  Future<Box> rewrite(Ledger l, Box b, Map<String, String> props) async {
    b.verify(keys);
    _checkProps(props);
    final next = b.copyWith(revision: await l.advance(b.id, b.revision), props: Map.of(props));
    return next.copyWith(sig: signBox(next));
  }

  /// Gives [owner] the open key of a box the first time it is claimed, and
  /// again only to the same owner, so a retry after a lost response is safe. A
  /// box with a userId goes to that user only, and an old revision is refused,
  /// so a previous owner cannot come back with the copy they kept.
  Future<Uint8List> release(Ledger l, Box b, String owner) async {
    b.verify(keys);
    final user = b.props[propUser];
    if (user != null && user != owner) throw HoneypotError.notOwner;
    if (await l.claim(b.id, b.revision, owner) != owner) throw HoneypotError.claimed;
    return key(b);
  }
}

Uint8List _entropy(List<int>? given) {
  final e = given ?? randomBytes(32);
  if (e.length != 32) throw ArgumentError.value(e.length, 'entropy', 'must be 32 bytes');
  return Uint8List.fromList(e);
}
