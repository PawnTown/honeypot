/// The Honeypot protocol (spec/HONEYPOT.md): post-quantum safe lootboxes whose
/// contents are fixed at creation and readable only with a key.
///
/// Blueprints with exact odds and the draw that picks from them, verifying a
/// box against the issuer's public key or an open key, public properties only
/// the issuer can rewrite, opening, and the issuer's side: the main key,
/// sealing, tickets, rewrites and the one-time release.
///
/// Byte-for-byte pinned to the Go library by the vectors in ../vectors.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/api.dart' show AEADParameters, InvalidCipherTextException, KeyParameter;
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/gcm.dart';
import 'package:pqcrypto/pqcrypto.dart' show DilithiumParams, MlDsa;

part 'src/blueprint.dart';
part 'src/box.dart';
part 'src/bytes.dart';
part 'src/draw.dart';
part 'src/issuer.dart';
part 'src/memory.dart';
