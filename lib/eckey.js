!function(globals) {
'use strict'

//*** IMPORTS
var BigInteger = null
var ECPointFp = null
var ecparams = null
var base58 = null
var sha256 = null
var ripe160 = null
var convertHex = null
var Address = null
var ecdsa = null
//*** IMPORTS END

if (typeof module !== 'undefined' && module.exports) { //CommonJS
  ECPointFp = require('ecurve').ECPointFp
  ecparams = require('ecurve-names')('secp256k1')
  sha256 = require('sha256')
  ripe160 = require('ripemd160')
  convertHex = require('convert-hex')
  Address = require('btc-address')
  ecdsa = require('ecdsa')
  BigInteger = require('bigi')
  base58 = require('bs58')
  module.exports = ECKey
} else {
  BigInteger = globals.BigInteger
  ECPointFp = globals.ECCurveFp.ECPointFp
  ecparams = globals.getSECCurveByName('secp256k1')
  base58 = globals.bs58
  sha256 = globals.sha256
  ripe160 = globals.ripemd160
  convertHex = globals.convertHex
  Address = globals.Address
  ecdsa = globals.ECDSA
  globals.ECKey = ECKey
}
//*** UMD END

var util = {
  sha256ripe160: function(bytes) {
    return ripe160(sha256(bytes, {asBytes: true}), {asBytes: true})
  }
}


var networkTypes = {
  prod: 128,
  testnet: 239
};

// input can be nothing, array of bytes, hex string, or base58 string
function ECKey (input) {
  if (!(this instanceof ECKey)) {
    return new ECKey(input);
  }

  this.compressed = !!ECKey.compressByDefault;

  if (!input) {
    // Generate new key
    var n = ecparams.getN();
    this.priv = ecdsa.getBigRandom(n);
  } else if (input instanceof BigInteger) {
    // Input is a private key value
    this.priv = input;
  } else if (Array.isArray(input)) {
    // Prepend zero byte to prevent interpretation as negative integer
    this.priv = BigInteger.fromByteArrayUnsigned(input);
    this.compressed = false;
  } else if ("string" == typeof input) {
    // A list of base58 encoded prefixes is at https://en.bitcoin.it/wiki/List_of_address_prefixes.
    if (input.length == 51 && input[0] == '5') {
      // Base58 encoded private key
      this.priv = BigInteger.fromByteArrayUnsigned(ECKey.decodeString(input, networkTypes.prod));
      this.compressed = false;
    }
    else if (input.length == 51 && input[0] == '9') {
      this.priv = BigInteger.fromByteArrayUnsigned(ECKey.decodeString(input, networkTypes.testnet));
      this.compressed = false;
    }
    else if (input.length == 52 && (input[0] === 'K' || input[0] === 'L')) {
      // Base58 encoded private key
      this.priv = BigInteger.fromByteArrayUnsigned(ECKey.decodeString(input, networkTypes.prod));
      this.compressed = true;
    }
    else if (input.length == 52 && input[0] === 'c') {
      // Base58 encoded private key
      this.priv = BigInteger.fromByteArrayUnsigned(ECKey.decodeString(input, networkTypes.testnet));
      this.compressed = true;
    }
  }
};

// TODO(shtylman) methods
// wallet import format (base58 check with meta info)
// fromWIF
// toWIF
// fromBytes
// toBytes
// fromHex
// toHex

/**
 * Whether public keys should be returned compressed by default.
 */
ECKey.compressByDefault = false;

/**
 * Set whether the public key should be returned compressed or not.
 */
ECKey.prototype.setCompressed = function (v) {
  this.compressed = !!v;
};

/**
 * Return public key in DER encoding.
 */
ECKey.prototype.getPub = function () {
  return this.getPubPoint().getEncoded(this.compressed);
};

/**
 * Return public point as ECPoint object.
 */
ECKey.prototype.getPubPoint = function () {
  if (!this.pub) this.pub = ecparams.getG().multiply(this.priv);

  return this.pub;
};

/**
 * Get the pubKeyHash for this key.
 *
 * This is calculated as RIPE160(SHA256([encoded pubkey])) and returned as
 * a byte array.
 */
ECKey.prototype.getPubKeyHash = function () {
  if (this.pubKeyHash) return this.pubKeyHash;

  return this.pubKeyHash = util.sha256ripe160(this.getPub());
};

ECKey.prototype.getBitcoinAddress = function (address_type) {
  var hash = this.getPubKeyHash();
  var addr = new Address(hash, address_type);
  return addr;
};

ECKey.prototype.getExportedPrivateKey = function (bitcoinNetwork) {
  bitcoinNetwork = bitcoinNetwork || 'prod';
  var hash = this.priv.toByteArrayUnsigned();
  while (hash.length < 32) hash.unshift(0);
  if (this.compressed) hash.push(0x01);
  hash.unshift(networkTypes[bitcoinNetwork]);
  var checksum = sha256.x2(hash, {asBytes: true})
  var bytes = hash.concat(checksum.slice(0,4));
  return base58.encode(bytes);
};

ECKey.prototype.setPub = function (pub) {
  this.pub = ECPointFp.decodeFrom(ecparams.getCurve(), pub);
};

ECKey.prototype.toString = function (format) {
  return convertHex.bytesToHex(this.priv.toByteArrayUnsigned());
};

ECKey.prototype.sign = function (hash) {
  return ecdsa.sign(hash, this.priv);
};

ECKey.prototype.verify = function (hash, sig) {
  return ecdsa.verify(hash, sig, this.getPub());
};


/// THIS METHOD WAS ORIGINALLY IN ECDSA

  /**
   * Recover a public key from a signature.
   *
   * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
   * Key Recovery Operation".
   *
   * http://www.secg.org/download/aid-780/sec1-v2.pdf
   */
ECKey.recoverPubKey = function (r, s, hash, i) {
    // The recovery parameter i has two bits.
    i = i & 3;

    // The less significant bit specifies whether the y coordinate
    // of the compressed point is even or not.
    var isYEven = i & 1;

    // The more significant bit specifies whether we should use the
    // first or second candidate key.
    var isSecondKey = i >> 1;

    var n = ecparams.getN();
    var G = ecparams.getG();
    var curve = ecparams.getCurve();
    var p = curve.getQ();
    var a = curve.getA().toBigInteger();
    var b = curve.getB().toBigInteger();

    // We precalculate (p + 1) / 4 where p is if the field order
    if (!P_OVER_FOUR) {
      P_OVER_FOUR = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
    }

    // 1.1 Compute x
    var x = isSecondKey ? r.add(n) : r;

    // 1.3 Convert x to point
    var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
    var beta = alpha.modPow(P_OVER_FOUR, p);

    var xorOdd = beta.isEven() ? (i % 2) : ((i+1) % 2);
    // If beta is even, but y isn't or vice versa, then convert it,
    // otherwise we're done and y == beta.
    var y = (beta.isEven() ? !isYEven : isYEven) ? beta : p.subtract(beta);

    // 1.4 Check that nR is at infinity
    var R = new ECPointFp(curve,
                          curve.fromBigInteger(x),
                          curve.fromBigInteger(y));
    R.validate();

    // 1.5 Compute e from M
    var e = BigInteger.fromByteArrayUnsigned(hash);
    var eNeg = BigInteger.ZERO.subtract(e).mod(n);

    // 1.6 Compute Q = r^-1 (sR - eG)
    var rInv = r.modInverse(n);
    var Q = implShamirsTrick(R, s, G, eNeg).multiply(rInv);

    Q.validate();
    if (!ECDSA.verifyRaw(e, r, s, Q)) {
      throw new Error("Pubkey recovery unsuccessful");
    }

    var pubKey = ECKey();
    pubKey.pub = Q;
    return pubKey;
}


/**
 * Parse an exported private key contained in a string.
 */
ECKey.decodeString = function (string, expectedVersion) {
  var bytes = base58.decode(string);

  if (bytes.length !== 37 && bytes.length !== 38) {
    throw new Error('not a valid base58 encoded private key');
  }

  //Format:
  //* uncompressed: 0x80 + [32-byte secret] + [4 bytes of Hash() of
  //previous 33 bytes], base58 encoded
  //* compressed: 0x80 + [32-byte secret] + 0x01 + [4 bytes of Hash()
  //previous 34 bytes], base58 encoded
  var checkSumPos = 33
  if (bytes[33] === 0x01) {
    // compressed
    checkSumPos += 1
  }

  var checkSumBytes = bytes.slice(0, checkSumPos);
  var checksum = sha256.x2(checkSumBytes, {asBytes: true});
  if (checksum[0] != bytes[checkSumPos] ||
      checksum[1] != bytes[checkSumPos+1] ||
      checksum[2] != bytes[checkSumPos+2] ||
      checksum[3] != bytes[checkSumPos+3]) {
    throw "Checksum validation failed!";
  }

  var hash = bytes.slice(0, 33);
  var version = hash.shift();

  if (version !== expectedVersion)
    throw "Version "+version+" not expected, expected " + expectedVersion + "!";

  return hash;
};


}(this);
