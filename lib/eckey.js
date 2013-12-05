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
  try { //Node.js
    BigInteger = require('cryptocoin-bigint')
    base58 = require('cryptocoin-base58')
  } catch (e) { //Component
    BigInteger = require('bigint')
    base58 = require('base58')
  }
  module.exports = ECKey
} else {
  BigInteger = globals.BigInteger
  ECPointFp = globals.ECCurveFp.ECPointFp
  ecparams = globals.getSECCurveByName('secp256k1')
  base58 = globals.base58
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

  if (bytes[33] === 0x01) {
    // compressed
  }

  var hash = bytes.slice(0, 33);

  /*
  var checksum = Crypto.SHA256(Crypto.SHA256(hash, {asBytes: true}), {asBytes: true});

  if (checksum[0] != bytes[33] ||
      checksum[1] != bytes[34] ||
      checksum[2] != bytes[35] ||
      checksum[3] != bytes[36]) {
    throw "Checksum validation failed!";
  }
  */

  var version = hash.shift();

  if (version !== expectedVersion)
    throw "Version "+version+" not expected, expected " + expectedVersion + "!";

  return hash;
};


}(this);
