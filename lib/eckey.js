var ECPointFp = require('ecurve').ECPointFp;
var ecparams = require('ecurve-names')('secp256k1');
var hashing = require('crypto-hashing');
var sha256 = hashing.sha256;
var convertHex = require('convert-hex');
var Address = require('btc-address');
var ecdsa = require('ecdsa');
var BigInteger = require('bigi');
var base58 = require('bs58');
  
module.exports = ECKey

var networkTypes = {
  prod: 128,
  testnet: 239
};


function ECKey (bytes, compressed) {
  if (!(this instanceof ECKey)) return new ECKey(input);

  if (bytes && (Array.isArray(bytes) || Buffer.isBuffer(bytes) || bytes instanceof Uint8Array)) //temporary
    this.privateKey = bytes; 

  this.compressed = compressed || !!ECKey.compressByDefault;

  var input = bytes;

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

  this.compressed = this.compressed || compressed || false; //temporary
}

/********************
 * GET/SET PROPERTIES
 ********************/

Object.defineProperty(ECKey.prototype, 'privateKey', {
  get: function() {
    return this.key;
  },
  set: function(bytes) {
    var byteArr;
    if (Buffer.isBuffer(bytes)) {
      this.key = bytes;
      byteArr = [].slice.call(bytes);
    } else if (bytes instanceof Uint8Array) {
      byteArr = [].slice.call(bytes);
      this.key = new Buffer(byteArr);
    } else if (Array.isArray(bytes)) {
      byteArr = bytes;
      this.key = new Buffer(byteArr);
    } else {
      throw new Error('bytes must be either a Buffer, Array, or Uint8Array.')
    }

    //only used if compressed is true
    this.compressedKey = Buffer.concat([ this.key, new Buffer([0x01]) ]);

    this.keyBigInteger = BigInteger.fromByteArrayUnsigned(byteArr);
  }
})

Object.defineProperty(ECKey.prototype, 'publicKey', {
  get: function() {
    return new Buffer(this.getPub());
  }
})

/*Object.defineProperty(ECKey.prototype, 'compressed', {
  get: function() {
    return this._compressed;
  }, 
  set: function(val) {
    this_compressed = val;
  }
})*/

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
  var shit = this.getPubPoint().getEncoded(this.compressed);
  //console.log(shit.length)
  //console.log(shit.join(', '));
  //process.exit();
  return shit;
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

  return this.pubKeyHash = hashing.sha256ripe160(this.getPub(), {in: 'bytes', out: 'bytes'});
};

ECKey.prototype.getAddress = function (address_type) {
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
  var checksum = sha256.x2(hash, {in: 'bytes', out: 'bytes'});
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
    throw "Checksum validation failed";
  }

  var hash = bytes.slice(0, 33);
  var version = hash.shift();

  if (version !== expectedVersion)
    throw "Version "+version+" not expected, expected " + expectedVersion + "!";

  return hash;
};



