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

  this._compressed = compressed || !!ECKey.compressByDefault;

  if (bytes && (Array.isArray(bytes) || Buffer.isBuffer(bytes) || bytes instanceof Uint8Array)) //temporary
    this.privateKey = bytes; 

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

  this._compressed = this._compressed || compressed || false; //temporary
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

    //_exportKey => privateKey + (0x01 if compressed)
    if (this._compressed)
      this._exportKey = Buffer.concat([ this.key, new Buffer([0x01]) ]);
    else
      this._exportKey = Buffer.concat([ this.key ]); //clone key as opposed to passing a reference (relevant to Node.js only)

    this.keyBigInteger = BigInteger.fromByteArrayUnsigned(byteArr);

    //reset
    this._publicPoint = null;
    this._pubKeyHash = null;
  }
})

Object.defineProperty(ECKey.prototype, 'privateExportKey', {
  get: function() {
    return this._exportKey;
  }
})

Object.defineProperty(ECKey.prototype, 'publicKey', {
  get: function() {
    return new Buffer(this.publicPoint.getEncoded(this.compressed));
  }
})

Object.defineProperty(ECKey.prototype, 'pubKeyHash', {
  get: function() {
    //return new Buffer(this.getPubKeyHash()); 
    if (!this._pubKeyHash)
      this._pubKeyHash = hashing.sha256ripe160(this.publicKey, {in: 'buffer', out: 'buffer'}); //sha256ripe160 should default on buffer, fix
    return this._pubKeyHash;
  }
})

Object.defineProperty(ECKey.prototype, 'publicHash', {
  get: function() {
    return this.pubKeyHash;
  }
})

Object.defineProperty(ECKey.prototype, 'publicPoint', {
  get: function() {
    if (!this._publicPoint)
      this._publicPoint = ecparams.getG().multiply(this.keyBigInteger);
    return this._publicPoint;
  }
})

Object.defineProperty(ECKey.prototype, 'compressed', {
  get: function() {
    return this._compressed;
  }, 
  set: function(val) {
    var c = !!val;
    if (c === this._compressed) return;
    
    //reset key stuff
    var pk = this.privateKey;
    this._compressed = c;
    this.privateKey = pk;
  }
})



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





/*ECKey.prototype.setPub = function (pub) {
  this.pub = ECPointFp.decodeFrom(ecparams.getCurve(), pub);
};*/

ECKey.prototype.toString = function (format) {
  return this.privateKey.toString('hex');
}









