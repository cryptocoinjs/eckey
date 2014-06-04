var ecurve = require('ecurve')
var ECPointFp = ecurve.ECPointFp
var ecparams = ecurve.getECParams('secp256k1')
var BigInteger = require('bigi'); //you were going to upgrade this
  
module.exports = ECKey


function ECKey (bytes, compressed) {
  if (!(this instanceof ECKey)) return new ECKey(bytes, compressed);

  if (typeof compressed == 'boolean')
    this._compressed = compressed
  else
    this._compressed = false

  if (bytes)
    this.privateKey = bytes; 
}

/********************
 * STATIC PROPERTIES
 ********************/

ECKey.compressByDefault = false;

/********************
 * GET/SET PROPERTIES
 ********************/

Object.defineProperty(ECKey.prototype, 'privateKey', {
  enumerable: true, configurable: true,
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
      throw new Error('private key bytes must be either a Buffer, Array, or Uint8Array.');
    }

    if (bytes.length != 32)
      throw new Error("private key bytes must have a length of 32");

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

Object.defineProperty(ECKey.prototype, 'publicPoint', {
  get: function() {
    if (!this._publicPoint) {
      this._publicPoint = ecparams.g.multiply(this.keyBigInteger);
    } 
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


/************
 * METHODS
 ************/

/*ECKey.prototype.setPub = function (pub) {
  this.pub = ECPointFp.decodeFrom(ecparams.getCurve(), pub);
};*/

ECKey.prototype.toString = function (format) {
  return this.privateKey.toString('hex');
}









