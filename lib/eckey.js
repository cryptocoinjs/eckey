var crypto = require('crypto')

var ecurve = require('ecurve')
var ecparams = ecurve.getCurveByName('secp256k1')
var BigInteger = require('bigi')

function ECKey (bytes, compressed) {
  if (!(this instanceof ECKey)) return new ECKey(bytes, compressed)

  if (typeof compressed == 'boolean')
    this._compressed = compressed
  else
    this._compressed = true

  if (bytes)
    this.privateKey = bytes 
}

/********************
 * GET/SET PROPERTIES
 ********************/

Object.defineProperty(ECKey.prototype, 'privateKey', {
  enumerable: true, configurable: true,
  get: function() {
    return this.key
  },
  set: function(bytes) {
    var byteArr
    if (Buffer.isBuffer(bytes)) {
      this.key = bytes
      byteArr = [].slice.call(bytes)
    } else if (bytes instanceof Uint8Array) {
      byteArr = [].slice.call(bytes)
      this.key = new Buffer(byteArr)
    } else if (Array.isArray(bytes)) {
      byteArr = bytes
      this.key = new Buffer(byteArr)
    } else {
      throw new Error('Invalid type. private key bytes must be either a Buffer, Array, or Uint8Array.')
    }

    if (bytes.length != 32)
      throw new Error("private key bytes must have a length of 32")

    //_exportKey => privateKey + (0x01 if compressed)
    if (this._compressed)
      this._exportKey = Buffer.concat([ this.key, new Buffer([0x01]) ])
    else
      this._exportKey = Buffer.concat([ this.key ]) //clone key as opposed to passing a reference (relevant to Node.js only)

    this.keyBigInteger = BigInteger.fromByteArrayUnsigned(byteArr)

    //reset
    this._publicPoint = null
    this._pubKeyHash = null
  }
})

Object.defineProperty(ECKey.prototype, 'privateExportKey', {
  get: function() {
    return this._exportKey
  }
})

Object.defineProperty(ECKey.prototype, 'publicHash', {
  get: function() {
    return this.pubKeyHash
  }
})

Object.defineProperty(ECKey.prototype, 'pubKeyHash', {
  get: function() {
    if (this._pubKeyHash) return this._pubKeyHash
    var sha = crypto.createHash('sha256').update(this.publicKey).digest()
    this._pubKeyHash = crypto.createHash('rmd160').update(sha).digest()
    return this._pubKeyHash
  }
})

Object.defineProperty(ECKey.prototype, 'publicKey', {
  get: function() {
    return new Buffer(this.publicPoint.getEncoded(this.compressed))
  }
})

Object.defineProperty(ECKey.prototype, 'publicPoint', {
  get: function() {
    if (!this._publicPoint) {
      this._publicPoint = ecparams.G.multiply(this.keyBigInteger)
    } 
    return this._publicPoint
  }
})

Object.defineProperty(ECKey.prototype, 'compressed', {
  get: function() {
    return this._compressed
  }, 
  set: function(val) {
    var c = !!val
    if (c === this._compressed) return
    
    //reset key stuff
    var pk = this.privateKey
    this._compressed = c
    this.privateKey = pk
  }
})

/************
 * METHODS
 ************/

ECKey.prototype.toString = function (format) {
  return this.privateKey.toString('hex')
}

module.exports = ECKey

