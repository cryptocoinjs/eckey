/* global describe, it */
var assert = require('assert')
var secureRandom = require('secure-random')
var ECKey = require('../')

describe('ECKey', function () {
  describe('+ ECKey()', function () {
    describe('> when input is a Buffer', function () {
      it('should create a new ECKey ', function () {
        var buf = secureRandom(32, {type: 'Buffer'})
        var key = new ECKey(buf)
        assert.equal(key.privateKey.toString('hex'), buf.toString('hex'))
        assert.equal(key.compressed, true)
      })
    })

    describe('> when new isnt used', function () {
      it('should create a new ECKey', function () {
        var bytes = secureRandom(32, {type: 'Buffer'})
        var buf = Buffer.from(bytes)
        var key = ECKey(buf)
        assert.equal(key.privateKey.toString('hex'), buf.toString('hex'))

        key = ECKey(buf, true)
        assert(key.compressed)

        key = ECKey(buf, false)
        assert(!key.compressed)
      })
    })

    describe('> when input is an Uint8Array', function () {
      it('should create a new ECKey ', function () {
        var bytes = secureRandom(32, {type: 'Uint8Array'})
        assert(bytes instanceof Uint8Array)

        var key = new ECKey(bytes)
        assert.equal(key.privateKey.toString('hex'), Buffer.from(bytes).toString('hex'))
        assert.equal(key.compressed, true)
      })
    })

    describe('> when input is an Array', function () {
      it('should create a new ECKey ', function () {
        var bytes = secureRandom(32, {type: 'Array'})
        assert(Array.isArray(bytes))

        var key = new ECKey(bytes)
        assert.equal(key.privateKey.toString('hex'), Buffer.from(bytes).toString('hex'))
        assert.equal(key.compressed, true)
      })
    })

    describe('> when compressed is true', function () {
      var key = new ECKey(null, true)
      assert(key.compressed)

      var key2 = new ECKey(secureRandom(32), true)
      assert(key2.compressed)
    })

    describe('> when bad data type', function () {
      it('should throw an error', function () {
        var data = new Uint16Array(16)

        assert.throws(function () {
          return new ECKey(data)
        }, /invalid type/i)
      })
    })
  })

  describe('- compressed', function () {
    describe('> when false to true', function () {
      it('should change privateExportKey and all other affected fields', function () {
        var privateKey = Buffer.from('1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd', 'hex')
        var key = new ECKey(privateKey, false)
        assert(!key.compressed)
        var pubKey = key.publicKey
        assert.notStrictEqual(key.privateExportKey.toString('hex').slice(-2), '01', 'ends with 01')

        key.compressed = true

        assert.notEqual(pubKey.toString('hex'), key.publicKey.toString('hex'))
        assert.strictEqual(key.privateExportKey.toString('hex').slice(-2), '01', 'ends with 01')
      })
    })

    describe('> when true to false', function () {
      it('should change privateExportKey and all other affected fields', function () {
        var privateKey = Buffer.from('1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd', 'hex')
        var key = new ECKey(privateKey, true)
        assert(key.compressed)
        var pubKey = key.publicKey
        assert.strictEqual(key.privateExportKey.toString('hex').slice(-2), '01', 'ends with 01')

        key.compressed = false

        assert.notEqual(pubKey.toString('hex'), key.publicKey.toString('hex'))
        assert.notStrictEqual(key.privateExportKey.toString('hex').slice(-2), '01', 'ends with 01')
      })
    })
  })

  describe('- privateKey', function () {
    it('should return the private key', function () {
      var privateKeyHex = '1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd'
      var key = new ECKey([].slice.call(Buffer.from(privateKeyHex, 'hex')))
      assert.equal(key.privateKey.toString('hex'), privateKeyHex)
    })

    describe('> when length is not 32', function () {
      var key = new ECKey()
      it('should throw an error', function () {
        assert.throws(function () {
          key.privateKey = Buffer.from('ff33', 'hex')
        }, /length of 32/i)
      })
    })
  })

  describe('- privateExportKey', function () {
    describe('> when not compressed', function () {
      it('should return the private key', function () {
        var privateKeyHex = '1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd'
        var key = new ECKey(Buffer.from(privateKeyHex, 'hex'), false)
        assert.equal(key.privateExportKey.toString('hex'), privateKeyHex)
      })
    })

    describe('> when compressed', function () {
      it('should return the private key', function () {
        var privateKeyHex = '1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd'
        var key = new ECKey(Buffer.from(privateKeyHex, 'hex'), true)
        assert.equal(key.compressed, true)
        assert.equal(key.privateExportKey.toString('hex'), privateKeyHex + '01')
      })
    })
  })

  describe('- publicKey', function () {
    describe('> when not compressed', function () {
      it('should return the 65 byte public key', function () {
        var privateKeyHex = '1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd'
        var publicKeyHex = '04d0988bfa799f7d7ef9ab3de97ef481cd0f75d2367ad456607647edde665d6f6fbdd594388756a7beaf73b4822bc22d36e9bda7db82df2b8b623673eefc0b7495'
        var key = new ECKey([].slice.call(Buffer.from(privateKeyHex, 'hex')), false)
        assert.equal(key.publicKey.length, 65)
        assert.equal(key.publicKey.toString('hex'), publicKeyHex)
      })
    })

    describe('> when compressed', function () {
      it('should return the 33 byte public key', function () {
        var privateKeyHex = '1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd'
        var publicKeyHex = '03d0988bfa799f7d7ef9ab3de97ef481cd0f75d2367ad456607647edde665d6f6f'
        var key = new ECKey([].slice.call(Buffer.from(privateKeyHex, 'hex')), true)

        assert(key.compressed)
        assert.equal(key.publicKey.length, 33)
        assert.equal(key.publicKey.toString('hex'), publicKeyHex)
      })
    })
  })

  describe('- publicHash', function () {
    it('should return the hash 160 of public key', function () {
      var key = new ECKey(Buffer.from('1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd', 'hex'), false)
      assert.equal(key.publicHash.toString('hex'), '3c176e659bea0f29a3e9bf7880c112b1b31b4dc8')
      assert.equal(key.pubKeyHash.toString('hex'), '3c176e659bea0f29a3e9bf7880c112b1b31b4dc8')
      key.compressed = true
      assert.equal(key.publicHash.toString('hex'), 'a1c2f92a9dacbd2991c3897724a93f338e44bdc1')
      assert.equal(key.pubKeyHash.toString('hex'), 'a1c2f92a9dacbd2991c3897724a93f338e44bdc1')
    })
  })

  describe('- toString()', function () {
    it('should show the string representation in...', function () {
      var privateKeyBytes = [].slice.call(Buffer.from('1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD', 'hex'))
      var eckey = new ECKey(privateKeyBytes)
      var s = eckey.toString()
      assert.equal(s, '1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd')
    })
  })
})
