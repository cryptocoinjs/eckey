var ECKey = require('../lib/eckey')
var conv = require('binstring') 
var secureRandom = require('secure-random')

require('terst')
var assert = require('assert')

describe('ECKey', function() {
  describe('+ ECKey()', function() {
    describe('> when input is a Buffer', function() {
      it('should create a new ECKey ', function() {
        var bytes = secureRandom(32);
        T (bytes instanceof Uint8Array);
        F (Array.isArray(bytes));
        bytes = [].slice.call(bytes);
        T (Array.isArray(bytes));
        var buf = new Buffer(bytes);

        var key = new ECKey(buf);
        EQ (key.privateKey.toString('hex'), conv(bytes, {out: 'hex'}));
        EQ (key.compressed, false);
      })
    })

    describe('> when new isnt used', function() {
      it('should create a new ECKey', function() {
        var bytes = secureRandom(32);
        var buf = new Buffer(bytes);
        var key = ECKey(buf);
        EQ (key.privateKey.toString('hex'), buf.toString('hex'));
      })
    })

    describe('> when input is an Uint8Array', function() {
      it('should create a new ECKey ', function() {
        var bytes = secureRandom(32);
        T (bytes instanceof Uint8Array);

        var key = new ECKey(bytes);
        EQ (key.privateKey.toString('hex'), conv([].slice.call(bytes), {out: 'hex'}));
        EQ (key.compressed, false);
      })
    })

    describe('> when input is an Array', function() {
      it('should create a new ECKey ', function() {
        var bytes = secureRandom(32, {array: true});
        T (Array.isArray(bytes));

        var key = new ECKey(bytes);
        EQ (key.privateKey.toString('hex'), conv(bytes, {out: 'hex'}));
        EQ (key.compressed, false);
      })
    })

    describe('> when compressed is true', function() {
      var key = new ECKey(null, true);
      T (key.compressed);

      var key2 = new ECKey(secureRandom(32), true);
      T (key2.compressed);
    })
  })

  describe('- privateKey', function() {
    it('should return the private key', function() {
      var privateKeyHex = "1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd";
      var key = new ECKey(conv(privateKeyHex, {in: 'hex', out: 'bytes'}));
      EQ (key.privateKey.toString('hex'), privateKeyHex);
    })
  })

  describe('- privateExportKey', function() {
    describe('> when not compressed', function() {
      it('should return the private key', function() {
        var privateKeyHex = "1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd";
        var key = new ECKey(conv(privateKeyHex, {in: 'hex', out: 'buffer'}), false);
        EQ (key.privateExportKey.toString('hex'), privateKeyHex);
      })
    })

    describe('> when compressed', function() {
      it('should return the private key', function() {
        var privateKeyHex = "1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd";
        var key = new ECKey(conv(privateKeyHex, {in: 'hex', out: 'buffer'}), true);
        EQ (key.compressed, true);
        EQ (key.privateExportKey.toString('hex'), privateKeyHex + "01");
      })
    })
  })

  describe('- publicKey', function() {
    describe('> when not compressed', function() {
      it('should return the 65 byte public key', function() {
        var privateKeyHex = "1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd";
        var publicKeyHex = "04d0988bfa799f7d7ef9ab3de97ef481cd0f75d2367ad456607647edde665d6f6fbdd594388756a7beaf73b4822bc22d36e9bda7db82df2b8b623673eefc0b7495";
        var key = new ECKey(conv(privateKeyHex, {in: 'hex', out: 'bytes'}), false);
        EQ (key.publicKey.length, 65);
        EQ (key.publicKey.toString('hex'), publicKeyHex);
      })
    })

    describe('> when compressed', function() {
      it('should return the 33 byte public key', function() {
        var privateKeyHex = "1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd";
        var publicKeyHex = "03d0988bfa799f7d7ef9ab3de97ef481cd0f75d2367ad456607647edde665d6f6f";
        var key = new ECKey(conv(privateKeyHex, {in: 'hex', out: 'bytes'}), true);

        T (key.compressed);
        EQ (key.publicKey.length, 33);
        EQ (key.publicKey.toString('hex'), publicKeyHex);
      })
    })
  })

  describe('- publicPoint', function() {
    it('should return the point object', function() {
      var privateKeyHex = "1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd";
      var key = new ECKey(conv(privateKeyHex, {in: 'hex', out: 'bytes'}), false);
      T (key.publicPoint);
    })
  })


  describe('- toString()', function() {
    it('should show the string representation in...', function() {
      var privateKeyBytes = conv("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD", {in: 'hex', out: 'bytes'})
      var eckey = new ECKey(privateKeyBytes)
      var s = eckey.toString()
      EQ (s, '1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd')
    })
  })



});
