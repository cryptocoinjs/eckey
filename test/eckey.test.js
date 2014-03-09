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

  describe('- publicHash', function() {
    describe('> when not compressed', function() {
      it('should return the 160 bit hash of the uncompressed public key', function() {
        var privateKeyHex = "1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd";
        var hash160Hex = "3c176e659bea0f29a3e9bf7880c112b1b31b4dc8";
        var key = new ECKey(conv(privateKeyHex, {in: 'hex', out: 'bytes'}), false);
        EQ (key.publicHash.toString('hex'), hash160Hex);
        EQ (key.pubKeyHash.toString('hex'), hash160Hex);
      })
    })

    describe('> when compressed', function() {
      it('should return the 160 bit hash of the compressed public key', function() {
        var privateKeyHex = "1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd";
        var hash160Hex = "a1c2f92a9dacbd2991c3897724a93f338e44bdc1";
        var key = new ECKey(conv(privateKeyHex, {in: 'hex', out: 'bytes'}), true);
        EQ (key.publicHash.toString('hex'), hash160Hex);
        EQ (key.pubKeyHash.toString('hex'), hash160Hex);
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


  describe('- getBitcoinAddress()', function() {
    describe('> when not compressed', function() {
      it('should generate the address of the uncompressed public key', function() {
        var privateKeyBytes = conv("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD", {in: 'hex', out: 'bytes'})
        var eckey = new ECKey(privateKeyBytes)
        var address = eckey.getAddress().toString()
        EQ (address, "16UjcYNBG9GTK4uq2f7yYEbuifqCzoLMGS")
      })
    })

    describe('> when compressed', function() {
      it('should generate the address of the compressed public key', function() {
         var privateKeyBytes = conv("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD", {in: 'hex', out: 'bytes'})
        var eckey = new ECKey(privateKeyBytes)
        eckey.compressed = true
        var address = eckey.getAddress().toString()
        EQ (address, "1FkKMsKNJqWSDvTvETqcCeHcUQQ64kSC6s")
      })
    })
  })


  describe('> toString()', function() {
    it('should show the string representation in...', function() {
      var privateKeyBytes = conv("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD", {in: 'hex', out: 'bytes'})
      var eckey = new ECKey(privateKeyBytes)
      var s = eckey.toString()
      EQ (s, '1184cd2cdd640ca42cfc3a091c51d549b2f016d454b2774019c2b2d2e08529fd')
    })
  })

  describe('- getExportedPrivateKey()', function() {
    describe('> when private key is uncompressed', function() {
      it('should return uncompressed private key', function() {
        var priv_uncompressed = '5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh';
        var eckey = new ECKey(priv_uncompressed);
        EQ(eckey.getExportedPrivateKey(), priv_uncompressed);
      });
    });
    describe('> when private key is compressed', function() {
      it('should return compressed private key', function() {
        var priv_compressed = 'KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp';
        var eckey = new ECKey(priv_compressed);
        EQ(eckey.getExportedPrivateKey(), priv_compressed);
      });
    });
  });

  describe('- decodeString()', function() {
    describe('> when private key is uncompressed', function() {
      it('should throw an error if checksum of uncompressed key is bad', function() {
        assert.throws(function() {
          var eckey = new ECKey('5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC111kLqaW');
        }, function(err) {
          if (/Checksum validation failed/.test(err)) {
            return true
          }
        });
      });
    })

    describe('> when private key is uncompressed', function() {
      it('should throw an error if checksum of compressed key is bad', function() {
        assert.throws(function() {
          var eckey = new ECKey('KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZeDYahL');
        }, function(err) {
          if (/Checksum validation failed/.test(err)) {
            return true
          }
        });
      });
    });
  });

});
