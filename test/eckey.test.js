var ECKey = require('../lib/eckey')
  , conv = require('convert-hex')

console.dir(ECKey)

require('terst')

describe('ECKey', function() {
  describe('- getPub()', function() {
    describe('> when not compressed', function() {
      it('should generate the public key uncompressed', function() {
        var privateKeyBytes = conv.hexToBytes("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD")
        var eckey = new ECKey(privateKeyBytes)
        var publicKeyHex = conv.bytesToHex(eckey.getPub())
        EQ (publicKeyHex, "04d0988bfa799f7d7ef9ab3de97ef481cd0f75d2367ad456607647edde665d6f6fbdd594388756a7beaf73b4822bc22d36e9bda7db82df2b8b623673eefc0b7495") 
      })
    })

    describe('> when compressed', function() {
      it('should generate the public key uncompressed', function() {
        var privateKeyBytes = conv.hexToBytes("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD")
        var eckey = new ECKey(privateKeyBytes)
        eckey.compressed = true
        var publicKeyHex = conv.bytesToHex(eckey.getPub())
        EQ (publicKeyHex, "03d0988bfa799f7d7ef9ab3de97ef481cd0f75d2367ad456607647edde665d6f6f") //this feels wrong, extra '6f' on the end? investigate
      
      })
    })
  })

  describe('- getBitcoinAddress()', function() {
    describe('> when not compressed', function() {
      it('should generate the address of the uncompressed public key', function() {
        var privateKeyBytes = conv.hexToBytes("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD")
        var eckey = new ECKey(privateKeyBytes)
        var address = eckey.getBitcoinAddress().toString()
        EQ (address, "16UjcYNBG9GTK4uq2f7yYEbuifqCzoLMGS")
      })
    })

    describe('> when compressed', function() {
      it('should generate the address of the compressed public key', function() {
         var privateKeyBytes = conv.hexToBytes("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD")
        var eckey = new ECKey(privateKeyBytes)
        eckey.compressed = true
        var address = eckey.getBitcoinAddress().toString()
        EQ (address, "1FkKMsKNJqWSDvTvETqcCeHcUQQ64kSC6s")
      })
    })
  })


  describe('> toString()', function() {
    it('should show the string representation in...', function() {
      var privateKeyBytes = conv.hexToBytes("1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD")
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
});
