eckey
=====

JavaScript component for Elliptical curve cryptography for crypto currencies such as Bitcoin, Litecoin, Dogecoin, etc.


Why?
----

This module provides a convenient way to compute relevant crypto currency operations that adhere to elliptical curve cryptography. To
really understand how private keys, public keys, addresses, and how elliptical curve cryptography works with JavaScript, read this: http://procbits.com/2013/08/27/generating-a-bitcoin-address-with-javascript


Installation
------------

    npm install --save eckey


Usage
-----

### API

#### ECKey([bytes], [compressed])

Constructor function.

- **bytes**: The private key bytes. Must be 32 bytes in length. Should be an `Array`, `Uint8Array`, or a `Buffer`.
- **compressed**: Specify whether the key should be compressed or not.

```js
var ECKey = require('eckey');
var secureRandom = require('secure-random'); 

var bytes = secureRandom(32); //https://github.com/jprichardson/secure-random
var key1 = new ECKey(bytes);
var key2 = ECKey(bytes); //<--- can also use without "new"
var compressedKey = new ECKey(bytes, true);
```

Note: Previous versions of this module would generate a random array of bytes for you if you didn't pass as input any to the constructor. This behavior has been removed to remove complexity and to ensure that the random generation is done securely. In the past, it wasn't.


#### privateKey

Get/set the private key. When setting, the type can be either an `Array`, `Buffer`, or `Uint8Array`. When getting, the type is always `Buffer`. Setting would be useful if you don't pass a private key to the constructor.


#### publicKey

Get the public key. The type is `Buffer`.





#### compressed

Get/set whether the point on the curve is compressed. Affects the output of the WIF (wallet import format) and the address.



References
----------
- http://procbits.com/2013/08/27/generating-a-bitcoin-address-with-javascript
- https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/eckey.js
- https://github.com/vbuterin/bitcoinjs-lib/blob/master/src/eckey.js
- 





