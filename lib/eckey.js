!function(globals) {
'use strict'

//*** IMPORTS
var BigInteger = null
var ECPointFp = null
var ecparams = null
var secureRandom = null
//*** IMPORTS END

//*** EXPORTS
var ECDSA = {}

//*** UMD BEGIN
if (typeof define !== 'undefined' && define.amd) { //require.js / AMD
  define(['cryptocoin-bigint', 'cryptocoin-ecc', 'cryptocoin-ecc-named', 'secure-random'], function(bigint, ecc, getSECCurveByName, _secureRandom) {
    BigInteger = bigint
    ECPointFp = ecc.ECPointFp
    secureRandom = _secureRandom
    ecparams = getSECCurveByName('secp256k1')
    return ECDSA
  })
} else if (typeof module !== 'undefined' && module.exports) { //CommonJS
  secureRandom = require('secure-random') //same name for both
  try { //Node.js
    BigInteger = require('cryptocoin-bigint')
    ECPointFp = require('cryptocoin-ecc').ECPointFp
    ecparams = require('cryptocoin-ecc-named')('secp256k1')
  } catch (e) { //Component
    BigInteger = require('bigint')
    ECPointFp = require('ecc').ECPointFp
    ecparams = require('ecc-named')('secp256k1')
  }
  module.exports = ECDSA
} else {
  BigInteger = globals.BigInteger
  secureRandom = globals.secureRandom
  ECPointFp = globals.ECCurveFp.ECPointFp
  ecparams = globals.getSECCurveByName('secp256k1')
  globals.ECDSA = ECDSA
}
//*** UMD END






}(this);
