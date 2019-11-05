import crypto = require('crypto')

const BN = require('bn.js')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')

const RAND_SIZE_BYTES = 32
const UPPER_BOUND_RANDOM = ec.curve.n.sub(new BN(2, 10))

export const getSecureRandomValue = (): any => {
    let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    let randomValue = new BN(randomBytes)
  
    // ensure that the random value is in range [1,n-1]
    while (!randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(1)) {
      randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
      randomValue = new BN(randomBytes, 'hex')
    }
    return randomValue
  }