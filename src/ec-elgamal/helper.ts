import crypto = require('crypto')

import BN = require('bn.js')
const EC = require('elliptic').ec
const secp256k1 = new EC('secp256k1')

const RAND_SIZE_BYTES = 32
const UPPER_BOUND_RANDOM = secp256k1.curve.n.sub(new BN(1, 10))

export const getSecureRandomValue = (): BN => {
  let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
  let randomValue = new BN(randomBytes, 'hex')

  // ensure that the random value is in range [1,n-1]
  while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(new BN(1)))) {
    randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    randomValue = new BN(randomBytes, 'hex')
  }
  return randomValue
}
