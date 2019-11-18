import crypto = require('crypto')

import BN = require('bn.js')
import { activeCurve } from './activeCurve'

export const getSecureRandomValue = (RAND_SIZE_BYTES: number = 32): BN => {
  const one = new BN(1, 10)

  const UPPER_BOUND_RANDOM: BN = activeCurve.curve.n.sub(new BN(1, 10))

  let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
  let randomValue = new BN(randomBytes, 'hex')

  // ensure that the random value is in range [1,n-1]
  while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(one))) {
    randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    randomValue = new BN(randomBytes, 'hex')
  }
  return randomValue
}
