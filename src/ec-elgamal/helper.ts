import crypto = require('crypto')
import { curve } from 'elliptic'
import BN = require('bn.js')
import { activeCurve } from './activeCurve'

export const getSecureRandomValue = (RAND_SIZE_BYTES: number = 32): BN => {
  const one = new BN(1, 10)
  const UPPER_BOUND_RANDOM: BN = activeCurve.curve.n.sub(one)

  let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
  let randomValue = new BN(randomBytes, 'hex')

  // ensure that the random value is in range [1,n-1]
  while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(one))) {
    randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    randomValue = new BN(randomBytes, 'hex')
  }
  return randomValue
}

export const newBN = (n: number, base: number = 10) => new BN(n, base)

export const BNadd = (a: BN, b: BN, modulus: BN) => a.add(b).mod(modulus)
export const BNsub = (a: BN, b: BN, modulus: BN) => a.sub(b).mod(modulus)
export const BNmul = (a: BN, b: BN, modulus: BN) => a.mul(b).mod(modulus)

export const ECpow = (a: curve.base.BasePoint, b: BN): curve.base.BasePoint => a.mul(b)
export const ECmul = (a: curve.base.BasePoint, b: curve.base.BasePoint): curve.base.BasePoint => a.add(b)
export const ECdiv = (a: curve.base.BasePoint, b: curve.base.BasePoint): curve.base.BasePoint => a.add(b.neg())
