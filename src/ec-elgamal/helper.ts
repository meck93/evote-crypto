import crypto = require('crypto')
import { curve } from 'elliptic'
import BN = require('bn.js')

export const getSecureRandomValue = (n: BN, byte_size: number = 32): BN => {
  const one = new BN(1, 10)

  // TODO: Fix upper limit to n-1
  const UPPER_BOUND_RANDOM: BN = n.sub(one)
  const RAND_SIZE_BYTES = byte_size

  let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
  let randomValue = new BN(randomBytes)

  // ensure that the random value is in range [1,n-1]
  while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(one))) {
    randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    randomValue = new BN(randomBytes)
  }
  return randomValue
}

export const newBN = (n: number, base: number = 10) => new BN(n, base)

export const BNadd = (a: BN, b: BN, mod: BN) => a.add(b).mod(mod)
export const BNsub = (a: BN, b: BN, mod: BN) => a.sub(b).mod(mod)
export const BNmul = (a: BN, b: BN, mod: BN) => a.mul(b).mod(mod)

export const ECpow = (a: curve.base.BasePoint, b: BN): curve.base.BasePoint => a.mul(b)
export const ECmul = (a: curve.base.BasePoint, b: curve.base.BasePoint): curve.base.BasePoint => a.add(b)
export const ECdiv = (a: curve.base.BasePoint, b: curve.base.BasePoint): curve.base.BasePoint => a.add(b.neg())

export function curvePointToString(point: any) {
  const pointAsJSON = point.toJSON()
  const Px = pointAsJSON[0].toString('hex')
  const Py = pointAsJSON[1].toString('hex')
  return Px + Py
}

export function curvePointsToString(points: curve.base.BasePoint[]) {
  let asString = ''
  for (const point of points) {
    asString += curvePointToString(point)
  }
  return asString
}
