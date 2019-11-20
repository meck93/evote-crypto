import { ECParams, CurvePoint, Cipher, SumProof } from './models'
import { ECelGamal } from '../index'
import { ECmul, ECpow, BNmul, BNadd } from './helper'

import BN = require('bn.js')
import { activeCurve } from './activeCurve'

const log = false

// fix type of point to be CurvePoint => requires all other to be ShortPoint
export function convertECPointToString(point: CurvePoint): string {
  const pointAsJSON = point.toJSON()
  const Px = (pointAsJSON[0] as BN).toString('hex')
  const Py = (pointAsJSON[1] as BN).toString('hex')
  return Px + Py
}

export function convertAllECPointsToString(points: CurvePoint[]): string {
  let asString = ''
  for (const point of points) {
    asString += convertECPointToString(point)
  }
  return asString
}

export function generateChallenge(
  n: BN,
  id: string,
  a: CurvePoint,
  b: CurvePoint,
  a1: CurvePoint,
  b1: CurvePoint
): BN {
  const pointsAsString: string = convertAllECPointsToString([a, b, a1, b1])
  const input = id + pointsAsString

  let c = activeCurve
    .hash()
    .update(input)
    .digest('hex')

  c = new BN(c, 'hex')
  c = c.mod(n)

  return c
}

export const generateSumProof = (
  encryptedVote: Cipher,
  params: ECParams,
  sk: BN,
  id: string
): SumProof => {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b } = encryptedVote
  const { g, n } = params

  // generate random value
  const x: BN = ECelGamal.Helper.getSecureRandomValue(n)

  // (a1, b1) = (a^x, g^x)
  const a1 = ECpow(a, x)
  const b1 = ECpow(g, x)

  // generate the challenge
  const c = generateChallenge(n, id, a, b, a1, b1)

  // compute f = x + c * sk (NOTE: mod q!)
  const cr = BNmul(c, sk, n)
  const f = BNadd(x, cr, n)

  // comute the decryption factor
  const d = ECpow(a, sk)

  log && console.log('a1 is on the curve?\t', activeCurve.curve.validate(a1))
  log && console.log('b1 is on the curve?\t', activeCurve.curve.validate(b1))
  log && console.log('d is on the curve?\t', activeCurve.curve.validate(d))

  log && console.log('x\t\t\t', x)
  log && console.log('a1\t\t\t', a1)
  log && console.log('b1\t\t\t', b1)
  log && console.log('c\t\t\t', c)
  log && console.log('f = x + c*r\t\t', f)
  log && console.log()

  return { a1, b1, f, d }
}

export const verifySumProof = (
  encryptedSum: Cipher,
  proof: SumProof,
  params: ECParams,
  pk: CurvePoint,
  id: string
): boolean => {
  const { a, b } = encryptedSum
  const { h, g, n } = params
  const { a1, b1, f, d } = proof

  // recompute the challenge
  const c = generateChallenge(n, id, a, b, a1, b1)

  // verification a^f == a1 * d^c
  const l1 = ECpow(a, f)
  const r1 = ECmul(a1, ECpow(d, c))
  const v1 = l1.eq(r1)

  // verification g^f == b1 * h^c
  const l2 = ECpow(g, f)
  const r2 = ECmul(b1, ECpow(h, c))
  const v2 = l2.eq(r2)

  log && console.log('a^f == a1*d^c:\t\t', v1)
  log && console.log('g^f == b1*h^c\t\t', v2)
  log && console.log()

  return v1 && v2
}
