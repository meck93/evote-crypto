import { ECCipher, ECParams } from './models'
import { ECelGamal } from '../index'
import { curve } from 'elliptic'
import { SumProof } from '../models'

import BN = require('bn.js')
import { activeCurve } from './activeCurve'

const log = false

const BNadd = (a: BN, b: BN, params: ECParams) => a.add(b).mod(params.n)
const BNsub = (a: BN, b: BN, params: ECParams) => a.sub(b).mod(params.n)
const BNmul = (a: BN, b: BN, params: ECParams) => a.mul(b).mod(params.n)

const ECpow = (a: curve.base.BasePoint, b: BN): curve.base.BasePoint => a.mul(b)
const ECmul = (a: curve.base.BasePoint, b: curve.base.BasePoint): curve.base.BasePoint => a.add(b)
const ECdiv = (a: curve.base.BasePoint, b: curve.base.BasePoint): curve.base.BasePoint => a.add(b.neg())

export const generateSumProof = (encryptedVote: ECCipher, params: ECParams, sk: BN, id: string): SumProof => {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b } = encryptedVote
  const { p, h, g, n } = params

  // generate random value
  const x: BN = ECelGamal.Helper.getSecureRandomValue()

  // (a1, b1) = (a^x, g^x)
  const a1 = ECpow(a, x)
  const b1 = ECpow(g, x)

  // generate the challenge
  const c = generateChallenge(n, id, a, b, a1, b1)

  // compute f = x + c * sk (NOTE: mod q!)
  const cr = BNmul(c, sk, params)
  const f = BNadd(x, cr, params)

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
  encryptedSum: ECCipher,
  proof: SumProof,
  params: ECParams,
  pk: curve.base.BasePoint,
  id: string
): boolean => {
  const { a, b } = encryptedSum
  const { p, h, g, n } = params
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

// fix type of point to be curve.short.ShortPoint => requires all other to be ShortPoint
export function convertECPointToString(point: any): string {
  const pointAsJSON = point.toJSON()
  const Px = pointAsJSON[0].toString('hex')
  const Py = pointAsJSON[1].toString('hex')
  return Px + Py
}

export function convertAllECPointsToString(points: curve.base.BasePoint[]): string {
  let asString = ''
  for (const point of points) {
    asString += convertECPointToString(point)
  }
  return asString
}

export function generateChallenge(
  n: BN,
  id: string,
  a: curve.base.BasePoint,
  b: curve.base.BasePoint,
  a1: curve.base.BasePoint,
  b1: curve.base.BasePoint
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
