import BN = require('bn.js')

import { GlobalHelper } from '../../index'
import {
  Cipher,
  Curve,
  CurvePoint,
  Helper,
  SystemParameters,
  SystemParametersSerialized,
} from '../index'
import { MembershipProof } from './models'
import { curveDefinition } from '../curve'

const printConsole = false

export const generateChallenge = (
  n: BN,
  id: string,
  c1: CurvePoint,
  c2: CurvePoint,
  a1: CurvePoint,
  a2: CurvePoint,
  b1: CurvePoint,
  b2: CurvePoint
): BN => {
  const pointsAsString = Helper.curvePointsToString([c1, c2, a1, a2, b1, b2])
  const input = id + pointsAsString

  let c = curveDefinition
    .hash()
    .update(input)
    .digest('hex')

  c = new BN(c, 'hex')
  c = c.mod(n)

  return c
}

// generate a proof for an encrypted yes vote
// steps:
// 1. generate fake values c0,f0 for m=0 (random values in Z_q = Z_n)
// 2. compute fake (a0,b0) = (g^f0 / a^c0, h^f0 / b^c0)
// 3. generate proof for m=1
//    3.1 generate a random value x in Z_q = Z_n
//    3.2 compute (a1,b1) =  (g^x, h^x)
// 4. generate the challenge c
// 5. compute c1 = c - c0
// 6. compute f1 = x + c1 * r (NOTE: mod q! = mod n!)
export const generateYesProof = (
  encryptedVote: Cipher,
  params: SystemParameters | SystemParametersSerialized,
  publicKey: CurvePoint | string,
  id: string
): MembershipProof => {
  const { a, b, r } = encryptedVote
  const { g, n } = Helper.deserializeParams(params)
  const h = Helper.deserializeCurvePoint(publicKey)

  if (r === undefined || r === null) {
    throw new Error('value r is undefined')
  }

  const c0: BN = GlobalHelper.getSecureRandomValue(n)
  const f0: BN = GlobalHelper.getSecureRandomValue(n)

  const a0 = Helper.ECdiv(Helper.ECpow(g, f0), Helper.ECpow(a, c0))
  const b0 = Helper.ECdiv(Helper.ECpow(h, f0), Helper.ECpow(b, c0))

  const x: BN = GlobalHelper.getSecureRandomValue(n)
  const a1 = Helper.ECpow(g, x)
  const b1 = Helper.ECpow(h, x)

  const c = generateChallenge(n, id, a, b, a0, b0, a1, b1)
  const c1 = Helper.BNadd(n, Helper.BNsub(c, c0, n), n)

  const f1 = Helper.BNadd(x, Helper.BNmul(c1, r, n), n)

  printConsole && console.log('a0 is on the curve?\t', Curve.validate(a0))
  printConsole && console.log('b0 is on the curve?\t', Curve.validate(b0))
  printConsole && console.log('a1 is on the curve?\t', Curve.validate(a1))
  printConsole && console.log('b1 is on the curve?\t', Curve.validate(b1))

  printConsole && console.log('c0\t\t\t\t', c0.toString('hex'))
  printConsole && console.log('f0\t\t\t\t', f0.toString('hex'))
  printConsole && console.log('x\t\t\t\t', x.toString('hex'))
  printConsole && console.log('c\t\t\t\t', c.toString('hex'))
  printConsole && console.log('c1 = (q + (c - c0) % q) % q\t', c1.toString('hex'))
  printConsole && console.log('f1 = x + c1*r\t\t\t', f1.toString('hex'))
  printConsole && console.log()

  return { a0, a1, b0, b1, c0, c1, f0, f1 }
}

// generate a proof for an encrypted no vote
// steps:
// 1. generate fake values c1,f1 for m=1 (random values in Z_q = Z_n)
// 2. compute fake b_ = b/g
// 3. compute fake (a1,b1) = (g^f1 / a^c1, h^f1 / (b/g)^c1)
// 4. generate proof for m=0
//    4.1 generate a random value x in Z_q = Z_n
//    4.2 compute (a0,b0) =  (g^x, h^x)
// 5. generate the challenge c
// 6. compute c0 = c - c1
// 7. compute f0 = x + c0 * r (NOTE: mod q!)
export const generateNoProof = (
  encryptedVote: Cipher,
  params: SystemParameters | SystemParametersSerialized,
  publicKey: CurvePoint | string,
  id: string
): MembershipProof => {
  const { a, b, r } = encryptedVote
  const { g, n } = Helper.deserializeParams(params)
  const h = Helper.deserializeCurvePoint(publicKey)

  if (r === undefined || r === null) {
    throw new Error('value r is undefined')
  }

  const c1: BN = GlobalHelper.getSecureRandomValue(n)
  const f1: BN = GlobalHelper.getSecureRandomValue(n)

  const b_ = Helper.ECdiv(b, g)
  const a1 = Helper.ECdiv(Helper.ECpow(g, f1), Helper.ECpow(a, c1))
  const b1 = Helper.ECdiv(Helper.ECpow(h, f1), Helper.ECpow(b_, c1))

  const x: BN = GlobalHelper.getSecureRandomValue(n)
  const a0 = Helper.ECpow(g, x)
  const b0 = Helper.ECpow(h, x)

  const c = generateChallenge(n, id, a, b, a0, b0, a1, b1)
  const c0 = Helper.BNadd(n, Helper.BNsub(c, c1, n), n)

  const f0 = Helper.BNadd(x, Helper.BNmul(c0, r, n), n)

  printConsole && console.log('a1 is on the curve?\t', Curve.validate(a1))
  printConsole && console.log('b1 is on the curve?\t', Curve.validate(b1))
  printConsole && console.log('a0 is on the curve?\t', Curve.validate(a0))
  printConsole && console.log('b0 is on the curve?\t', Curve.validate(b0))

  printConsole && console.log('c1\t\t\t\t', c1.toString('hex'))
  printConsole && console.log('f1\t\t\t\t', f1.toString('hex'))
  printConsole && console.log('x\t\t\t\t', x.toString('hex'))
  printConsole && console.log('c\t\t\t\t', c.toString('hex'))
  printConsole && console.log('c0 = (q + (c - c1) % q) % q\t', c0.toString('hex'))
  printConsole && console.log('f0 = x + c0*r\t\t\t', f0.toString('hex'))
  printConsole && console.log()

  return { a0, a1, b0, b1, c0, c1, f0, f1 }
}

// verification g^f0 == a0*a^c0
// verification g^f1 == a1*a^c1
// verification h^f0 == b0 * b^c0
// verification h^f1 == b1 * (b/g)^c1
// recompute the hash and verify
export const verify = (
  encryptedVote: Cipher,
  proof: MembershipProof,
  params: SystemParameters | SystemParametersSerialized,
  publicKey: CurvePoint | string,
  id: string
): boolean => {
  const { a0, a1, b0, b1, c0, c1, f0, f1 } = proof
  const { g, n } = Helper.deserializeParams(params)
  const h = Helper.deserializeCurvePoint(publicKey)
  const { a, b } = encryptedVote

  const v1 = Helper.ECpow(g, f0).eq(Helper.ECmul(a0, Helper.ECpow(a, c0)))
  const v2 = Helper.ECpow(g, f1).eq(Helper.ECmul(a1, Helper.ECpow(a, c1)))
  const v3 = Helper.ECpow(h, f0).eq(Helper.ECmul(b0, Helper.ECpow(b, c0)))
  const v4 = Helper.ECpow(h, f1).eq(Helper.ECmul(b1, Helper.ECpow(Helper.ECdiv(b, g), c1)))
  const v5 = Helper.BNadd(c0, c1, n).eq(generateChallenge(n, id, a, b, a0, b0, a1, b1))

  printConsole && console.log('g^f0 == a0*a^c0:\t', v1)
  printConsole && console.log('g^f1 == a1*a^c1\t\t', v2)
  printConsole && console.log('h^f0 == b0*b^c0\t\t', v3)
  printConsole && console.log('h^f1 == b1*(b/g)^c1\t', v4)
  printConsole && console.log('c == c1 + c0\t\t', v5)
  printConsole && console.log()

  return v1 && v2 && v3 && v4 && v5
}
