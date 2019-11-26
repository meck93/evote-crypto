import BN = require('bn.js')
import { CurvePoint, Cipher, SystemParameters, SystemParametersSerialized } from '../models'
import { ECmul, ECpow, BNmul, BNadd, deserializeParams, deserializeCurvePoint } from '../helper'

import { activeCurve } from '../activeCurve'
import { DecryptionProof } from './models'
import { Helper } from '../index'

export function generateChallenge(
  n: BN,
  id: string,
  a: CurvePoint,
  b: CurvePoint,
  a1: CurvePoint,
  b1: CurvePoint
): BN {
  const pointsAsString: string = Helper.curvePointsToString([a, b, a1, b1])
  const input = id + pointsAsString

  let c = activeCurve
    .hash()
    .update(input)
    .digest('hex')

  c = new BN(c, 'hex')
  c = c.mod(n)

  return c
}

// generate a proof for the decryption
// steps:
// 1. generate random value x
// 2. compute (a1, b1) = (a^x, g^x)
// 3. generate the challenge
// 4. compute f = x + c * sk (NOTE: mod q!)
// 5. compute the decryption factor d = a^r
export const generate = (
  cipher: Cipher,
  params: SystemParameters | SystemParametersSerialized,
  sk: BN,
  id: string,
  log = false
): DecryptionProof => {
  const { a, b } = cipher
  const { g, n } = deserializeParams(params)

  const x: BN = Helper.getSecureRandomValue(n)

  const a1 = ECpow(a, x)
  const b1 = ECpow(g, x)

  const c = generateChallenge(n, id, a, b, a1, b1)
  const f = BNadd(x, BNmul(c, sk, n), n)
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

// verify a proof for the decryption
// 1. recompute the challenge
// 2. verification a^f == a1 * d^c
// 3. verification g^f == b1 * h^c
export const verify = (
  encryptedSum: Cipher,
  proof: DecryptionProof,
  params: SystemParameters | SystemParametersSerialized,
  pk: CurvePoint | string,
  id: string,
  log = false
): boolean => {
  const { a, b } = encryptedSum
  const { g, n } = deserializeParams(params)
  pk = deserializeCurvePoint(pk)
  const { a1, b1, f, d } = proof

  const c = generateChallenge(n, id, a, b, a1, b1)

  const l1 = ECpow(a, f)
  const r1 = ECmul(a1, ECpow(d, c))
  const v1 = l1.eq(r1)

  const l2 = ECpow(g, f)
  const r2 = ECmul(b1, ECpow(pk, c))
  const v2 = l2.eq(r2)

  log && console.log('a^f == a1*d^c:\t\t', v1)
  log && console.log('g^f == b1*h^c\t\t', v2)
  log && console.log()

  return v1 && v2
}
