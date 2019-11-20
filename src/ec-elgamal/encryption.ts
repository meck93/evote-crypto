import { getSecureRandomValue } from './helper'
import { CurvePoint, Cipher } from './models'

import BN = require('bn.js')
import { activeCurve } from './activeCurve'

const shouldLog = false

// Elliptic Curve ElGamal Encryption
//
// given:
// - g: generator
// - h: public key (g^privateKey)
// - m: message
//
// steps:
// 1. pick random value r
// 2. compute c1 = g^r (ec-multiplication)
// 3. compute s = h^r (ec-multiplication)
// 4. compute c2 = s*m
export const encrypt = (message: CurvePoint, pubK: CurvePoint): Cipher => {
  const r = getSecureRandomValue(activeCurve.curve.n)

  const c1 = activeCurve.g.mul(r) as CurvePoint
  const s = pubK.mul(r)
  const c2 = s.add(message) as CurvePoint

  shouldLog && console.log('Is c1 on the curve?\t', activeCurve.curve.validate(c1))
  shouldLog && console.log('Is point s on the curve?', activeCurve.curve.validate(s))
  shouldLog && console.log('Is c2 on curve?\t\t', activeCurve.curve.validate(c2))

  return { a: c1, b: c2, r: r }
}

// Elliptic Curve ElGamal Decryption
//
// given:
// - g: generator
// - x: private key
// - c1,c2: cipher
//
// steps:
// 1. compute s = c1^x (ec-multiplication)
// 2. compute s^-1 = multiplicative inverse of s
// 3. compute m = c2 * s^-1 (ec-addition)
export const decrypt = (cipherText: Cipher, privK: BN): CurvePoint => {
  const { a: c1, b: c2 } = cipherText

  const s = c1.mul(privK)
  const sInverse = s.neg()
  const m = c2.add(sInverse)

  shouldLog && console.log('is s on the curve?', activeCurve.curve.validate(s))
  shouldLog && console.log('is s^-1 on the curve?', activeCurve.curve.validate(sInverse))
  shouldLog && console.log('is m on curve?', activeCurve.curve.validate(m))

  return m as CurvePoint
}

export const homomorphicAdd = (cipher0: Cipher, cipher1: Cipher): Cipher => {
  return {
    a: cipher0.a.add(cipher1.a) as CurvePoint,
    b: cipher0.b.add(cipher1.b) as CurvePoint,
  }
}
